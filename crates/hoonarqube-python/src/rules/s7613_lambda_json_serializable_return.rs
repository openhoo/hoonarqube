use crate::engine::file_context::FileContext;
use crate::support::enclosing_function;
use crate::support::flow_location;
use crate::support::has_lambda_handler_signature;
use crate::support::issue_at;
use crate::support::{NameResolution, WebFrameworkFacts};
use hoonarqube_ir::{Issue, IssueFlow};
use ruff_python_ast::{Expr, ExprCall, Stmt, StmtClassDef};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

// --- python:S7613 — Lambda handlers return JSON-serializable values -----------

const RULE_KEY: &str = "python:S7613";
const MESSAGE: &str = "Fix the return value to be JSON serializable.";
const SECONDARY_MESSAGE: &str = "The non-serializable value is set here.";

/// Sonar's `NON_SERIALIZABLE_FQNS`: datetime factory calls whose results are
/// not JSON serializable.
const NON_SERIALIZABLE_FQNS: &[&str] = &[
    "datetime.datetime.now",
    "datetime.datetime.utcnow",
    "datetime.datetime.today",
    "datetime.datetime.fromtimestamp",
    "datetime.datetime.utcfromtimestamp",
    "datetime.date",
    "datetime.date.today",
    "datetime.date.fromtimestamp",
    "datetime.time",
];

/// Callee tails that mark a call result as serialized (`user.to_dict()`,
/// `obj.dict()`, `dataclasses.asdict`, …).
const SERIALIZATION_METHOD_NAMES: &[&str] = &["to_dict", "dict", "asdict", "serialize", "json"];

/// Unbound builtins whose call results are not JSON serializable
/// (`set`, `complex`, `bytes`, `bytearray`, `frozenset`, `open`).
const NON_SERIALIZABLE_BUILTINS: &[&str] =
    &["set", "complex", "bytes", "bytearray", "frozenset", "open"];

/// Constructor FQNs whose results are not JSON serializable: `re.Pattern`,
/// `decimal.Decimal`, and the `io`/`typing.IO` hierarchy (including `open`).
const NON_SERIALIZABLE_CALL_FQNS: &[&str] = &[
    "re.compile",
    "re.Pattern",
    "decimal.Decimal",
    "io.open",
    "io.StringIO",
    "io.BytesIO",
    "io.TextIOWrapper",
    "io.FileIO",
    "io.BufferedReader",
    "io.BufferedWriter",
    "io.BufferedRandom",
    "tempfile.TemporaryFile",
    "tempfile.NamedTemporaryFile",
    "tempfile.SpooledTemporaryFile",
];

/// One flagged location: the primary range plus an optional secondary range
/// (the single-assigned value behind a returned name).
struct Flagged {
    main: TextRange,
    secondary: Option<TextRange>,
}

/// python:S7613 — synchronous Lambda invocations serialize the handler's
/// return value to JSON, so returning `datetime` objects, sets, `bytes`,
/// `complex`, `Decimal`, compiled patterns, IO objects, or instances of
/// user classes without `__dict__`/`__json__` raises `TypeError`. Sonar's
/// `isOnlyLambdaHandler` gates on the signature only.
pub(crate) fn check_s7613_lambda_json_serializable_return(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::Return(return_stmt) = *stmt else {
            continue;
        };
        let Some(value) = return_stmt.value.as_deref() else {
            continue;
        };
        let Some(function) = enclosing_function(&facts, file_ctx, stmt.range()) else {
            continue;
        };
        if !has_lambda_handler_signature(function) {
            continue;
        }
        for flagged in collect_non_serializable(&facts, file_ctx, value, 0) {
            let mut issue = issue_at(RULE_KEY, MESSAGE, flagged.main, index, source);
            if let Some(secondary) = flagged.secondary {
                issue.flows.push(IssueFlow {
                    locations: vec![flow_location(SECONDARY_MESSAGE, secondary, index, source)],
                });
            }
            issues.push(issue);
        }
    }
    issues
}

fn collect_non_serializable<'a>(
    facts: &WebFrameworkFacts<'a>,
    file_ctx: &FileContext<'a>,
    expr: &'a Expr,
    depth: u32,
) -> Vec<Flagged> {
    if depth > 16 {
        return Vec::new();
    }
    match expr {
        Expr::Call(call) => collect_non_serializable_call(facts, file_ctx, call, depth),
        Expr::Dict(dict) => dict
            .items
            .iter()
            .flat_map(|item| {
                let mut flagged = item
                    .key
                    .as_ref()
                    .map(|key| collect_non_serializable(facts, file_ctx, key, depth + 1))
                    .unwrap_or_default();
                flagged.extend(collect_non_serializable(
                    facts,
                    file_ctx,
                    &item.value,
                    depth + 1,
                ));
                flagged
            })
            .collect(),
        Expr::List(list) => list
            .elts
            .iter()
            .flat_map(|elt| collect_non_serializable(facts, file_ctx, elt, depth + 1))
            .collect(),
        Expr::Tuple(tuple) => tuple
            .elts
            .iter()
            .flat_map(|elt| collect_non_serializable(facts, file_ctx, elt, depth + 1))
            .collect(),
        Expr::Name(name) => {
            if let Some((value, _)) = facts.strict_single_assignment(name.id.as_str(), name.range())
            {
                return collect_non_serializable(facts, file_ctx, value, depth + 1)
                    .into_iter()
                    .map(|flagged| Flagged {
                        main: name.range(),
                        secondary: Some(flagged.main),
                    })
                    .collect();
            }
            // A bare name bound to a same-file function is not serializable.
            if facts.resolve_function_def(expr, expr.range()).is_some() {
                return vec![Flagged {
                    main: expr.range(),
                    secondary: None,
                }];
            }
            Vec::new()
        }
        _ => non_serializable_leaf(facts, expr),
    }
}

/// Whether `expr` is provably a `set` (literal, comprehension, `set(...)`
/// call, or a name singly assigned one) — `list(...)` arguments skip these.
fn is_set_expr(facts: &WebFrameworkFacts<'_>, expr: &Expr, depth: u32) -> bool {
    if depth > 8 {
        return false;
    }
    match expr {
        Expr::Set(_) | Expr::SetComp(_) => true,
        Expr::Call(call) => is_unbound_builtin(facts, &call.func, "set"),
        Expr::Name(name) => facts
            .strict_single_assignment(name.id.as_str(), name.range())
            .is_some_and(|(value, _)| is_set_expr(facts, value, depth + 1)),
        _ => false,
    }
}

/// Whether `expr` is a bare `name` with no binding in scope (a builtin).
fn is_unbound_builtin(facts: &WebFrameworkFacts<'_>, expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Name(ident) if ident.id.as_str() == name)
        && matches!(
            facts.resolve_name(name, expr.range()),
            NameResolution::Unbound
        )
}

fn collect_non_serializable_call<'a>(
    facts: &WebFrameworkFacts<'a>,
    file_ctx: &FileContext<'a>,
    call: &'a ExprCall,
    depth: u32,
) -> Vec<Flagged> {
    let callee = call.func.as_ref();
    // `x.to_dict()`/`x.dict()`/`x.asdict()`/`x.serialize()`/`x.json()` and
    // `dataclasses.asdict(...)`/`json.dumps(...)`/`json.loads(...)` results
    // are serializable.
    if let Expr::Attribute(attribute) = callee
        && SERIALIZATION_METHOD_NAMES.contains(&attribute.attr.as_str())
    {
        return Vec::new();
    }
    if let Some(fqn) = facts.expr_fqn(callee)
        && matches!(
            fqn.as_str(),
            "dataclasses.asdict" | "json.dumps" | "json.loads"
        )
    {
        return Vec::new();
    }
    // `list(...)` converts non-serializable iterables; only non-set arguments
    // are rechecked (a `set` argument is converted, not returned as-is).
    if is_unbound_builtin(facts, callee, "list") {
        return call
            .arguments
            .args
            .iter()
            .chain(call.arguments.keywords.iter().map(|keyword| &keyword.value))
            .filter(|arg| !is_set_expr(facts, arg, 0))
            .flat_map(|arg| collect_non_serializable(facts, file_ctx, arg, depth + 1))
            .collect();
    }
    if NON_SERIALIZABLE_BUILTINS
        .iter()
        .any(|name| is_unbound_builtin(facts, callee, name))
    {
        return vec![Flagged {
            main: call.range(),
            secondary: None,
        }];
    }
    if let Some(fqn) = facts.expr_fqn(callee) {
        if NON_SERIALIZABLE_FQNS.contains(&fqn.as_str())
            || NON_SERIALIZABLE_CALL_FQNS.contains(&fqn.as_str())
        {
            return vec![Flagged {
                main: call.range(),
                secondary: None,
            }];
        }
        // Resolvable library calls other than the ones above are assumed
        // serializable; only same-file class constructors are inspected.
        return Vec::new();
    }
    // A call to a same-file class without `__dict__`/`__json__` members
    // returns a non-serializable instance.
    if let Some(class) = facts.resolve_class_def(callee, call.range())
        && !class_has_serialization_member(class)
    {
        return vec![Flagged {
            main: call.range(),
            secondary: None,
        }];
    }
    Vec::new()
}

/// Whether `class` declares `__dict__` or `__json__` (Sonar's
/// `canHaveMember` over the class symbol).
fn class_has_serialization_member(class: &StmtClassDef) -> bool {
    class.body.iter().any(|stmt| match stmt {
        Stmt::FunctionDef(method) => {
            matches!(method.name.as_str(), "__dict__" | "__json__")
        }
        Stmt::Assign(assign) => assign.targets.iter().any(|target| {
            matches!(target, Expr::Name(name) if matches!(name.id.as_str(), "__dict__" | "__json__"))
        }),
        Stmt::AnnAssign(assign) => {
            matches!(assign.target.as_ref(), Expr::Name(name) if matches!(name.id.as_str(), "__dict__" | "__json__"))
        }
        _ => false,
    })
}

/// Non-call leaf expressions whose values are not JSON serializable: set
/// literals/comprehensions, bytes literals, and complex numbers. Attribute
/// chains whose FQN is a non-serializable datetime factory are also flagged.
fn non_serializable_leaf(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> Vec<Flagged> {
    let flagged = match expr {
        Expr::Set(_) | Expr::SetComp(_) | Expr::BytesLiteral(_) => true,
        Expr::NumberLiteral(number) => {
            matches!(number.value, ruff_python_ast::Number::Complex { .. })
        }
        Expr::Attribute(_) => facts
            .expr_fqn(expr)
            .is_some_and(|fqn| NON_SERIALIZABLE_FQNS.contains(&fqn.as_str())),
        _ => false,
    };
    if flagged {
        vec![Flagged {
            main: expr.range(),
            secondary: None,
        }]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7613";

    #[test]
    fn s7613_flags_datetime_in_returned_dict() {
        let flagged = scan(concat!(
            "import datetime\n",
            "def lambda_handler(event, context):\n",
            "    return {\n",
            "        \"message\": \"Request processed successfully\",\n",
            "        \"timestamp\": datetime.datetime.now()\n",
            "    }\n",
        ));
        let issues = findings(&flagged, KEY);
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Fix the return value to be JSON serializable."
        );
    }

    #[test]
    fn s7613_spares_isoformat_and_plain_values() {
        let compliant = scan(concat!(
            "import datetime\n",
            "import json\n",
            "def lambda_handler(event, context):\n",
            "    return {\n",
            "        \"timestamp\": datetime.datetime.now().isoformat(),\n",
            "        \"data\": list({1, 2}),\n",
            "        \"json\": json.dumps({\"test\": 1}),\n",
            "        \"number\": 42,\n",
            "        \"null\": None,\n",
            "        \"unknown\": unknown(\"test\")\n",
            "    }\n",
        ));
        assert!(findings(&compliant, KEY).is_empty());
    }

    #[test]
    fn s7613_flags_sets_bytes_complex_decimal_and_io() {
        let flagged = scan(concat!(
            "from decimal import Decimal\n",
            "from io import StringIO\n",
            "def lambda_handler(event, context):\n",
            "    return {\n",
            "        \"set\": {1, 2},\n",
            "        \"set_call\": set([1]),\n",
            "        \"complex\": 3j,\n",
            "        \"complex_call\": complex(3, 5),\n",
            "        \"decimal\": Decimal(1),\n",
            "        \"file_like\": StringIO(\"test\"),\n",
            "        \"bytes\": bytes(\"t\", \"utf-8\"),\n",
            "        \"file\": open(\"test\")\n",
            "    }\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 8);
    }

    #[test]
    fn s7613_flags_names_with_secondary_location() {
        let flagged = scan(concat!(
            "def lambda_handler(event, context):\n",
            "    data_set = {1, 2, 3}\n",
            "    return {\"data\": data_set}\n",
        ));
        let issues = findings(&flagged, KEY);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].flows.len(), 1);
        assert_eq!(
            issues[0].flows[0].locations[0].message,
            "The non-serializable value is set here."
        );
    }

    #[test]
    fn s7613_flags_custom_class_instances_without_serialization() {
        let flagged = scan(concat!(
            "class CustomObject:\n",
            "    def __init__(self, value):\n",
            "        self.value = value\n",
            "class Serializable:\n",
            "    def __json__(self):\n",
            "        ...\n",
            "def lambda_handler(event, context):\n",
            "    obj = CustomObject(\"test\")\n",
            "    return {\"obj\": obj, \"ok\": Serializable(3)}\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 1);
    }

    #[test]
    fn s7613_spares_non_handlers_and_serialization_methods() {
        let quiet = scan(concat!(
            "import datetime\n",
            "def regular_function():\n",
            "    return {1, 2, 3}\n",
            "def lambda_handler(event, context):\n",
            "    alice = make_user()\n",
            "    return {\"user\": alice.to_dict(), \"dict\": alice.__dict__}\n",
        ));
        assert!(findings(&quiet, KEY).is_empty());
    }

    #[test]
    fn s7613_flags_bare_function_names() {
        let flagged = scan(concat!(
            "def foo():\n",
            "    ...\n",
            "def lambda_handler(event, context):\n",
            "    return {\"fun\": foo}\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 1);
    }
}
