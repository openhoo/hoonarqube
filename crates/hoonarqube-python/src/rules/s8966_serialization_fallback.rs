use ruff_python_ast::{Expr, ExprCall, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{ClassIndex, ImportFqns, NameResolver, NameValue, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8966";
const MESSAGE: &str = "Add a \"fallback\" parameter to this pydantic-core serialization call.";

/// python:S8966 — `pydantic_core.to_json` and
/// `pydantic_core.to_jsonable_python` raise `PydanticSerializationError`
/// on types they cannot convert; a `fallback` handler keeps serialization
/// from crashing on unexpected data. A call without a `fallback` keyword
/// anchors on the callee — unless its first positional argument might be
/// a `pydantic.BaseModel` instance, which pydantic-core serializes
/// natively. Mirroring the reference's `isObjectInstanceOf` exemption, the
/// first argument only vetoes when it could be a model: literal and
/// comprehension values, calls to in-file non-model classes, and names
/// bound once to such values are provably not models and still flag, while
/// names of unknown provenance, attribute reads, subscripts, and calls to
/// unknown callables stay silent. A keyword first argument and `*args`
/// unpackings cannot be the model instance and flag like any other call.
pub(crate) fn check_s8966_serialization_fallback(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let fqns = ImportFqns::build(file_ctx);
    let classes = ClassIndex::build(file_ctx);
    let resolver = NameResolver::build(parsed, source);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        check_call(call, &fqns, &classes, &resolver, index, source, &mut issues);
    }
    issues
}

fn check_call(
    call: &ExprCall,
    fqns: &ImportFqns,
    classes: &ClassIndex,
    resolver: &NameResolver,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !fqns.is_fqn_in(
        &call.func,
        &["pydantic_core.to_json", "pydantic_core.to_jsonable_python"],
    ) {
        return;
    }
    if call.arguments.args.is_empty() && call.arguments.keywords.is_empty() {
        return;
    }
    // The first argument in source order: positional args precede keywords
    // unless a keyword or `**kwargs` comes first. A keyword first argument
    // is never the model instance, so the exemption does not apply.
    let first_positional = call.arguments.args.first();
    let first_keyword = call.arguments.keywords.first();
    if let Some(keyword) = first_keyword
        && first_positional.is_none_or(|arg| keyword.range().start() < arg.range().start())
    {
        report_if_no_fallback(call, index, source, issues);
        return;
    }
    let Some(first) = first_positional else {
        return;
    };
    if matches!(first, Expr::Starred(_)) {
        report_if_no_fallback(call, index, source, issues);
        return;
    }
    if might_be_model_instance(first, fqns, classes, resolver) {
        return;
    }
    report_if_no_fallback(call, index, source, issues);
}

fn report_if_no_fallback(
    call: &ExprCall,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if call.arguments.keywords.iter().any(|keyword| {
        keyword
            .arg
            .as_ref()
            .is_some_and(|arg| arg.as_str() == "fallback")
    }) {
        return;
    }
    issues.push(issue_at(
        RULE_KEY,
        MESSAGE,
        call.func.range(),
        index,
        source,
    ));
}

/// Whether the first positional argument could be a `BaseModel` instance —
/// the reference's `evaluateFor(...).isFalse()` veto inverted: only values
/// provably not model instances proceed to the finding. Anything of
/// unknown provenance may be a model and vetoes.
fn might_be_model_instance(
    expr: &Expr,
    fqns: &ImportFqns,
    classes: &ClassIndex,
    resolver: &NameResolver,
) -> bool {
    match expr {
        Expr::Name(_) => match resolver.resolve(expr) {
            NameValue::Single(value) => !provably_not_model(value, fqns, classes, resolver, 0),
            // Unbound names are builtins or externals; bound-but-ambiguous
            // names (parameters, multi-writes) may hold a model.
            NameValue::Unbound | NameValue::Ambiguous => true,
        },
        other => !provably_not_model(other, fqns, classes, resolver, 0),
    }
}

/// Whether `expr` is provably not a `BaseModel` instance: literal and
/// comprehension values, calls to in-file non-model classes, and names
/// bound once to such values.
fn provably_not_model(
    expr: &Expr,
    fqns: &ImportFqns,
    classes: &ClassIndex,
    resolver: &NameResolver,
    depth: u8,
) -> bool {
    // Name chains can cycle (`a = a`); past a few hops the provenance is
    // unknowable and the value may be a model.
    if depth > 8 {
        return false;
    }
    match expr {
        Expr::BooleanLiteral(_)
        | Expr::NoneLiteral(_)
        | Expr::NumberLiteral(_)
        | Expr::StringLiteral(_)
        | Expr::BytesLiteral(_)
        | Expr::FString(_)
        | Expr::EllipsisLiteral(_)
        | Expr::List(_)
        | Expr::Tuple(_)
        | Expr::Dict(_)
        | Expr::Set(_)
        | Expr::ListComp(_)
        | Expr::SetComp(_)
        | Expr::DictComp(_)
        | Expr::Generator(_) => true,
        Expr::Name(_) => match resolver.resolve(expr) {
            NameValue::Single(value) => {
                provably_not_model(value, fqns, classes, resolver, depth + 1)
            }
            NameValue::Unbound | NameValue::Ambiguous => false,
        },
        Expr::Call(call) => call_result_not_model(call, fqns, classes, resolver),
        _ => false,
    }
}

/// Whether a call's result is provably not a `BaseModel` instance: the
/// callee resolves to an in-file class that is not a Pydantic model, or to
/// a name bound once to such a class. Unknown callables may return (or
/// construct) a model.
fn call_result_not_model(
    call: &ExprCall,
    fqns: &ImportFqns,
    classes: &ClassIndex,
    resolver: &NameResolver,
) -> bool {
    let callee = call.func.as_ref();
    let class = match callee {
        Expr::Name(name) => {
            classes
                .local_class(name.id.as_str())
                .or_else(|| match resolver.resolve(callee) {
                    NameValue::Single(Expr::Name(bound)) => classes.local_class(bound.id.as_str()),
                    _ => None,
                })
        }
        _ => None,
    };
    match class {
        Some(class) => !classes.is_pydantic_model(class, fqns),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8966")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8966_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: `to_json(data)` where `data` is
        // bound once to a dict literal — provably not a model — anchors on
        // the callee (line 8, columns 9-16).
        let ranges = found(concat!(
            "from pydantic_core import to_json\n",
            "\n",
            "class CustomObject:\n",
            "    def __init__(self, value):\n",
            "        self.value = value\n",
            "\n",
            "data = {\"key\": CustomObject(42)}\n",
            "result = to_json(data)\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(8, 9));
        assert_eq!(ranges[0].end, pos(8, 16));
    }

    #[test]
    fn s8966_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from pydantic_core import to_json\n",
                "\n",
                "class CustomObject:\n",
                "    def __init__(self, value):\n",
                "        self.value = value\n",
                "\n",
                "def handle_unknown(obj):\n",
                "    return str(obj)\n",
                "\n",
                "data = {\"key\": CustomObject(42)}\n",
                "result = to_json(data, fallback=handle_unknown)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8966_flags_literal_first_arguments_and_both_functions() {
        // Literal first arguments are provably not models; both
        // `to_json` and `to_jsonable_python` flag, qualified or not.
        let ranges = found(concat!(
            "import pydantic_core\n",
            "from pydantic_core import to_jsonable_python\n",
            "\n",
            "a = pydantic_core.to_json({\"k\": 1})\n",
            "b = to_jsonable_python([1, 2])\n",
            "c = pydantic_core.to_jsonable_python(\"text\")\n",
        ));
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].start, pos(4, 4));
        assert_eq!(ranges[0].end, pos(4, 25));
        assert_eq!(ranges[1].start, pos(5, 4));
        assert_eq!(ranges[1].end, pos(5, 22));
    }

    #[test]
    fn s8966_accepts_possible_model_instances() {
        // Names of unknown provenance, model-constructing calls, and
        // attribute reads may be `BaseModel` instances and stay silent.
        assert!(
            found(concat!(
                "from pydantic import BaseModel\n",
                "from pydantic_core import to_json\n",
                "\n",
                "class Model(BaseModel):\n",
                "    x: int\n",
                "\n",
                "def dump(value, other):\n",
                "    a = to_json(value)\n",
                "    b = to_json(Model(x=1))\n",
                "    c = to_json(other.data)\n",
                "    d = to_json()\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8966_flags_provably_non_model_calls_and_keyword_first_args() {
        // A call to an in-file non-model class is provably not a model
        // instance; a keyword first argument skips the exemption entirely.
        let ranges = found(concat!(
            "from pydantic_core import to_json\n",
            "\n",
            "class CustomObject:\n",
            "    pass\n",
            "\n",
            "a = to_json(CustomObject())\n",
            "b = to_json(value=CustomObject())\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(6, 4));
        assert_eq!(ranges[0].end, pos(6, 11));
        assert_eq!(ranges[1].start, pos(7, 4));
        assert_eq!(ranges[1].end, pos(7, 11));
    }
}
