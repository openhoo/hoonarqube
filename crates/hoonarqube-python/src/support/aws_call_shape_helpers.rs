// --- AWS call-shape helpers

use crate::engine::file_context::FileContext;
use crate::support::{WebFrameworkFacts, for_each_stmt_expr, string_literal_text};
use ruff_python_ast::{Expr, ExprCall, Stmt, StmtFunctionDef};
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashSet;

/// Source slice of a whole call expression (name-table text searches).
pub(crate) fn call_source_text<'a>(call: &ruff_python_ast::ExprCall, source: &'a str) -> &'a str {
    let range = call.range();
    source
        .get(range.start().to_usize()..range.end().to_usize())
        .unwrap_or_default()
}

pub(crate) fn for_each_dict_literal(
    stmts: &[Stmt],
    visit: &mut dyn FnMut(&ruff_python_ast::ExprDict),
) {
    for_each_stmt_expr(stmts, &mut |expr| {
        if let Expr::Dict(dict) = expr {
            visit(dict);
        }
    });
}

pub(crate) fn dict_string_entry<'a>(
    dict: &'a ruff_python_ast::ExprDict,
    key: &str,
) -> Option<&'a Expr> {
    dict.items.iter().find_map(|item| {
        item.key
            .as_ref()
            .and_then(string_literal_text)
            .filter(|text| text == key)
            .map(|_| &item.value)
    })
}

fn is_wildcard_string(expr: &Expr) -> bool {
    string_literal_text(expr).as_deref() == Some("*")
}

// --- AWS Lambda handler detection (python:S7618–S7621 family) --------------

/// FQNs that produce a `botocore.client.BaseClient` instance. Sonar matches
/// `botocore.client.BaseClient.<method>` types; without type inference we
/// reconstruct the same provenance from `boto3.client`/`Session.client` calls
/// and `boto3.resource(...).meta.client` attribute chains.
pub(crate) const BOTO3_CLIENT_ORIGINS: &[&str] = &[
    "boto3.client",
    "boto3.Session.client",
    "boto3.session.Session.client",
    "boto3.resource.meta.client",
    "boto3.Session.resource.meta.client",
    "boto3.session.Session.resource.meta.client",
];

/// Whether `expr` resolves to a boto3 client object (a `boto3.client(...)`
/// call result, `Session.client(...)`, or `resource(...).meta.client`).
pub(crate) fn is_boto3_client_receiver(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> bool {
    facts
        .expr_fqn(expr)
        .is_some_and(|fqn| BOTO3_CLIENT_ORIGINS.contains(&fqn.as_str()))
}

/// Whether `call` invokes `method` on a boto3 client receiver.
pub(crate) fn is_boto3_client_method_call(
    facts: &WebFrameworkFacts<'_>,
    call: &ruff_python_ast::ExprCall,
    method: &str,
) -> bool {
    match call.func.as_ref() {
        Expr::Attribute(attribute) => {
            attribute.attr.as_str() == method && is_boto3_client_receiver(facts, &attribute.value)
        }
        _ => false,
    }
}

/// Per-file AWS Lambda handler facts, approximating
/// `AwsLambdaChecksUtils`: a function is a handler when its name matches
/// `.*(_handler|Handler)$` and it takes exactly `(event, ctx|context)`, or
/// when it is called (transitively, same-file) from such a handler.
pub(crate) struct AwsLambdaFacts<'a> {
    /// Shared lexical resolver (imports, single assignments, scopes).
    pub(crate) facts: WebFrameworkFacts<'a>,
    /// Ranges of every function considered a Lambda handler.
    handler_ranges: HashSet<TextRange>,
    /// Ranges of functions that are handlers by signature alone
    /// (`isOnlyLambdaHandler` in the reference).
    signature_handler_ranges: HashSet<TextRange>,
}

impl<'a> AwsLambdaFacts<'a> {
    pub(crate) fn build(file_ctx: &FileContext<'a>) -> Self {
        let facts = WebFrameworkFacts::build(file_ctx);
        let mut signature_handler_ranges = HashSet::new();
        for function in file_ctx.functions.iter().copied() {
            if is_lambda_handler_signature(function) {
                signature_handler_ranges.insert(function.range());
            }
        }
        // Call-graph walk: functions called from a handler are handlers too.
        let mut handler_ranges = signature_handler_ranges.clone();
        loop {
            let mut grew = false;
            for call in &file_ctx.calls {
                let Some(enclosing) = innermost_function(file_ctx, call.range()) else {
                    continue;
                };
                if !handler_ranges.contains(&enclosing.range()) {
                    continue;
                }
                if let Some(target) = facts.resolve_function(call) {
                    grew |= handler_ranges.insert(target.range());
                }
            }
            if !grew {
                break;
            }
        }
        AwsLambdaFacts {
            facts,
            handler_ranges,
            signature_handler_ranges,
        }
    }

    /// Any Lambda handler (signature or called-from-handler) exists in file.
    pub(crate) fn has_handler(&self) -> bool {
        !self.handler_ranges.is_empty()
    }

    /// `function` is a Lambda handler (signature or called from one).
    pub(crate) fn is_lambda_handler(&self, function: &StmtFunctionDef) -> bool {
        self.handler_ranges.contains(&function.range())
    }

    /// `function` is a Lambda handler by signature only.
    pub(crate) fn is_only_lambda_handler(&self, function: &StmtFunctionDef) -> bool {
        self.signature_handler_ranges.contains(&function.range())
    }
}

/// The innermost `FunctionDef` containing `at` (lambdas are not functions
/// here, matching `TreeUtils.firstAncestorOfClass(FunctionDef)`).
pub(crate) fn innermost_function<'a>(
    file_ctx: &'a FileContext<'a>,
    at: TextRange,
) -> Option<&'a StmtFunctionDef> {
    file_ctx
        .functions
        .iter()
        .filter(|function| function.range().contains_range(at))
        .min_by_key(|function| function.range().len().to_u32())
        .copied()
}

/// `SignatureBasedAwsLambdaHandlersCollector`: name ends in `_handler` or
/// `Handler`, and the parameter list is exactly `(event, ctx|context)`.
fn is_lambda_handler_signature(function: &StmtFunctionDef) -> bool {
    let name = function.name.as_str();
    if !(name.ends_with("_handler") || name.ends_with("Handler")) {
        return false;
    }
    let parameters = &function.parameters;
    let names: Vec<&str> = parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .map(|parameter| parameter.parameter.name.as_str())
        .chain(
            parameters
                .vararg
                .iter()
                .map(|parameter| parameter.name.as_str()),
        )
        .chain(
            parameters
                .kwonlyargs
                .iter()
                .map(|parameter| parameter.parameter.name.as_str()),
        )
        .chain(
            parameters
                .kwarg
                .iter()
                .map(|parameter| parameter.name.as_str()),
        )
        .collect();
    names.len() == 2 && names[0] == "event" && matches!(names[1], "ctx" | "context")
}

/// Whether the value is `"*"` or a mapping whose `"AWS"` entry is `"*"`.
pub(crate) fn grants_to_all_principals(expr: &Expr) -> bool {
    match expr {
        Expr::Dict(dict) => dict_string_entry(dict, "AWS").is_some_and(is_wildcard_string),
        _ => is_wildcard_string(expr),
    }
}

// ---------------------------------------------------------------------------
// Shared boto3/CDK machinery for the python:S6243, python:S6246,
// python:S6249, python:S6262, and python:S7625 detectors.
//
// The reference checks lean on SonarPython's type system (`isTypeWithFqn`,
// `inferSingleAssignedExpressionType`, `Expressions.singleAssignedValue`).
// Hoonarqube reconstructs the same identities with `WebFrameworkFacts`:
// import aliases resolve to their module path, `name = Constructor(...)`
// bindings resolve through the scope chain, and attribute tails append.
// ---------------------------------------------------------------------------

/// Canonical AWS FQN of `expr`: collapses the doubled tail segment that
/// `import boto3.session` / `import mysql.connector` produce when the bound
/// root already names the submodule, and maps the `boto3.Session` re-export
/// onto `boto3.session.Session`.
pub(crate) fn aws_fqn(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> Option<String> {
    let fqn = facts.expr_fqn(expr)?;
    let mut segments: Vec<&str> = fqn.split('.').collect();
    segments.dedup();
    let collapsed = segments.join(".");
    if collapsed == "boto3.Session" || collapsed.starts_with("boto3.Session.") {
        return Some(collapsed.replacen("boto3.Session", "boto3.session.Session", 1));
    }
    Some(collapsed)
}

/// Boto3 call shapes the AWS rules dispatch on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Boto3Callee {
    /// `boto3.client(...)`
    Client,
    /// `boto3.resource(...)`
    Resource,
    /// `boto3.session.Session(...)` (any import spelling)
    SessionNew,
    /// `<session>.client(...)`
    SessionClient,
    /// `<session>.resource(...)`
    SessionResource,
}

/// Classifies `call.func` as a boto3 client/resource/session producer. A
/// `<name>.client` / `<name>.resource` receiver counts when every assignment
/// of `name` visible from the call site constructs a `boto3` `Session`.
pub(crate) fn boto3_callee(facts: &WebFrameworkFacts<'_>, call: &ExprCall) -> Option<Boto3Callee> {
    let at = call.range();
    if let Some(fqn) = aws_fqn(facts, &call.func) {
        return match fqn.as_str() {
            "boto3.client" => Some(Boto3Callee::Client),
            "boto3.resource" => Some(Boto3Callee::Resource),
            "boto3.session.Session" => Some(Boto3Callee::SessionNew),
            "boto3.session.Session.client" => Some(Boto3Callee::SessionClient),
            "boto3.session.Session.resource" => Some(Boto3Callee::SessionResource),
            _ => None,
        };
    }
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return None;
    };
    let Expr::Name(receiver) = attribute.value.as_ref() else {
        return None;
    };
    if !is_session_receiver(facts, receiver.id.as_str(), at) {
        return None;
    }
    match attribute.attr.as_str() {
        "client" => Some(Boto3Callee::SessionClient),
        "resource" => Some(Boto3Callee::SessionResource),
        _ => None,
    }
}

/// Whether `name` read at `at` is a boto3 `Session` object: either the
/// scope-resolved single assignment constructs one, or every plain
/// assignment of `name` in the scopes enclosing `at` does (the reference's
/// declared-type inference keeps the `Session` type across reassignments).
fn is_session_receiver(facts: &WebFrameworkFacts<'_>, name: &str, at: TextRange) -> bool {
    all_assigned_values_match(facts, name, at, &|value| {
        matches!(
            value,
            Expr::Call(call)
                if aws_fqn(facts, &call.func).as_deref() == Some("boto3.session.Session")
        )
    })
}

/// Whether `name` read at `at` is a boto3 client object: every plain
/// assignment in the scopes enclosing `at` calls `boto3.client` or
/// `<session>.client`.
pub(crate) fn is_client_receiver(facts: &WebFrameworkFacts<'_>, name: &str, at: TextRange) -> bool {
    all_assigned_values_match(facts, name, at, &|value| {
        matches!(
            value,
            Expr::Call(call)
                if matches!(
                    boto3_callee(facts, call),
                    Some(Boto3Callee::Client | Boto3Callee::SessionClient)
                )
        )
    })
}

/// Every plain `name = value` assignment visible from `at` must satisfy
/// `predicate`, and at least one must exist. Single assignments resolve
/// through the scope chain first so a same-scope binding wins over an
/// unrelated outer one.
fn all_assigned_values_match(
    facts: &WebFrameworkFacts<'_>,
    name: &str,
    at: TextRange,
    predicate: &dyn Fn(&Expr) -> bool,
) -> bool {
    if let Some(value) = facts.single_assigned_value(name, at) {
        return predicate(value);
    }
    let chain: HashSet<Option<TextRange>> = facts.enclosing_chain(at).into_iter().collect();
    let mut matched = false;
    let mut failed = false;
    for stmt in &facts.stmts {
        let stmt: &Stmt = stmt;
        let value: Option<&Expr> = match stmt {
            Stmt::Assign(assign)
                if assign.targets.iter().any(
                    |target| matches!(target, Expr::Name(target) if target.id.as_str() == name),
                ) =>
            {
                Some(assign.value.as_ref())
            }
            Stmt::AnnAssign(assign) if matches!(assign.target.as_ref(), Expr::Name(target) if target.id.as_str() == name) => {
                assign.value.as_deref()
            }
            _ => None,
        };
        if let Some(value) = value
            && chain.contains(&facts.enclosing_scope(stmt.range()))
        {
            matched = true;
            if !predicate(value) {
                failed = true;
            }
        }
    }
    matched && !failed
}

/// `Expressions.ifNameGetSingleAssignedNonNameValue`: a `Name` resolves to
/// its single assigned value when that value is not itself a `Name`;
/// anything else resolves to the expression unchanged.
pub(crate) fn resolved_value<'a>(facts: &WebFrameworkFacts<'a>, expr: &'a Expr) -> &'a Expr {
    if let Expr::Name(name) = expr
        && let Some(value) = facts.single_assigned_value(name.id.as_str(), name.range())
        && !matches!(value, Expr::Name(_))
    {
        return value;
    }
    expr
}

/// String text of `expr` after the single-assignment resolution the
/// reference checks apply to keyword arguments.
pub(crate) fn resolved_string_literal(
    facts: &WebFrameworkFacts<'_>,
    expr: &Expr,
) -> Option<String> {
    string_literal_text(resolved_value(facts, expr))
}

/// Positional argument `position` of `call`, else the `name` keyword's value
/// (`TreeUtils.nthArgumentOrKeyword`).
pub(crate) fn nth_or_keyword_arg<'a>(
    call: &'a ExprCall,
    position: usize,
    name: &str,
) -> Option<&'a Expr> {
    if let Some(expr) = call.arguments.args.get(position) {
        return Some(expr);
    }
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_deref() == Some(name))
        .map(|keyword| &keyword.value)
}

/// Range of positional argument `position`, else of the whole `name` keyword
/// (`name=value`), matching the reference's `RegularArgument` anchor.
pub(crate) fn nth_or_keyword_range(
    call: &ExprCall,
    position: usize,
    name: &str,
) -> Option<TextRange> {
    if let Some(expr) = call.arguments.args.get(position) {
        return Some(expr.range());
    }
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_deref() == Some(name))
        .map(Ranged::range)
}

/// Whether the call passes a `**mapping` whose value is not a literal dict
/// (the reference cannot see through it, so the rules skip the call).
pub(crate) fn has_unknown_keyword_unpack(arguments: &ruff_python_ast::Arguments) -> bool {
    arguments
        .keywords
        .iter()
        .any(|keyword| keyword.arg.is_none() && !matches!(keyword.value, Expr::Dict(_)))
}

/// `name` entry of a literal-dict `**{...}` unpack, if present.
pub(crate) fn literal_unpacked_keyword<'a>(
    arguments: &'a ruff_python_ast::Arguments,
    name: &str,
) -> Option<&'a Expr> {
    arguments.keywords.iter().find_map(|keyword| {
        if keyword.arg.is_some() {
            return None;
        }
        let Expr::Dict(dict) = &keyword.value else {
            return None;
        };
        dict_string_entry(dict, name)
    })
}

// --- boto3/aiobotocore client helpers ----------------------------------------
//
// SonarPython types every `boto3.client(...)`/`boto3.Session().client(...)`
// result as `botocore.client.BaseClient` and every
// `aiobotocore.session.get_session().create_client(...)` result as
// `aiobotocore.client.AioBaseClient`, so the AWS rules only need to know that
// a receiver was produced by one of those factories — the service argument is
// irrelevant. `expr_fqn` already resolves `name = <factory call>` bindings
// and direct `boto3.client("s3").method()` chains to the factory's FQN.

/// Whether `expr` resolves to a boto3/botocore/aiobotocore client factory
/// call (`boto3.client`, `boto3.Session().client`,
/// `aiobotocore.session.get_session().create_client`, …). `with ... as`
/// bindings intentionally stay unresolved, matching Sonar's
/// `inferSingleAssignedExpressionType` blind spot. Unlike
/// `is_boto3_client_receiver` this also covers aiobotocore/botocore
/// factories, which the S7608/S7609 upstream checks type against
/// `AioBaseClient`.
pub(crate) fn resolves_to_aws_client(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> bool {
    let Some(fqn) = facts.expr_fqn(expr) else {
        return false;
    };
    let Some((base, factory)) = fqn.rsplit_once('.') else {
        return false;
    };
    matches!(factory, "client" | "create_client")
        && (base == "boto3"
            || base.starts_with("boto3.")
            || base == "botocore"
            || base.starts_with("botocore.")
            || base == "aiobotocore"
            || base.starts_with("aiobotocore."))
}
