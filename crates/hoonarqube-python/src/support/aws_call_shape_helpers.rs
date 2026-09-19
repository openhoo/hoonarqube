// --- AWS call-shape helpers

use crate::support::{for_each_stmt_expr, string_literal_text};
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_text_size::Ranged;

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

/// Whether the value is `"*"` or a mapping whose `"AWS"` entry is `"*"`.
pub(crate) fn grants_to_all_principals(expr: &Expr) -> bool {
    match expr {
        Expr::Dict(dict) => dict_string_entry(dict, "AWS").is_some_and(is_wildcard_string),
        _ => is_wildcard_string(expr),
    }
}

// --- boto3/aiobotocore client and Lambda-handler helpers ---------------------
//
// SonarPython types every `boto3.client(...)`/`boto3.Session().client(...)`
// result as `botocore.client.BaseClient` and every
// `aiobotocore.session.get_session().create_client(...)` result as
// `aiobotocore.client.AioBaseClient`, so the AWS rules only need to know that
// a receiver was produced by one of those factories — the service argument is
// irrelevant. `expr_fqn` already resolves `name = <factory call>` bindings
// and direct `boto3.client("s3").method()` chains to the factory's FQN.

use crate::engine::file_context::FileContext;
use crate::support::WebFrameworkFacts;
use ruff_python_ast::StmtFunctionDef;
use ruff_text_size::TextRange;
use std::collections::HashSet;

/// Whether `expr` resolves to a boto3/botocore/aiobotocore client factory
/// call (`boto3.client`, `boto3.Session().client`,
/// `aiobotocore.session.get_session().create_client`, …). `with ... as`
/// bindings intentionally stay unresolved, matching Sonar's
/// `inferSingleAssignedExpressionType` blind spot.
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

/// Sonar's `SignatureBasedAwsLambdaHandlersCollector`: a function is a Lambda
/// handler when its name ends in `_handler` or `Handler` (with at least one
/// preceding character) and it declares exactly two parameters named `event`
/// and `context`/`ctx`, in that order.
pub(crate) fn has_lambda_handler_signature(function: &StmtFunctionDef) -> bool {
    let name = function.name.as_str();
    let name_matches = (name.len() > "_handler".len() && name.ends_with("_handler"))
        || (name.len() > "Handler".len() && name.ends_with("Handler"));
    if !name_matches {
        return false;
    }
    let parameters = &function.parameters;
    if parameters.vararg.is_some() || parameters.kwarg.is_some() {
        return false;
    }
    let names: Vec<&str> = parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .map(|with_default| with_default.parameter.name.as_str())
        .collect();
    names.len() == 2 && names[0] == "event" && matches!(names[1], "context" | "ctx")
}

/// The innermost function definition enclosing `at` (class bodies are
/// transparent, matching Sonar's `firstAncestorOfKind(FUNCDEF)`).
pub(crate) fn enclosing_function<'a>(
    facts: &WebFrameworkFacts<'a>,
    file_ctx: &FileContext<'a>,
    at: TextRange,
) -> Option<&'a StmtFunctionDef> {
    let scope = facts.enclosing_scope(at)?;
    file_ctx
        .functions
        .iter()
        .find(|function| function.range() == scope)
        .copied()
}

/// Ranges of every function that is a Lambda handler by signature or is
/// transitively called from one — Sonar's `isLambdaHandler` (configured FQN
/// plus `CallGraphWalker.isUsedFrom`). Only same-file call targets resolve.
pub(crate) fn lambda_related_function_ranges<'a>(
    facts: &WebFrameworkFacts<'a>,
    file_ctx: &FileContext<'a>,
) -> HashSet<TextRange> {
    let mut related: HashSet<TextRange> = file_ctx
        .functions
        .iter()
        .filter(|function| has_lambda_handler_signature(function))
        .map(Ranged::range)
        .collect();
    let mut queue: Vec<TextRange> = related.iter().copied().collect();
    while let Some(range) = queue.pop() {
        for call in &file_ctx.calls {
            if !range.contains_range(call.range()) {
                continue;
            }
            if let Some(target) = facts.resolve_function(call)
                && related.insert(target.range())
            {
                queue.push(target.range());
            }
        }
    }
    related
}
