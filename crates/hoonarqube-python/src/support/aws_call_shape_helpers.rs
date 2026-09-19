// --- AWS call-shape helpers

use crate::support::{for_each_stmt_expr, string_literal_text};
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::WebFrameworkFacts;
use ruff_python_ast::StmtFunctionDef;
use ruff_text_size::TextRange;
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
