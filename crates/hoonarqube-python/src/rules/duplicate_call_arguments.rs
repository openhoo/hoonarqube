use crate::engine::calls::LocalSignatures;
use crate::engine::calls::ResolvedCallee;
use crate::support::for_each_stmt_with_class;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashSet;

// --- python:S5549 — arguments bound to the same parameter --------------------
//
// The reference reports duplicate *parameter bindings*: the same parameter
// supplied positionally and by keyword, or a `**dict` literal key colliding
// with an explicit argument. It requires a resolvable callee, so calls to
// unknown functions are never flagged.

pub(crate) fn check_duplicate_call_arguments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let signatures = LocalSignatures::new(parsed.syntax().body.as_slice());
    let mut issues = Vec::new();
    for_each_stmt_with_class(
        parsed.syntax().body.as_slice(),
        None,
        &mut |stmt, class_context| {
            for top_expr in stmt_exprs(stmt) {
                let mut pending = vec![top_expr];
                while let Some(expr) = pending.pop() {
                    let Expr::Call(call) = expr else {
                        pending.extend(crate::support::child_exprs(expr));
                        continue;
                    };
                    if let Some(resolved) = signatures.resolve(&call.func, class_context)
                        && has_duplicate_binding(&resolved, &call.arguments)
                    {
                        issues.push(issue_at(
                            "python:S5549",
                            "This identical argument appears more than once.",
                            call.range(),
                            index,
                            source,
                        ));
                    }
                    pending.extend(crate::support::child_exprs(expr));
                }
            }
        },
    );
    issues
}

/// Whether any parameter of the resolved callee is bound twice: positionally
/// and by keyword, or by an explicit argument plus a `**{...}` literal key.
fn has_duplicate_binding(
    resolved: &ResolvedCallee,
    arguments: &ruff_python_ast::Arguments,
) -> bool {
    let parameters = &resolved.function().parameters;
    let mut positional: Vec<&str> = parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .map(|entry| entry.parameter.name.as_str())
        .collect();
    if resolved.skips_receiver() && !positional.is_empty() {
        positional.remove(0);
    }
    let mut bound: HashSet<String> = HashSet::new();
    for (position, _argument) in arguments.args.iter().enumerate() {
        if let Some(name) = positional.get(position) {
            bound.insert((*name).to_string());
        }
    }
    let keyword_names: HashSet<&str> = parameters
        .args
        .iter()
        .chain(&parameters.kwonlyargs)
        .map(|entry| entry.parameter.name.as_str())
        .collect();
    for keyword in &arguments.keywords {
        match keyword.arg.as_ref() {
            Some(name) => {
                if !bound.insert(name.to_string()) {
                    return true;
                }
            }
            // `**{"name": ...}` binds `name` like an explicit keyword.
            None => {
                if let Expr::Dict(dict) = &keyword.value {
                    for item in &dict.items {
                        if let Some(key) = item.key.as_ref()
                            && let Expr::StringLiteral(literal) = key
                        {
                            let text = crate::support::string_value_text(&literal.value);
                            if keyword_names.contains(text.as_str()) && !bound.insert(text) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}
