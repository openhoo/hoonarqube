use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::expr_normalized_text;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5864 — confusing type checks --------------------------------------

pub(crate) fn check_confusing_type_checks(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Call(call) = expr else { continue };
        if called_name(&call.func) != Some("isinstance") || call.arguments.args.len() != 2 {
            continue;
        }
        let checked = &call.arguments.args[0];
        let types = &call.arguments.args[1];
        let confusing = match types {
            Expr::List(_) | Expr::Set(_) | Expr::Dict(_) => true,
            Expr::Tuple(tuple) => {
                let elements: Vec<String> = tuple
                    .elts
                    .iter()
                    .map(|element| expr_normalized_text(element, source))
                    .collect();
                let mut unique = elements.clone();
                unique.sort();
                unique.dedup();
                unique.len() != elements.len()
            }
            _ => expr_normalized_text(checked, source) == expr_normalized_text(types, source),
        };
        if confusing {
            issues.push(issue_at(
                "python:S5864",
                "Fix this confusing type check; the second argument must be a distinct type or tuple of types.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
