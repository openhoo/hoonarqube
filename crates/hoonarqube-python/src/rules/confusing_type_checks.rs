use crate::support::called_name;
use crate::support::expr_normalized_text;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5864 — confusing type checks --------------------------------------

pub(crate) fn check_confusing_type_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        if called_name(&call.func) != Some("isinstance") || call.arguments.args.len() != 2 {
            return;
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
    });
    issues
}
