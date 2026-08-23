use crate::support::expr_normalized_text;
use crate::support::for_each_stmt;
use crate::support::is_constant_expression;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7519 — constant-populated dict built in a loop ------------------------

pub(crate) fn check_constant_populated_dict_loop(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::For(for_stmt) = stmt else { return };
        if for_stmt.body.is_empty() {
            return;
        }
        let mut constant: Option<String> = None;
        let all_constant_assignments = for_stmt.body.iter().all(|inner| {
            let Stmt::Assign(assign) = inner else {
                return false;
            };
            let [Expr::Subscript(subscript)] = &assign.targets[..] else {
                return false;
            };
            matches!(subscript.slice.as_ref(), Expr::Name(_))
                && matches!(subscript.value.as_ref(), Expr::Name(_))
                && is_constant_expression(&assign.value)
        }) && for_stmt.body.iter().all(|inner| {
            let Stmt::Assign(assign) = inner else {
                return false;
            };
            let normalized = expr_normalized_text(&assign.value, source);
            match &constant {
                None => {
                    constant = Some(normalized);
                    true
                }
                Some(existing) => *existing == normalized,
            }
        });
        if all_constant_assignments {
            issues.push(issue_at(
                "python:S7519",
                "Populate this dictionary with 'dict.fromkeys' instead of assigning a constant in a loop.",
                for_stmt.range(),
                index,
                source,
            ));
        }
    });
    issues
}
