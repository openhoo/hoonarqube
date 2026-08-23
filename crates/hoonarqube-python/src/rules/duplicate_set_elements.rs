use crate::support::constant_literal_text;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5781 — duplicate set literal values ---------------------------------

pub(crate) fn check_duplicate_set_elements(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Set(set) = expr else { return };
        let mut seen = std::collections::HashSet::new();
        for element in &set.elts {
            let Some(canonical) = constant_literal_text(element) else {
                continue;
            };
            if !seen.insert(canonical) {
                issues.push(issue_at(
                    "python:S5781",
                    "Remove this duplicate element.",
                    element.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
