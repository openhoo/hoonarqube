use crate::support::constant_literal_text;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5780 — duplicate dict literal keys ---------------------------------

pub(crate) fn check_duplicate_dict_keys(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Dict(dict) = expr else { return };
        let mut seen = std::collections::HashSet::new();
        for item in &dict.items {
            let Some(key) = &item.key else { continue };
            let Some(canonical) = constant_literal_text(key) else {
                continue;
            };
            if !seen.insert(canonical) {
                issues.push(issue_at(
                    "python:S5780",
                    "Change this duplicate key; it overrides an earlier entry.",
                    key.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
