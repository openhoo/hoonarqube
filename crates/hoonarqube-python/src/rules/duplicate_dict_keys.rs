use crate::engine::file_context::FileContext;
use crate::support::constant_literal_text;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5780 — duplicate dict literal keys ---------------------------------

pub(crate) fn check_duplicate_dict_keys(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Dict(dict) = expr else { continue };
        let mut seen = std::collections::HashMap::new();
        let mut reported = std::collections::HashSet::new();
        for item in &dict.items {
            let Some(key) = &item.key else { continue };
            let Some(canonical) = constant_literal_text(key) else {
                continue;
            };
            if let Some(first_range) = seen.get(&canonical)
                && reported.insert(canonical.clone())
            {
                issues.push(issue_at(
                    "python:S5780",
                    "Change or remove duplicates of this key.",
                    *first_range,
                    index,
                    source,
                ));
            } else {
                seen.insert(canonical, key.range());
            }
        }
    }
    issues
}
