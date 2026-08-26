use crate::engine::file_context::FileContext;
use crate::support::dotted_name_in;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7492 — materialized list passed to any/all -----------------------------

pub(crate) fn check_any_all_list_comprehension(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name_in(&call.func, &["any", "all"])
            && let [only] = &call.arguments.args[..]
            && matches!(only, Expr::ListComp(_))
        {
            issues.push(issue_at(
                "python:S7492",
                "Pass a generator expression instead of a materialized list.",
                only.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7492_prefers_generator_expressions_for_any_all() {
        let flagged = scan("any([x for x in xs])\nany(x for x in xs)\n");
        assert_eq!(findings(&flagged, "python:S7492").len(), 1);
    }
}
