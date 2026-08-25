use crate::engine::file_context::FileContext;
use crate::support::stmt_exprs;
use crate::support::visit_ifexp_branches;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

pub(crate) fn check_nested_conditional_expressions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        for expr in stmt_exprs(stmt) {
            visit_ifexp_branches(expr, false, &mut issues, index, source);
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s3358_flags_nested_conditional_expressions() {
        let flagged = scan("v = a if b else c if d else e\n");
        assert_eq!(findings(&flagged, "python:S3358").len(), 1);
        assert!(findings(&scan("v = a if b else e\n"), "python:S3358").is_empty());
    }
}
