use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_typealias_assignments(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::AnnAssign(assign) = stmt
            && matches!(
                dotted_name(&assign.annotation).as_deref(),
                Some("typing.TypeAlias" | "TypeAlias")
            )
        {
            issues.push(issue_at(
                "python:S6794",
                "Use the type statement for this alias.",
                stmt.range(),
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
    fn s6794_prefers_type_statement_aliases() {
        let flagged = scan("X: TypeAlias = int\nY = int\n");
        assert_eq!(findings(&flagged, "python:S6794").len(), 1);
    }
}
