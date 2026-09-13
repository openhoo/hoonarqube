use crate::engine::file_context::FileContext;
use crate::support::dotted_name_in;
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
            && dotted_name_in(&assign.annotation, &["typing.TypeAlias", "TypeAlias"])
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
    #[test]
    fn s6794_flags_typealias_annotation_through_typing_module_alias() {
        let flagged =
            scan("import typing as t\n\nAliased: t.TypeAlias = int\nUnrelated = int\n");
        let found = findings(&flagged, "python:S6794");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);

        // Only the typing module's alias resolves; foreign modules with the
        // same local spelling stay clean.
        let foreign =
            scan("import other as t\n\nMissing: t.TypeAlias = int\n");
        assert!(findings(&foreign, "python:S6794").is_empty());
    }
}
