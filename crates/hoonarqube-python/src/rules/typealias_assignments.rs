use crate::support::dotted_name;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_typealias_assignments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
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
    });
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
