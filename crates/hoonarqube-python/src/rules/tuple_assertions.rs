use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5905 — assert on a tuple literal ---------------------------------

pub(crate) fn check_tuple_assertions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::Assert(assert) = stmt
            && let Expr::Tuple(tuple) = assert.test.as_ref()
            && !tuple.elts.is_empty()
        {
            issues.push(issue_at(
                "python:S5905",
                "This assertion always passes because it tests a non-empty tuple.",
                assert.test.range(),
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
    fn s5905_flags_nonempty_tuple_assertions() {
        let flagged = scan("assert (False, \"why\")\n");
        assert_eq!(findings(&flagged, "python:S5905").len(), 1);
        for clean in ["assert ()\n", "assert condition\n"] {
            assert!(findings(&scan(clean), "python:S5905").is_empty(), "{clean}");
        }
    }
}
