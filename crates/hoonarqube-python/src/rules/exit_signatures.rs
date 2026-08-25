use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2733 — `__exit__` signature --------------------------------------

pub(crate) fn check_exit_signatures(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = stmt
            && function.name.as_str() == "__exit__"
            && positional_parameters(&function.parameters).len() < 4
        {
            issues.push(issue_at(
                "python:S2733",
                "'__exit__' requires the exc_type, exc_value and traceback parameters.",
                function.name.range(),
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
    fn s2733_checks_exit_signature_completeness() {
        let flagged =
            scan("class C:\n    def __exit__(self, kind, value):\n        return False\n");
        assert_eq!(findings(&flagged, "python:S2733").len(), 1);
        let clean = "class C:\n    def __exit__(self, kind, value, trace):\n        return False\n";
        assert!(findings(&scan(clean), "python:S2733").is_empty());
    }
}
