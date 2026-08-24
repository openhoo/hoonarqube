use crate::support::exception_type_names;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5754 — SystemExit must be re-raised -------------------------------

pub(crate) fn check_swallowed_system_exit(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else { return };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let caught = exception_type_names(inner.type_.as_deref());
            if !caught.iter().any(|name| name == "SystemExit") {
                continue;
            }
            let mut re_raised = false;
            for_each_stmt_in_scope(&inner.body, &mut |candidate| {
                re_raised |= matches!(candidate, Stmt::Raise(_));
            });
            if !re_raised {
                issues.push(issue_at(
                    "python:S5754",
                    "Re-raise 'SystemExit'; swallowing it prevents proper termination.",
                    handler.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5754_requires_systemexit_reraise() {
        let flagged = scan("try:\n    run_app()\nexcept SystemExit:\n    cleanup()\n");
        assert_eq!(findings(&flagged, "python:S5754").len(), 1);
        let clean = "try:\n    run_app()\nexcept ValueError:\n    cleanup()\n";
        assert!(findings(&scan(clean), "python:S5754").is_empty());
    }
}
