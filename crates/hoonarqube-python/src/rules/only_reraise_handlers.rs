use crate::support::exception_type_names;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2737 — except clause that only re-raises -------------------------

pub(crate) fn check_only_reraise_handlers(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else { return };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let [only] = &inner.body[..] else { continue };
            let Stmt::Raise(raised) = only else { continue };
            let caught = exception_type_names(inner.type_.as_deref());
            let pure_reraise = raised.exc.is_none() && raised.cause.is_none()
                || raised.exc.as_deref().is_some_and(
                    |exc| matches!(exc, Expr::Name(name) if caught.contains(&name.id.to_string())),
                );
            if pure_reraise {
                issues.push(issue_at(
                    "python:S2737",
                    "Remove this 'except' clause or handle the exception; it only re-raises.",
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
    fn s2737_flags_handlers_that_only_reraise() {
        let flagged = scan("try:\n    risky()\nexcept ValueError:\n    raise\n");
        assert_eq!(findings(&flagged, "python:S2737").len(), 1);
        let clean = "try:\n    risky()\nexcept ValueError:\n    log()\n    raise\n";
        assert!(findings(&scan(clean), "python:S2737").is_empty());
    }
}
