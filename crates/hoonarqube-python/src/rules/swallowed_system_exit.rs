use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::dotted_name;
use crate::support::exception_type_names;
use crate::support::for_each_stmt_expr_in_scope;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5754 — SystemExit must be re-raised -------------------------------

pub(crate) fn check_swallowed_system_exit(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::Try(try_stmt) = stmt else { continue };
        let mut system_exit_handled = false;
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let Some(caught_type) = inner.type_.as_deref() else {
                // Bare `except:` catches SystemExit too; the reference flags
                // it unless the body re-raises or SystemExit was handled by
                // an earlier clause, then stops scanning further handlers.
                if !system_exit_handled && !handler_reraises(&inner.body, None) {
                    issues.push(issue_at(
                        "python:S5754",
                        "Specify an exception class to catch or reraise the exception",
                        inner.range(),
                        index,
                        source,
                    ));
                }
                break;
            };
            system_exit_handled |= check_typed_handler(
                inner,
                caught_type,
                system_exit_handled,
                &mut issues,
                index,
                source,
            );
        }
    }
    issues
}

/// Flags a typed handler that swallows SystemExit/BaseException without
/// re-raising; returns whether SystemExit is now handled.
fn check_typed_handler(
    inner: &ruff_python_ast::ExceptHandlerExceptHandler,
    caught_type: &Expr,
    system_exit_handled: bool,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) -> bool {
    let mut handled = false;
    for name in exception_type_names(Some(caught_type)) {
        if handler_reraises(&inner.body, inner.name.as_deref()) {
            handled |= name == "SystemExit";
            continue;
        }
        if name == "SystemExit" {
            issues.push(issue_at(
                "python:S5754",
                "Reraise this exception to stop the application as the user expects",
                caught_type.range(),
                index,
                source,
            ));
            handled = true;
        } else if name == "BaseException" && !system_exit_handled {
            issues.push(issue_at(
                "python:S5754",
                "Catch a more specific exception or reraise the exception",
                caught_type.range(),
                index,
                source,
            ));
        }
    }
    handled
}

/// Whether the handler body re-raises: a bare `raise`, `raise <bound name>`,
/// `raise SystemExit`, or a call to `sys.exit`/`sys.exc_info` — the cases the
/// reference's ExceptionReRaiseCheckVisitor treats as propagation.
fn handler_reraises(body: &[Stmt], bound_name: Option<&str>) -> bool {
    let mut re_raised = false;
    for_each_stmt_in_scope(body, &mut |candidate| {
        if let Stmt::Raise(raise) = candidate {
            match raise.exc.as_deref() {
                None => re_raised = true,
                Some(Expr::Name(name))
                    if Some(name.id.as_str()) == bound_name || name.id.as_str() == "SystemExit" =>
                {
                    re_raised = true;
                }
                Some(Expr::Call(call)) if called_name(&call.func) == Some("SystemExit") => {
                    re_raised = true;
                }
                _ => {}
            }
        }
    });
    for_each_stmt_expr_in_scope(body, &mut |expr| {
        if let Expr::Call(call) = expr {
            re_raised |= matches!(
                dotted_name(&call.func).as_deref(),
                Some("sys.exit" | "sys.exc_info")
            );
        }
    });
    re_raised
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
        // `except BaseException` swallows SystemExit when no earlier clause
        // handles it and the body does not re-raise.
        let flagged = scan(
            "try:\n    work()\nexcept KeyboardInterrupt:\n    raise\nexcept BaseException as e:\n    record(e)\n",
        );
        assert_eq!(findings(&flagged, "python:S5754").len(), 1);
        // Re-raising the bound exception or calling sys.exit complies.
        let clean = "try:\n    work()\nexcept BaseException as e:\n    record(e)\n    raise\n";
        assert!(findings(&scan(clean), "python:S5754").is_empty());
        let clean = "try:\n    work()\nexcept BaseException:\n    sys.exit(1)\n";
        assert!(findings(&scan(clean), "python:S5754").is_empty());
        // A bare except after a handled SystemExit is compliant.
        let clean = "try:\n    work()\nexcept SystemExit:\n    raise\nexcept:\n    cleanup()\n";
        assert!(findings(&scan(clean), "python:S5754").is_empty());
    }
}
