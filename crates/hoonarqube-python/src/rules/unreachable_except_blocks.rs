use crate::engine::file_context::FileContext;
use crate::support::expr_normalized_text;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// ---------------------------------------------------------------------------
// flow: control-flow / exception-flow reasoning.
// ---------------------------------------------------------------------------

// --- python:S1045 — unreachable except blocks --------------------------------

pub(crate) fn check_unreachable_except_blocks(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::Try(try_stmt) = stmt else { continue };
        let mut seen = SeenHandlers::default();
        for handler in &try_stmt.handlers {
            if let Some(issue) = seen.check(handler, index, source) {
                issues.push(issue);
            }
        }
    }
    issues
}

#[derive(Default)]
struct SeenHandlers {
    bare: bool,
    broad: bool,
    types: Vec<String>,
}

impl SeenHandlers {
    fn check(&mut self, handler: &ExceptHandler, index: &LineIndex, source: &str) -> Option<Issue> {
        let ExceptHandler::ExceptHandler(inner) = handler;
        let Some(type_expr) = inner.type_.as_deref() else {
            let unreachable = self.bare || self.broad || !self.types.is_empty();
            self.bare = true;
            return unreachable.then(|| {
                issue_at(
                    "python:S1045",
                    "This except block cannot catch anything; review the preceding clauses.",
                    inner.range(),
                    index,
                    source,
                )
            });
        };
        let normalized = expr_normalized_text(type_expr, source);
        let issue = if self.bare || self.broad {
            Some(issue_at(
                "python:S1045",
                "This except block cannot catch anything; an earlier clause catches everything.",
                type_expr.range(),
                index,
                source,
            ))
        } else if self.types.contains(&normalized) {
            Some(issue_at(
                "python:S1045",
                "Catch this exception only once; it is already handled by a previous except clause.",
                type_expr.range(),
                index,
                source,
            ))
        } else {
            None
        };
        self.broad |= matches!(normalized.as_str(), "Exception" | "BaseException");
        self.types.push(normalized);
        issue
    }
}
