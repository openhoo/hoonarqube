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
        let mut seen_bare = false;
        let mut seen_broad: Option<&'static str> = None;
        let mut seen_types: Vec<String> = Vec::new();
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let Some(type_expr) = inner.type_.as_deref() else {
                if seen_bare || !seen_types.is_empty() || seen_broad.is_some() {
                    issues.push(issue_at(
                        "python:S1045",
                        "This except block cannot catch anything; review the preceding clauses.",
                        inner.range(),
                        index,
                        source,
                    ));
                }
                seen_bare = true;
                continue;
            };
            let normalized = expr_normalized_text(type_expr, source);
            if seen_bare || seen_broad.is_some() {
                issues.push(issue_at(
                    "python:S1045",
                    "This except block cannot catch anything; an earlier clause catches everything.",
                    type_expr.range(),
                    index,
                    source,
                ));
            } else if seen_types.iter().any(|previous| previous == &normalized) {
                issues.push(issue_at(
                    "python:S1045",
                    "An earlier except clause catches the same exceptions.",
                    type_expr.range(),
                    index,
                    source,
                ));
            }
            if normalized == "Exception" || normalized == "BaseException" {
                seen_broad = Some(match normalized.as_str() {
                    "Exception" => "Exception",
                    _ => "BaseException",
                });
            }
            seen_types.push(normalized);
        }
    }
    issues
}
