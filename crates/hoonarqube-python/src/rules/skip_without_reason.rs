use crate::support::decorator_callee_path;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1607 — skipped tests without a reason ----------------------------------

pub(crate) fn check_skip_without_reason(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt {
            for decorator in &function.decorator_list {
                if let Expr::Call(call) = &decorator.expression
                    && matches!(
                        decorator_callee_path(&call.func).as_deref(),
                        Some("unittest.skip" | "pytest.mark.skip")
                    )
                    && call.arguments.args.is_empty()
                {
                    issues.push(issue_at(
                        "python:S1607",
                        "Give a reason for skipping this test.",
                        call.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}
