use crate::engine::file_context::FileContext;
use crate::support::decorator_callee_path;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1607 — skipped tests without a reason ----------------------------------

pub(crate) fn check_skip_without_reason(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
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
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1607_requires_reasons_for_skips() {
        let flagged = scan(
            "@unittest.skip()\ndef t1():\n    pass\n@unittest.skip(\"flaky\")\ndef t2():\n    pass\n",
        );
        assert_eq!(findings(&flagged, "python:S1607").len(), 1);
    }
}
