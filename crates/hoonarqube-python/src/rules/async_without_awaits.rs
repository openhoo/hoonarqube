use crate::support::for_each_expr;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_async_without_awaits(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.is_async
            && !async_features_present(function)
        {
            issues.push(issue_at(
                "python:S7503",
                "This async function never awaits; make it synchronous or await something.",
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S7503) ---
// --- python:S7503 — async function without async features ---------------------------

fn async_features_present(function: &ruff_python_ast::StmtFunctionDef) -> bool {
    let mut found = false;
    for_each_stmt_in_scope(function.body.as_slice(), &mut |stmt| {
        match stmt {
            Stmt::For(loop_stmt) => found |= loop_stmt.is_async,
            Stmt::With(with_stmt) => found |= with_stmt.is_async,
            _ => {}
        }
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                found |= matches!(expr, Expr::Await(_));
            });
        }
    });
    found
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7503_flags_async_functions_without_awaits() {
        let flagged = scan(concat!(
            "async def noop():\n",
            "    return 1\n",
            "async def real():\n",
            "    await asyncio.sleep(1)\n"
        ));
        let found = findings(&flagged, "python:S7503");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
    }
}
