use crate::support::collect_void_function_names;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

/// python:S3699 — flags expression-position uses of calls to file-local void
/// functions: every call except a whole expression statement, a decorator
/// subtree, or a directly awaited operand consumes the (nonexistent) output.
pub(crate) fn check_s3699_used_void_outputs(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let module = parsed.syntax().body.as_slice();
    let void = collect_void_function_names(module);
    if void.is_empty() {
        return Vec::new();
    }
    let mut exempt_ranges: Vec<TextRange> = Vec::new();
    for_each_stmt(module, &mut |stmt| match stmt {
        Stmt::Expr(expr_stmt) => {
            if let Expr::Call(call) = expr_stmt.value.as_ref() {
                exempt_ranges.push(call.range());
            }
        }
        Stmt::FunctionDef(function) => {
            for decorator in &function.decorator_list {
                exempt_ranges.push(decorator.range());
            }
        }
        Stmt::ClassDef(class) => {
            for decorator in &class.decorator_list {
                exempt_ranges.push(decorator.range());
            }
        }
        _ => {}
    });
    for_each_stmt_expr(module, &mut |expr| {
        if let Expr::Await(awaited) = expr
            && let Expr::Call(call) = awaited.value.as_ref()
        {
            exempt_ranges.push(call.range());
        }
    });
    let mut issues = Vec::new();
    for_each_stmt_expr(module, &mut |expr| {
        let Expr::Call(call) = expr else {
            return;
        };
        let Expr::Name(callee) = call.func.as_ref() else {
            return;
        };
        if !void.contains(callee.id.as_str()) || exempt_ranges.contains(&call.range()) {
            return;
        }
        issues.push(issue_at(
            "python:S3699",
            &format!(
                "'{}' returns nothing, so this use of its output is invalid.",
                callee.id.as_str()
            ),
            call.func.range(),
            index,
            source,
        ));
    });
    issues
}
