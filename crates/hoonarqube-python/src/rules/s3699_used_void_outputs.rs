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
use std::collections::HashMap;
use std::collections::HashSet;

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

// --- migrated from support/mod.rs (S3699) ---
// --- python:S3699 — output of functions returning nothing should not be used -

/// Whether the undecorated, non-async function provably returns nothing:
/// no `return <value>` and no `yield` anywhere in its body.
pub(crate) fn is_void_function(function: &ruff_python_ast::StmtFunctionDef) -> bool {
    if function.is_async || !function.decorator_list.is_empty() {
        return false;
    }
    let mut returns_value = false;
    for_each_stmt(&function.body, &mut |stmt| {
        if let Stmt::Return(returned) = stmt
            && returned.value.is_some()
        {
            returns_value = true;
        }
    });
    let mut yields = false;
    for_each_stmt_expr(&function.body, &mut |expr| {
        if matches!(expr, Expr::Yield(_) | Expr::YieldFrom(_)) {
            yields = true;
        }
    });
    !returns_value && !yields
}

/// Names of module-level functions satisfying [`is_void_function`]. Duplicate
/// definitions shadow one another and are dropped as ambiguous.
pub(crate) fn collect_void_function_names(module: &[Stmt]) -> HashSet<String> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for stmt in module {
        if let Stmt::FunctionDef(function) = stmt {
            *counts
                .entry(function.name.as_str().to_string())
                .or_insert(0) += 1;
        }
    }
    let mut void = HashSet::new();
    for stmt in module {
        if let Stmt::FunctionDef(function) = stmt
            && counts.get(function.name.as_str()) == Some(&1)
            && is_void_function(function)
        {
            void.insert(function.name.as_str().to_string());
        }
    }
    void
}
