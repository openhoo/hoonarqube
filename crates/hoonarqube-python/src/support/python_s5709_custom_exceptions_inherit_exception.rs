// --- python:S5709 — custom exceptions inherit Exception

use crate::context::FlowState;
use crate::engine::scope::RaiseContext;
use crate::support::{
    child_bodies, for_each_expr, for_each_stmt, for_each_stmt_expr, issue_at, loads_any_name,
    stmt_exprs,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn looks_like_exception_name(name: &str) -> bool {
    name.ends_with("Error") || name.ends_with("Warning") || name.ends_with("Exception")
}

/// Names of functions called inside an `except` or `finally` body —
/// Sonar's `RaiseOutsideExceptCheck` exempts their bare `raise`s.
pub(crate) type ExceptCalledFns = std::collections::HashSet<String>;

/// Collects the names of every function called inside an `except` or
/// `finally` body anywhere in `suite`.
pub(crate) fn collect_except_called_fns(suite: &[Stmt]) -> ExceptCalledFns {
    let mut names = ExceptCalledFns::new();
    for_each_stmt(suite, &mut |stmt| {
        if let Stmt::Try(try_stmt) = stmt {
            let mut collect = |body: &[Stmt]| {
                for_each_stmt_expr(body, &mut |expr| {
                    if let Expr::Call(call) = expr
                        && let Expr::Name(name) = call.func.as_ref()
                    {
                        names.insert(name.id.to_string());
                    }
                });
            };
            for handler in &try_stmt.handlers {
                let ExceptHandler::ExceptHandler(inner) = handler;
                collect(&inner.body);
            }
            collect(&try_stmt.finalbody);
        }
    });
    names
}

pub(crate) fn scan_flow_statements(
    suite: &[Stmt],
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let exempt = collect_except_called_fns(suite);
    scan_flow_statements_in(suite, state, None, &exempt, issues, index, source);
}

fn scan_flow_statements_in(
    suite: &[Stmt],
    state: FlowState,
    current_fn: Option<&str>,
    exempt_fns: &ExceptCalledFns,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in suite {
        match stmt {
            Stmt::Break(_) | Stmt::Continue(_) => {
                flag_flow_jump(stmt, state, issues, index, source);
            }
            Stmt::Return(_) => {
                if state.finally_depth > 0 {
                    issues.push(issue_at(
                        "python:S1143",
                        "Remove this \"return\" statement from this \"finally\" block.",
                        stmt.range(),
                        index,
                        source,
                    ));
                }
            }
            Stmt::Raise(raised) => {
                flag_flow_raise(raised, state, current_fn, exempt_fns, issues, index, source);
            }
            _ => {
                scan_flow_nested_bodies(stmt, state, current_fn, exempt_fns, issues, index, source);
            }
        }
    }
}

fn flag_flow_jump(
    stmt: &Stmt,
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if state.finally_depth > 0 {
        issues.push(issue_at(
            "python:S1143",
            match stmt {
                Stmt::Break(_) => "Remove this \"break\" statement from this \"finally\" block.",
                Stmt::Continue(_) => {
                    "Remove this \"continue\" statement from this \"finally\" block."
                }
                _ => unreachable!("guarded jump statement"),
            },
            stmt.range(),
            index,
            source,
        ));
        return;
    }
    if state.loop_depth == 0 {
        issues.push(issue_at(
            "python:S1716",
            match stmt {
                Stmt::Break(_) => "Remove this \"break\" statement",
                Stmt::Continue(_) => "Remove this \"continue\" statement",
                _ => unreachable!("guarded jump statement"),
            },
            stmt.range(),
            index,
            source,
        ));
    }
}

fn flag_flow_raise(
    raised: &ruff_python_ast::StmtRaise,
    state: FlowState,
    current_fn: Option<&str>,
    exempt_fns: &ExceptCalledFns,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if raised.exc.is_some() || raised.cause.is_some() || state.context == RaiseContext::InExcept {
        return;
    }
    // Sonar exempts functions called inside an except/finally body — their
    // bare raise re-raises the handled exception.
    if current_fn.is_some_and(|name| exempt_fns.contains(name)) {
        return;
    }
    let (key, message) = if state.context == RaiseContext::InFinally {
        (
            "python:S5704",
            "Refactor this code so that any active exception raises naturally.",
        )
    } else {
        (
            "python:S5747",
            "Remove this \"raise\" statement or move it inside an \"except\" block.",
        )
    };
    issues.push(issue_at(key, message, raised.range(), index, source));
}

fn scan_flow_nested_bodies(
    stmt: &Stmt,
    state: FlowState,
    current_fn: Option<&str>,
    exempt_fns: &ExceptCalledFns,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    match stmt {
        Stmt::For(loop_stmt) => {
            scan_flow_statements_in(
                &loop_stmt.body,
                state.with_loop(),
                current_fn,
                exempt_fns,
                issues,
                index,
                source,
            );
            scan_flow_statements_in(
                &loop_stmt.orelse,
                state,
                current_fn,
                exempt_fns,
                issues,
                index,
                source,
            );
        }
        Stmt::While(loop_stmt) => {
            scan_flow_statements_in(
                &loop_stmt.body,
                state.with_loop(),
                current_fn,
                exempt_fns,
                issues,
                index,
                source,
            );
            scan_flow_statements_in(
                &loop_stmt.orelse,
                state,
                current_fn,
                exempt_fns,
                issues,
                index,
                source,
            );
        }
        Stmt::Try(try_stmt) => {
            scan_try_flow(
                try_stmt, state, current_fn, exempt_fns, issues, index, source,
            );
        }
        Stmt::With(with_stmt) => {
            scan_flow_statements_in(
                &with_stmt.body,
                state,
                current_fn,
                exempt_fns,
                issues,
                index,
                source,
            );
        }
        Stmt::If(if_stmt) => {
            scan_flow_statements_in(
                &if_stmt.body,
                state,
                current_fn,
                exempt_fns,
                issues,
                index,
                source,
            );
            for clause in &if_stmt.elif_else_clauses {
                scan_flow_statements_in(
                    &clause.body,
                    state,
                    current_fn,
                    exempt_fns,
                    issues,
                    index,
                    source,
                );
            }
        }
        Stmt::Match(match_stmt) => {
            for case in &match_stmt.cases {
                scan_flow_statements_in(
                    &case.body, state, current_fn, exempt_fns, issues, index, source,
                );
            }
        }
        // Jumps bind within the innermost function scope; reset the state
        // and remember the function name for the except-called exemption.
        Stmt::FunctionDef(function) => {
            scan_flow_statements_in(
                &function.body,
                FlowState::fresh_scope(),
                Some(function.name.as_str()),
                exempt_fns,
                issues,
                index,
                source,
            );
        }
        _ => {}
    }
}

fn scan_try_flow(
    try_stmt: &ruff_python_ast::StmtTry,
    state: FlowState,
    current_fn: Option<&str>,
    exempt_fns: &ExceptCalledFns,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    scan_flow_statements_in(
        &try_stmt.body,
        state,
        current_fn,
        exempt_fns,
        issues,
        index,
        source,
    );
    for handler in &try_stmt.handlers {
        let ExceptHandler::ExceptHandler(inner) = handler;
        scan_flow_statements_in(
            &inner.body,
            FlowState {
                context: RaiseContext::InExcept,
                ..state
            },
            current_fn,
            exempt_fns,
            issues,
            index,
            source,
        );
    }
    scan_flow_statements_in(
        &try_stmt.orelse,
        state,
        current_fn,
        exempt_fns,
        issues,
        index,
        source,
    );
    scan_flow_statements_in(
        &try_stmt.finalbody,
        state.in_finally(),
        current_fn,
        exempt_fns,
        issues,
        index,
        source,
    );
}

pub(crate) fn stmts_load_any_name(stmts: &[Stmt], names: &[String]) -> bool {
    let mut found = false;
    for_each_stmt_expr(stmts, &mut |expr| {
        found |= loads_any_name(expr, names);
    });
    found
}

pub(crate) fn visit_scopes_for_yields(
    suite: &[Stmt],
    function_depth: u32,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in suite {
        match stmt {
            Stmt::FunctionDef(function) => {
                visit_scopes_for_yields(&function.body, function_depth + 1, issues, index, source);
            }
            Stmt::ClassDef(class) => {
                visit_scopes_for_yields(&class.body, function_depth, issues, index, source);
            }
            _ => {
                if function_depth == 0 {
                    flag_top_level_return_and_yield(stmt, issues, index, source);
                }
                for body in child_bodies(stmt) {
                    visit_scopes_for_yields(body, function_depth, issues, index, source);
                }
            }
        }
    }
}

/// python:S2711 — a bare `return` or `yield` outside of any function body.
fn flag_top_level_return_and_yield(
    stmt: &Stmt,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if matches!(stmt, Stmt::Return(_)) {
        issues.push(issue_at(
            "python:S2711",
            "Remove this use of \"return\".",
            stmt.range(),
            index,
            source,
        ));
    }
    for expr in stmt_exprs(stmt) {
        for_each_expr(expr, &mut |node| match node {
            Expr::Yield(_) | Expr::YieldFrom(_) => {
                issues.push(issue_at(
                    "python:S2711",
                    "Remove this use of \"yield\".",
                    node.range(),
                    index,
                    source,
                ));
            }
            _ => {}
        });
    }
}
