// --- python:S5709 — custom exceptions inherit Exception

use crate::context::FlowState;
use crate::engine::scope::RaiseContext;
use crate::support::{
    child_bodies, for_each_expr, for_each_stmt_expr, issue_at, loads_any_name, stmt_exprs,
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

pub(crate) fn scan_flow_statements(
    suite: &[Stmt],
    state: FlowState,
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
            Stmt::Raise(raised) => flag_flow_raise(raised, state, issues, index, source),
            _ => scan_flow_nested_bodies(stmt, state, issues, index, source),
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
    } else if state.loop_depth == 0 {
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
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if raised.exc.is_some() || raised.cause.is_some() || state.context == RaiseContext::InExcept {
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
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    match stmt {
        Stmt::For(loop_stmt) => {
            scan_flow_statements(&loop_stmt.body, state.with_loop(), issues, index, source);
            scan_flow_statements(&loop_stmt.orelse, state, issues, index, source);
        }
        Stmt::While(loop_stmt) => {
            scan_flow_statements(&loop_stmt.body, state.with_loop(), issues, index, source);
            scan_flow_statements(&loop_stmt.orelse, state, issues, index, source);
        }
        Stmt::Try(try_stmt) => {
            scan_flow_statements(&try_stmt.body, state, issues, index, source);
            for handler in &try_stmt.handlers {
                let ExceptHandler::ExceptHandler(inner) = handler;
                scan_flow_statements(
                    &inner.body,
                    FlowState {
                        context: RaiseContext::InExcept,
                        ..state
                    },
                    issues,
                    index,
                    source,
                );
            }
            scan_flow_statements(&try_stmt.orelse, state, issues, index, source);
            scan_flow_statements(
                &try_stmt.finalbody,
                state.in_finally(),
                issues,
                index,
                source,
            );
        }
        Stmt::With(with_stmt) => {
            scan_flow_statements(&with_stmt.body, state, issues, index, source);
        }
        Stmt::If(if_stmt) => {
            scan_flow_statements(&if_stmt.body, state, issues, index, source);
            for clause in &if_stmt.elif_else_clauses {
                scan_flow_statements(&clause.body, state, issues, index, source);
            }
        }
        Stmt::Match(match_stmt) => {
            for case in &match_stmt.cases {
                scan_flow_statements(&case.body, state, issues, index, source);
            }
        }
        // Jumps bind within the innermost function scope; reset the state.
        Stmt::FunctionDef(function) => {
            scan_flow_statements(
                &function.body,
                FlowState::fresh_scope(),
                issues,
                index,
                source,
            );
        }
        _ => {}
    }
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
