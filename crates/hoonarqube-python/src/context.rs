use crate::engine::scope::RaiseContext;
use crate::support::child_bodies;
use crate::support::for_each_expr;
use crate::support::stmt_exprs;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;

/// Lexical raise/jump binding state carried by the flow walk.
#[derive(Clone, Copy)]
pub(crate) struct FlowState {
    pub(crate) context: RaiseContext,
    pub(crate) finally_depth: u32,
    pub(crate) loop_depth: u32,
}

impl FlowState {
    pub(crate) fn with_loop(self) -> Self {
        Self {
            loop_depth: self.loop_depth + 1,
            ..self
        }
    }

    pub(crate) fn in_finally(self) -> Self {
        Self {
            context: RaiseContext::InFinally,
            finally_depth: self.finally_depth + 1,
            ..self
        }
    }

    pub(crate) fn fresh_scope() -> Self {
        Self {
            context: RaiseContext::Outside,
            finally_depth: 0,
            loop_depth: 0,
        }
    }
}

/// Lexical context carried by the function-aware walker below.
#[derive(Clone, Copy)]
pub(crate) struct FnContext<'a> {
    pub(crate) nearest_function: Option<&'a ruff_python_ast::StmtFunctionDef>,
    pub(crate) loop_depth: u32,
}

/// Depth-first statement walk that tracks the nearest enclosing function and
/// loop depth. Nested functions reset both; loop bodies increment depth.
pub(crate) fn for_each_stmt_in_fn_context(
    suite: &[Stmt],
    ctx: FnContext,
    visit: &mut impl FnMut(&Stmt, FnContext),
) {
    for stmt in suite {
        visit(stmt, ctx);
        match stmt {
            Stmt::FunctionDef(function) => {
                for_each_stmt_in_fn_context(
                    function.body.as_slice(),
                    FnContext {
                        nearest_function: Some(function),
                        loop_depth: 0,
                    },
                    visit,
                );
            }
            Stmt::For(loop_stmt) => {
                for_each_stmt_in_fn_context(
                    loop_stmt.body.as_slice(),
                    FnContext {
                        loop_depth: ctx.loop_depth + 1,
                        ..ctx
                    },
                    visit,
                );
                for_each_stmt_in_fn_context(loop_stmt.orelse.as_slice(), ctx, visit);
            }
            Stmt::While(loop_stmt) => {
                for_each_stmt_in_fn_context(
                    loop_stmt.body.as_slice(),
                    FnContext {
                        loop_depth: ctx.loop_depth + 1,
                        ..ctx
                    },
                    visit,
                );
                for_each_stmt_in_fn_context(loop_stmt.orelse.as_slice(), ctx, visit);
            }
            _ => {
                for body in child_bodies(stmt) {
                    for_each_stmt_in_fn_context(body, ctx, visit);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Async-family contracts (#155–#167, #193).
// ---------------------------------------------------------------------------

/// `(call, context)` pairs for every call in the tree, carrying the nearest
/// enclosing function and loop depth.
pub(crate) fn for_each_call_in_fn_context(
    module_body: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::ExprCall, FnContext),
) {
    for_each_stmt_in_fn_context(
        module_body,
        FnContext {
            nearest_function: None,
            loop_depth: 0,
        },
        &mut |stmt, ctx| {
            for expr in stmt_exprs(stmt) {
                for_each_expr(expr, &mut |expr| {
                    if let Expr::Call(call) = expr {
                        visit(call, ctx);
                    }
                });
            }
        },
    );
}

pub(crate) fn context_is_async(ctx: FnContext) -> bool {
    ctx.nearest_function
        .is_some_and(|function| function.is_async)
}
