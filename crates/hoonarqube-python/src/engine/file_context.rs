//! Single-pass, per-file pre-computed context shared by all rules.
//!
//! Every rule used to re-walk the whole AST for the data it needed. The
//! [`FileContext`] materializes those shared views exactly once per analyzed
//! file. Each bucket reproduces the element sequence of the canonical walker
//! helper it replaces (`for_each_stmt`, `for_each_stmt_expr`, `for_each_call`)
//! because the collection pass recurses over the very same
//! [`child_bodies`]/[`child_exprs`] primitives — iteration order, and
//! therefore issue emission order before the final sort, is identical by
//! construction.

use crate::support::child_bodies;
use crate::support::child_exprs;
use crate::support::stmt_exprs;
use ruff_python_ast::Expr;
use ruff_python_ast::ExprCall;
use ruff_python_ast::ExprStringLiteral;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtClassDef;
use ruff_python_ast::StmtFunctionDef;
use ruff_python_ast::StmtImport;
use ruff_python_ast::StmtImportFrom;
use ruff_python_parser::Parsed;

/// An import statement of either flavor, kept in source order so rules can
/// reproduce a combined `Stmt::Import | Stmt::ImportFrom` walk.
#[derive(Clone, Copy)]
pub(crate) enum AnyImport<'a> {
    /// Precomputed per the shared-context contract; current rule set only
    /// matches from-imports, but the table must stay complete.
    #[allow(dead_code)]
    Plain(&'a StmtImport),
    From(&'a StmtImportFrom),
}

/// Shared per-file inventories, computed once instead of once per rule.
pub(crate) struct FileContext<'a> {
    /// Every statement in pre-order — the exact `for_each_stmt` sequence.
    pub(crate) stmts: Vec<&'a Stmt>,
    /// Every expression in pre-order — the exact `for_each_stmt_expr` sequence.
    pub(crate) exprs: Vec<&'a Expr>,
    /// Every call expression in `for_each_call` order.
    pub(crate) calls: Vec<&'a ExprCall>,
    /// Every string literal expression in expression pre-order.
    pub(crate) strings: Vec<&'a ExprStringLiteral>,
    /// Every function definition in statement pre-order.
    pub(crate) functions: Vec<&'a StmtFunctionDef>,
    /// Every class definition in statement pre-order.
    pub(crate) classes: Vec<&'a StmtClassDef>,
    /// Every import (plain and from-imports) in statement pre-order.
    pub(crate) imports: Vec<AnyImport<'a>>,
}

impl<'a> FileContext<'a> {
    /// Builds every inventory in one combined pass over the module.
    pub(crate) fn build(parsed: &'a Parsed<ModModule>) -> Self {
        let mut ctx = FileContext {
            stmts: Vec::new(),
            exprs: Vec::new(),
            calls: Vec::new(),
            strings: Vec::new(),
            functions: Vec::new(),
            classes: Vec::new(),
            imports: Vec::new(),
        };
        collect_stmts(parsed.syntax().body.as_slice(), &mut ctx);
        ctx
    }
}

/// Depth-first statement collection; mirrors `for_each_stmt`
/// (`visit`, then each body in `child_bodies` order).
fn collect_stmts<'a>(stmts: &'a [Stmt], ctx: &mut FileContext<'a>) {
    for stmt in stmts {
        ctx.stmts.push(stmt);
        match stmt {
            Stmt::FunctionDef(function) => ctx.functions.push(function),
            Stmt::ClassDef(class) => ctx.classes.push(class),
            Stmt::Import(import) => ctx.imports.push(AnyImport::Plain(import)),
            Stmt::ImportFrom(import_from) => ctx.imports.push(AnyImport::From(import_from)),
            _ => {}
        }
        for expr in stmt_exprs(stmt) {
            collect_exprs(expr, ctx);
        }
        for body in child_bodies(stmt) {
            collect_stmts(body, ctx);
        }
    }
}

/// Pre-order expression collection; mirrors `for_each_expr`
/// (`visit`, then each child in `child_exprs` order).
fn collect_exprs<'a>(expr: &'a Expr, ctx: &mut FileContext<'a>) {
    ctx.exprs.push(expr);
    match expr {
        Expr::Call(call) => ctx.calls.push(call),
        Expr::StringLiteral(string) => ctx.strings.push(string),
        _ => {}
    }
    for child in child_exprs(expr) {
        collect_exprs(child, ctx);
    }
}
