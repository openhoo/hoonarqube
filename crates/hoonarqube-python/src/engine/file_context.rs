//! Single-pass, per-file pre-computed context shared by all rules.
//!
//! Every rule used to re-walk the whole AST for the data it needed. The
//! [`FileContext`] materializes those shared views exactly once per analyzed
//! file. Each bucket reproduces the element sequence of the canonical walker
//! helper it replaces (`for_each_stmt`, `for_each_stmt_expr`, `for_each_call`)
//! because the collection pass traverses the very same
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
    /// Whether the file imports AWS CDK. Computed once so cloud rules can
    /// require the same library provenance as `SonarPython`.
    pub(crate) has_aws_cdk_import: bool,
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
            has_aws_cdk_import: false,
        };
        collect_all(parsed.syntax().body.as_slice(), &mut ctx);
        ctx.has_aws_cdk_import = ctx.imports.iter().any(|entry| match entry {
            AnyImport::Plain(import) => import
                .names
                .iter()
                .any(|alias| alias.name.as_str().starts_with("aws_cdk")),
            AnyImport::From(import) => import
                .module
                .as_ref()
                .is_some_and(|module| module.as_str().starts_with("aws_cdk")),
        });
        ctx
    }
}

/// Pending work items for the explicit-stack collection walk.
enum Work<'a> {
    Stmt(&'a Stmt),
    Expr(&'a Expr),
}
/// Collects every inventory in one explicit-stack pre-order pass; mirrors the
/// recursive walker sequence (`visit`, then `stmt_exprs`, then each
/// `child_bodies` slice in order, every subtree drained before the next item)
/// while keeping traversal state on the heap so pathological AST nesting
/// cannot overflow the thread stack.
fn collect_all<'a>(body: &'a [Stmt], ctx: &mut FileContext<'a>) {
    let mut work: Vec<Work<'a>> = body.iter().rev().map(Work::Stmt).collect();
    while let Some(item) = work.pop() {
        match item {
            Work::Stmt(stmt) => {
                ctx.stmts.push(stmt);
                match stmt {
                    Stmt::FunctionDef(function) => ctx.functions.push(function),
                    Stmt::ClassDef(class) => ctx.classes.push(class),
                    Stmt::Import(import) => ctx.imports.push(AnyImport::Plain(import)),
                    Stmt::ImportFrom(import_from) => ctx.imports.push(AnyImport::From(import_from)),
                    _ => {}
                }
                // Bodies go onto the stack first so the statement's own
                // expressions pop — and fully drain — ahead of them.
                for body_slice in child_bodies(stmt).into_iter().rev() {
                    work.extend(body_slice.iter().rev().map(Work::Stmt));
                }
                for expr in stmt_exprs(stmt).into_iter().rev() {
                    work.push(Work::Expr(expr));
                }
            }
            Work::Expr(expr) => {
                ctx.exprs.push(expr);
                match expr {
                    Expr::Call(call) => ctx.calls.push(call),
                    Expr::StringLiteral(string) => ctx.strings.push(string),
                    _ => {}
                }
                work.extend(child_exprs(expr).into_iter().rev().map(Work::Expr));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::parse;

    /// Regression: collection survives arbitrarily deep expression nesting
    /// via the heap-grown explicit stack where the former per-frame recursion
    /// overflowed the thread stack, still yielding full pre-order inventories.
    /// Nesting uses chained unary negations because ruff's AST keeps no node
    /// for grouping parentheses (`((((1))))` parses as a bare literal).
    #[test]
    fn deep_expression_nesting_collects_iteratively() {
        let depth = 50_000_usize;
        let source = format!("value = {}1", "-".repeat(depth));
        let parsed = parse(&source);
        let ctx = FileContext::build(&parsed);
        assert_eq!(ctx.stmts.len(), 1);
        assert_eq!(ctx.exprs.len(), depth + 2); // unaries + literal + target
        // The traversal above stays on the heap, but end-of-test drop glue
        // would still recurse once per nesting level and overflow the small
        // test-thread stack, so the deep chain is deliberately leaked.
        std::mem::forget(parsed);
    }
}
