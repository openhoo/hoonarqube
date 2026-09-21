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
use crate::engine::bindings::KnownBindings;
use crate::engine::scope::{FileFacts, SymbolTable};

use crate::support::child_bodies_into;
use crate::support::child_exprs_into;
use crate::support::push_stmt_exprs;
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
use ruff_text_size::{Ranged, TextRange};
use std::cell::OnceCell;

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
    /// The parsed module and raw source, retained so lazily built shared
    /// facts can reuse the same inputs the inventories were collected from.
    pub(crate) parsed: &'a Parsed<ModModule>,
    pub(crate) source: &'a str,
    /// The module's direct statement suite. Rules that need control-flow
    /// provenance must retain the original hierarchy rather than reconstructing
    /// it from the flattened inventories below.
    pub(crate) module_body: &'a [Stmt],
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
    /// Lexical identities for standard-library APIs whose rule semantics
    /// depend on binding provenance rather than a method's final spelling.
    pub(crate) known_bindings: KnownBindings,
    /// Flask/FastAPI provenance for the web-framework rule family
    /// (application instances, the `flask.request` proxy, view/response
    /// classes, file-like objects).
    pub(crate) web_bindings: crate::support::WebBindings,
    /// Lazily built Tier-B symbol table, shared by the battery, the
    /// unseeded-randomness rule, and quick-fix planners that used to rebuild
    /// it per call (and per issue).
    symbol_table: OnceCell<SymbolTable>,
    /// Lazily built cross-file lexical facts, shared for the same reason.
    file_facts: OnceCell<FileFacts>,
    /// `name = expr` target-range → value map shared by the `NameResolver`
    /// users (previously one AST walk per rule). Built eagerly in
    /// [`FileContext::build`] so the context stays covariant over `'a`.
    assigned_values: std::collections::HashMap<TextRange, &'a Expr>,
    /// Lazily built load-range → (scope, name) map shared by `NameResolver`.
    load_map: OnceCell<std::collections::HashMap<TextRange, (usize, String)>>,
}
impl<'a> FileContext<'a> {
    /// Builds every inventory in one combined pass over the module.
    pub(crate) fn build(parsed: &'a Parsed<ModModule>, source: &'a str) -> Self {
        let mut ctx = FileContext {
            parsed,
            source,
            module_body: parsed.syntax().body.as_slice(),
            stmts: Vec::new(),
            exprs: Vec::new(),
            calls: Vec::new(),
            strings: Vec::new(),
            functions: Vec::new(),
            classes: Vec::new(),
            imports: Vec::new(),
            has_aws_cdk_import: false,
            known_bindings: KnownBindings::build(parsed),
            web_bindings: crate::support::WebBindings::build(parsed),
            symbol_table: OnceCell::new(),
            file_facts: OnceCell::new(),
            assigned_values: std::collections::HashMap::new(),
            load_map: OnceCell::new(),
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

    /// The shared Tier-B symbol table, built on first use.
    pub(crate) fn symbol_table(&self) -> &SymbolTable {
        self.symbol_table
            .get_or_init(|| crate::engine::scope::build_symbol_table(self.parsed))
    }

    /// The shared cross-file lexical facts, built on first use from the same
    /// inventories the rules consume.
    pub(crate) fn file_facts(&self) -> &FileFacts {
        self.file_facts
            .get_or_init(|| crate::engine::scope::collect_file_facts(self, self.source))
    }

    /// Maps each single-`Name` assignment target range to its value
    /// expression. Chained targets (`x = y = v`) each record the same value;
    /// tuple targets, annotated targets without a value, and non-`Name`
    /// targets record nothing. Built once from the statement inventory.
    pub(crate) fn assigned_values(&self) -> &std::collections::HashMap<TextRange, &'a Expr> {
        &self.assigned_values
    }

    /// Maps every resolved load's source range to its target scope and name.
    pub(crate) fn load_map(&self) -> &std::collections::HashMap<TextRange, (usize, String)> {
        self.load_map.get_or_init(|| {
            let mut loads = std::collections::HashMap::new();
            for load in &self.symbol_table().resolved_loads {
                if let Some(target) = load.target {
                    loads.insert(load.range, (target, load.name.clone()));
                }
            }
            loads
        })
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
/// cannot overflow the thread stack. Scratch buffers replace the per-node
/// `Vec` allocations the `child_*`/`stmt_exprs` accessors would create.
fn collect_all<'a>(body: &'a [Stmt], ctx: &mut FileContext<'a>) {
    let mut work: Vec<Work<'a>> = body.iter().rev().map(Work::Stmt).collect();
    let mut bodies = Vec::new();
    let mut top_exprs = Vec::new();
    let mut children = Vec::new();
    while let Some(item) = work.pop() {
        match item {
            Work::Stmt(stmt) => {
                ctx.stmts.push(stmt);
                match stmt {
                    Stmt::FunctionDef(function) => ctx.functions.push(function),
                    Stmt::ClassDef(class) => ctx.classes.push(class),
                    Stmt::Import(import) => ctx.imports.push(AnyImport::Plain(import)),
                    Stmt::ImportFrom(import_from) => ctx.imports.push(AnyImport::From(import_from)),
                    Stmt::Assign(assign) => {
                        for target in &assign.targets {
                            if let Expr::Name(name) = target {
                                ctx.assigned_values
                                    .insert(name.range(), assign.value.as_ref());
                            }
                        }
                    }
                    Stmt::AnnAssign(assign) => {
                        if let (Expr::Name(name), Some(value)) =
                            (assign.target.as_ref(), assign.value.as_deref())
                        {
                            ctx.assigned_values.insert(name.range(), value);
                        }
                    }
                    _ => {}
                }
                // Bodies go onto the stack first so the statement's own
                // expressions pop — and fully drain — ahead of them.
                child_bodies_into(stmt, &mut bodies);
                for body_slice in bodies.drain(..).rev() {
                    work.extend(body_slice.iter().rev().map(Work::Stmt));
                }
                push_stmt_exprs(stmt, &mut top_exprs);
                work.extend(top_exprs.drain(..).rev().map(Work::Expr));
            }
            Work::Expr(expr) => {
                ctx.exprs.push(expr);
                match expr {
                    Expr::Call(call) => ctx.calls.push(call),
                    Expr::StringLiteral(string) => ctx.strings.push(string),
                    _ => {}
                }
                child_exprs_into(expr, &mut children);
                work.extend(children.drain(..).rev().map(Work::Expr));
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
        let ctx = FileContext::build(&parsed, "");
        assert_eq!(ctx.stmts.len(), 1);
        assert_eq!(ctx.exprs.len(), depth + 2); // unaries + literal + target
        // The traversal above stays on the heap, but end-of-test drop glue
        // would still recurse once per nesting level and overflow the small
        // test-thread stack, so the deep chain is deliberately leaked.
        std::mem::forget(parsed);
    }

    /// Differential inventory control for the shared traversal: the identical
    /// call is collected exactly once from every executable position — direct
    /// statement, assert message, except selector, f-string interpolation, and
    /// nested format spec — while the literal text of the same call in plain
    /// string segments stays out of the inventory.
    #[test]
    fn collect_all_counts_identical_call_in_each_executable_position() {
        let source = concat!(
            "eval(v)\n",
            "assert c, eval(v)\n",
            "try:\n",
            "    pass\n",
            "except eval(v):\n",
            "    pass\n",
            "first = f\"{eval(v)}\"\n",
            "second = f\"{first:{eval(v)}}\"\n",
            "third = \"eval(v)\" f\"plain segment\"\n",
        );
        let parsed = parse(source);
        let ctx = FileContext::build(&parsed, "");
        assert_eq!(ctx.calls.len(), 5);
    }
}
