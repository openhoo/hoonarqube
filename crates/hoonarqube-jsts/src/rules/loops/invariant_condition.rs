//! Variable-based S2189 for JavaScript loop conditions.
use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        ArrowFunctionExpression, BreakStatement, CallExpression, DoWhileStatement, Expression,
        ForInStatement, ForOfStatement, ForStatement, Function, IdentifierReference,
        ReturnStatement, Statement, StaticBlock, ThrowStatement, VariableDeclarator,
        WhileStatement, YieldExpression,
    },
};
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;

use crate::support::{IssueSink, RuleScope, unparenthesized};

#[derive(Clone, Copy)]
pub(super) struct Condition<'a, 'node> {
    pub test: &'node Expression<'a>,
    pub body: &'node Statement<'a>,
    pub init: Option<Span>,
    pub update: Option<&'node Expression<'a>>,
    pub span: Span,
}

pub(super) fn check<'a>(
    condition: Condition<'a, '_>,
    semantic: &Semantic<'a>,
    reported: &mut HashSet<SymbolId>,
    sink: &mut IssueSink<'_>,
) {
    let mut groups = Vec::new();
    test_groups(condition.test, &mut groups);
    if groups.is_empty() {
        return;
    }
    let mut effects = LoopEffects {
        semantic,
        exits: false,
        nested_loops: 0,
        arrow_depth: 0,
        calls: false,
        calls_eval: false,
        callees: Vec::new(),
    };
    effects.visit_statement(condition.body);
    if effects.exits {
        return;
    }
    effects.visit_expression(condition.test);
    if let Some(update) = condition.update {
        effects.visit_expression(update);
    }
    if effects.exits || effects.calls_eval {
        return;
    }

    for group in groups {
        let Some(bindings) = group
            .into_iter()
            .map(|id| Some((id, binding(semantic, id)?)))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        // Any changing operand can end a comparison. Logical branches are
        // considered separately, so a mutable queue does not hide a comparison.
        if bindings.iter().any(|&(_, symbol)| {
            written_in_loop(semantic, symbol, &condition) || effects.called_writer(symbol)
        }) {
            continue;
        }
        for (id, symbol) in bindings {
            if !effects.mutable_file_binding(symbol, condition.init) && reported.insert(symbol) {
                sink.emit_span(
                    RuleScope::JsOnly,
                    "S2189",
                    &format!("'{}' is not modified in this loop.", id.name),
                    id.span(),
                );
            }
        }
    }
}

/// Collect direct bindings and groups that share a comparison/conditional.
/// Accessors and calls can yield a different value at each evaluation.
fn test_groups<'a, 'node>(
    expression: &'node Expression<'a>,
    groups: &mut Vec<Vec<&'node IdentifierReference<'a>>>,
) {
    match unparenthesized(expression) {
        Expression::LogicalExpression(logical) => {
            test_groups(&logical.left, groups);
            test_groups(&logical.right, groups);
        }
        Expression::UnaryExpression(unary) => test_groups(&unary.argument, groups),
        expression => {
            let mut group = Vec::new();
            if pure_operands(expression, &mut group) && !group.is_empty() {
                groups.push(group);
            }
        }
    }
}

fn pure_operands<'a, 'node>(
    expression: &'node Expression<'a>,
    group: &mut Vec<&'node IdentifierReference<'a>>,
) -> bool {
    match unparenthesized(expression) {
        Expression::Identifier(id) => {
            group.push(id);
            true
        }
        Expression::BinaryExpression(binary) => {
            pure_operands(&binary.left, group) && pure_operands(&binary.right, group)
        }
        Expression::LogicalExpression(logical) => {
            pure_operands(&logical.left, group) && pure_operands(&logical.right, group)
        }
        Expression::ConditionalExpression(conditional) => {
            pure_operands(&conditional.test, group)
                && pure_operands(&conditional.consequent, group)
                && pure_operands(&conditional.alternate, group)
        }
        Expression::UnaryExpression(unary) => pure_operands(&unary.argument, group),
        expression => expression.is_literal(),
    }
}

fn binding(semantic: &Semantic<'_>, id: &IdentifierReference<'_>) -> Option<SymbolId> {
    semantic
        .scoping()
        .get_reference(id.reference_id.get()?)
        .symbol_id()
}

fn written_in_loop(
    semantic: &Semantic<'_>,
    symbol: SymbolId,
    condition: &Condition<'_, '_>,
) -> bool {
    let scoping = semantic.scoping();
    let iterates_at = |span: Span| {
        condition.span.contains_inclusive(span)
            && !condition
                .init
                .is_some_and(|init| init.contains_inclusive(span))
    };
    scoping
        .get_resolved_references(symbol)
        .any(|reference| reference.is_write() && iterates_at(semantic.reference_span(reference)))
        || scoping.symbol_declarations(symbol).any(|decl| {
            let node = semantic.nodes().get_node(decl);
            matches!(node.kind(), AstKind::VariableDeclarator(variable) if variable.init.is_some())
                && iterates_at(node.span())
        })
}

struct LoopEffects<'a, 'semantic> {
    semantic: &'semantic Semantic<'a>,
    exits: bool,
    nested_loops: u32,
    arrow_depth: u32,
    calls: bool,
    calls_eval: bool,
    callees: Vec<Span>,
}

impl LoopEffects<'_, '_> {
    fn mutable_file_binding(&self, symbol: SymbolId, init: Option<Span>) -> bool {
        let scoping = self.semantic.scoping();
        let declared_in_initializer =
            init.is_some_and(|init| init.contains_inclusive(scoping.symbol_span(symbol)));
        if scoping.symbol_scope_id(symbol) == scoping.root_scope_id() && !declared_in_initializer {
            // File-scope state can be changed by calls outside the local loop.
            if self.calls {
                return true;
            }
            return scoping.get_resolved_references(symbol).any(|reference| {
                reference.is_write()
                    && self
                        .semantic
                        .nodes()
                        .ancestors(reference.node_id())
                        .any(|node| {
                            matches!(
                                node.kind(),
                                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                            )
                        })
            });
        }
        false
    }

    fn called_writer(&self, symbol: SymbolId) -> bool {
        let scoping = self.semantic.scoping();
        !self.callees.is_empty()
            && scoping.get_resolved_references(symbol).any(|reference| {
                reference.is_write()
                    && self.callees.iter().any(|callee| {
                        callee.contains_inclusive(self.semantic.reference_span(reference))
                    })
            })
    }

    fn resolve_callee(&self, id: &IdentifierReference<'_>) -> Option<Span> {
        let symbol = binding(self.semantic, id)?;
        match self.semantic.symbol_declaration(symbol).kind() {
            AstKind::Function(function) => Some(function.span()),
            AstKind::VariableDeclarator(VariableDeclarator {
                init: Some(init), ..
            }) => match unparenthesized(init) {
                Expression::FunctionExpression(function) => Some(function.span()),
                Expression::ArrowFunctionExpression(function) => Some(function.span()),
                _ => None,
            },
            _ => None,
        }
    }

    fn nested(&mut self, walk: impl FnOnce(&mut Self)) {
        self.nested_loops += 1;
        walk(self);
        self.nested_loops -= 1;
    }
}

impl<'a> Visit<'a> for LoopEffects<'a, '_> {
    fn visit_statement(&mut self, statement: &Statement<'a>) {
        if !self.exits {
            walk::walk_statement(self, statement);
        }
    }

    fn visit_break_statement(&mut self, statement: &BreakStatement) {
        // Retain the reference's conservative silence for switch breaks and
        // labels; an unlabeled break in a nested loop only exits that loop.
        self.exits |= self.nested_loops == 0 || statement.label.is_some();
    }

    fn visit_return_statement(&mut self, _: &ReturnStatement<'a>) {
        self.exits = true;
    }

    fn visit_throw_statement(&mut self, _: &ThrowStatement<'a>) {
        self.exits = true;
    }

    fn visit_yield_expression(&mut self, _: &YieldExpression<'a>) {
        self.exits = true;
    }

    fn visit_while_statement(&mut self, statement: &WhileStatement<'a>) {
        self.nested(|scan| walk::walk_while_statement(scan, statement));
    }

    fn visit_do_while_statement(&mut self, statement: &DoWhileStatement<'a>) {
        self.nested(|scan| walk::walk_do_while_statement(scan, statement));
    }

    fn visit_for_statement(&mut self, statement: &ForStatement<'a>) {
        self.nested(|scan| walk::walk_for_statement(scan, statement));
    }

    fn visit_for_in_statement(&mut self, statement: &ForInStatement<'a>) {
        self.nested(|scan| walk::walk_for_in_statement(scan, statement));
    }

    fn visit_for_of_statement(&mut self, statement: &ForOfStatement<'a>) {
        self.nested(|scan| walk::walk_for_of_statement(scan, statement));
    }

    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}

    fn visit_static_block(&mut self, _: &StaticBlock<'a>) {}

    fn visit_arrow_function_expression(&mut self, expression: &ArrowFunctionExpression<'a>) {
        // The reference treats returns in arrows as possible exits.
        self.arrow_depth += 1;
        walk::walk_arrow_function_expression(self, expression);
        self.arrow_depth -= 1;
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.arrow_depth == 0 {
            self.calls = true;
            if let Expression::Identifier(id) = unparenthesized(&call.callee) {
                self.calls_eval |= id.name == "eval";
                if let Some(callee) = self.resolve_callee(id) {
                    self.callees.push(callee);
                }
            }
        }
        walk::walk_call_expression(self, call);
    }
}
