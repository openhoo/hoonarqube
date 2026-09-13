// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use super::collectors::RootedMemberScanner;
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::rules::shared::is_equality_operator;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use crate::support::identifier_name;
use crate::support::unparenthesized;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::LogicalExpression;
use oxc_ast::ast::LogicalOperator;
use oxc_ast::ast::UnaryOperator;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

/// Root identifier guarded by one side of an `&&` (`S6582`). Resolves the
/// direct nullish-equality form (`x !== null && x.member`), the plain
/// truthy guard (`x && x.member`), and multi-clause guards whose left side
/// is an `&&` chain (`x !== null && x !== undefined && x.member`).
fn null_guard_target<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    let peeled = unparenthesized(expression);
    if let Expression::Identifier(identifier) = peeled {
        return Some(&identifier.name);
    }
    if let Expression::BinaryExpression(binary) = peeled {
        return nullish_equality_root(binary);
    }
    if let Expression::LogicalExpression(logical) = peeled
        && logical.operator == LogicalOperator::And
    {
        return and_chain_root(peeled);
    }
    None
}

/// Identifier compared against `null`/`undefined` by an equality test.
fn nullish_equality_root<'a>(binary: &'a BinaryExpression<'a>) -> Option<&'a str> {
    if !is_equality_operator(binary.operator) {
        return None;
    }
    let is_nullish = |expression: &Expression<'_>| {
        matches!(expression, Expression::NullLiteral(_))
            || identifier_name(expression) == Some("undefined")
    };
    match (&binary.left, &binary.right) {
        (Expression::Identifier(identifier), other)
        | (other, Expression::Identifier(identifier))
            if is_nullish(other) =>
        {
            Some(&identifier.name)
        }
        _ => None,
    }
}

/// Flattens a (possibly single-operand) `&&` chain into its operands.
fn collect_and_operands<'a>(
    expression: &'a Expression<'a>,
    operands: &mut Vec<&'a Expression<'a>>,
) {
    if let Expression::LogicalExpression(logical) = unparenthesized(expression)
        && logical.operator == LogicalOperator::And
    {
        collect_and_operands(&logical.left, operands);
        collect_and_operands(&logical.right, operands);
        return;
    }
    operands.push(unparenthesized(expression));
}

/// Root of a multi-clause guard: the last nullish-equality operand wins;
/// without any, the leftmost plain identifier acts as a truthy guard.
fn and_chain_root<'a>(chain: &'a Expression<'a>) -> Option<&'a str> {
    let mut operands = Vec::new();
    collect_and_operands(chain, &mut operands);
    let mut root = None;
    for &operand in &operands {
        if let Expression::BinaryExpression(binary) = operand
            && let Some(name) = nullish_equality_root(binary)
        {
            root = Some(name);
        }
    }
    if root.is_some() {
        return root;
    }
    match operands.first() {
        Some(Expression::Identifier(identifier)) => Some(&identifier.name),
        _ => None,
    }
}

/// De Morgan dual of the `&&` guard family: every operand of the `||`
/// chain is a single negation over either the guarded identifier or a
/// member chain rooted at it (`!fn || !fn.handle || !fn.set`). The root
/// must agree across the chain, and at least one operand must guard a
/// member access.
fn negated_or_guard_root<'a>(logical: &'a LogicalExpression<'a>) -> Option<&'a str> {
    let mut operands = Vec::new();
    collect_or_operands(logical, &mut operands);
    let mut root: Option<&str> = None;
    let mut member_guard = false;
    for &operand in &operands {
        let Expression::UnaryExpression(unary) = operand else {
            return None;
        };
        if unary.operator != UnaryOperator::LogicalNot {
            return None;
        }
        let argument = unparenthesized(&unary.argument);
        let name = expression_root_name(argument)?;
        if root.is_some_and(|known| known != name) {
            return None;
        }
        root = Some(name);
        member_guard |= !matches!(argument, Expression::Identifier(_));
    }
    if member_guard { root } else { None }
}

/// Flattens a (possibly single-operand) `||` chain into its operands.
fn collect_or_operands<'a>(
    logical: &'a LogicalExpression<'a>,
    operands: &mut Vec<&'a Expression<'a>>,
) {
    for side in [&logical.left, &logical.right] {
        if let Expression::LogicalExpression(nested) = unparenthesized(side)
            && nested.operator == LogicalOperator::Or
        {
            collect_or_operands(nested, operands);
        } else {
            operands.push(unparenthesized(side));
        }
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl EsIdiomCollector<'_> {
    /// `S6582` logic extracted from `visit_logical_expression`. Each chain
    /// reports once, at its outermost span.
    pub(crate) fn check_s6582_logical_expression(&mut self, it: &LogicalExpression<'_>) {
        if self
            .s6582_spans
            .iter()
            .any(|span| span.contains_inclusive(it.span()))
        {
            return;
        }
        let root = match it.operator {
            LogicalOperator::And => null_guard_target(&it.left).and_then(|root| {
                let mut scanner = RootedMemberScanner { root, found: false };
                scanner.visit_expression(&it.right);
                scanner.found.then_some(root)
            }),
            LogicalOperator::Or => negated_or_guard_root(it),
            LogicalOperator::Coalesce => None,
        };
        if root.is_some() {
            self.sink.emit_span(
                RuleScope::Both,
                "S6582",
                "Use optional chaining (\"?.\") instead of this null check.",
                it.span(),
            );
            self.s6582_spans.push(it.span());
        }
    }
}
