// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::rules::shared::is_equality_operator;
use crate::support::RuleScope;
use crate::support::identifier_name;
use crate::support::unparenthesized;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_ast::ast::Expression;
use oxc_ast::ast::LogicalExpression;
use oxc_ast::ast::LogicalOperator;
use oxc_ast::ast::UnaryOperator;
use oxc_span::GetSpan;

/// One statically known link of a receiver chain (`S6582`).
#[derive(Debug, PartialEq, Eq)]
enum ChainSegment<'a> {
    /// Identifier root or static/private property name.
    Name(&'a str),
    /// The `this` receiver.
    This,
    /// Computed access; links compare by the key's source text.
    Computed(&'a str),
    /// A call made through the chain.
    Call,
}

/// What an `&&` operand contributes to the guard pair search. A plain
/// receiver chain (`this.a`, `x.y`) may guard later operands and extend
/// earlier guards alike. A nullish equality test (`x !== null`) resolves
/// to the tested chain and may only guard. An equality test against a
/// meaningful value (`a.b === 1`) resolves to the compared chain and may
/// only extend: `a && a.b === 1` rewrites to `a?.b === 1`, but an `!==`
/// against a meaningful value would invert its result when the receiver
/// is nullish.
#[derive(Debug, PartialEq, Eq)]
enum ChainRole {
    Receiver,
    Guard,
    Extender,
}

fn and_chain_reports(logical: &LogicalExpression<'_>, source: &str) -> bool {
    let mut operands = Vec::new();
    collect_and_operands(logical, &mut operands);
    let chains: Vec<Option<(Vec<ChainSegment<'_>>, ChainRole)>> = operands
        .iter()
        .map(|operand| operand_chain(operand, source))
        .collect();
    for (index, chain) in chains.iter().enumerate() {
        let Some((guard, role)) = chain else {
            continue;
        };
        if *role == ChainRole::Extender {
            continue;
        }
        for later in chains.iter().skip(index + 1) {
            let Some((extension, _)) = later else {
                continue;
            };
            if extension.len() > guard.len() && extension.starts_with(guard) {
                return true;
            }
        }
    }
    false
}
/// Receiver chain plus role of one `&&` operand.
fn operand_chain<'a>(
    expression: &'a Expression<'a>,
    source: &'a str,
) -> Option<(Vec<ChainSegment<'a>>, ChainRole)> {
    match unparenthesized(expression) {
        Expression::BinaryExpression(binary) => comparison_chain(binary, source),
        expression => Some((receiver_chain(expression, source)?, ChainRole::Receiver)),
    }
}

/// Statically known receiver chain of an expression: identifier or `this`
/// root followed by member links and trailing calls. Arguments are never
/// traversed, so `foo(a.b)` stays the `foo` chain.
fn receiver_chain<'a>(
    expression: &'a Expression<'a>,
    source: &'a str,
) -> Option<Vec<ChainSegment<'a>>> {
    let chain = match unparenthesized(expression) {
        Expression::Identifier(identifier) => vec![ChainSegment::Name(&identifier.name)],
        Expression::ThisExpression(_) => vec![ChainSegment::This],
        Expression::StaticMemberExpression(member) => {
            let mut chain = receiver_chain(&member.object, source)?;
            chain.push(ChainSegment::Name(&member.property.name));
            chain
        }
        Expression::PrivateFieldExpression(member) => {
            let mut chain = receiver_chain(&member.object, source)?;
            chain.push(ChainSegment::Name(&member.field.name));
            chain
        }
        Expression::ComputedMemberExpression(member) => {
            let mut chain = receiver_chain(&member.object, source)?;
            let key = &member.expression;
            let text = source.get(key.span().start as usize..key.span().end as usize)?;
            chain.push(ChainSegment::Computed(text));
            chain
        }
        Expression::CallExpression(call) => {
            let mut chain = receiver_chain(&call.callee, source)?;
            chain.push(ChainSegment::Call);
            chain
        }
        // Type-level wrappers keep the underlying receiver chain.
        Expression::TSNonNullExpression(wrapped) => receiver_chain(&wrapped.expression, source)?,
        Expression::TSAsExpression(wrapped) => receiver_chain(&wrapped.expression, source)?,
        Expression::TSSatisfiesExpression(wrapped) => receiver_chain(&wrapped.expression, source)?,
        _ => return None,
    };
    Some(chain)
}

/// Equality operands resolve to the receiver chain they compare.
fn comparison_chain<'a>(
    binary: &'a BinaryExpression<'a>,
    source: &'a str,
) -> Option<(Vec<ChainSegment<'a>>, ChainRole)> {
    if !is_equality_operator(binary.operator) {
        return None;
    }
    let left = unparenthesized(&binary.left);
    let right = unparenthesized(&binary.right);
    let is_nullish = |expression: &Expression<'_>| {
        matches!(expression, Expression::NullLiteral(_))
            || identifier_name(expression) == Some("undefined")
    };
    if is_nullish(right) {
        return Some((receiver_chain(left, source)?, ChainRole::Guard));
    }
    if is_nullish(left) {
        return Some((receiver_chain(right, source)?, ChainRole::Guard));
    }
    match binary.operator {
        BinaryOperator::Equality | BinaryOperator::StrictEquality => {
            // `a && a.b === value` rewrites to `a?.b === value` only while
            // `value` is a definite literal: `undefined === value` could
            // otherwise flip the comparison result when `a` is nullish.
            for (chain_side, other) in [(&left, &right), (&right, &left)] {
                if let Some(chain) = receiver_chain(chain_side, source)
                    && is_definite_value(other)
                {
                    return Some((chain, ChainRole::Extender));
                }
            }
            None
        }
        _ => None,
    }
}

/// `a?.b === value` keeps its comparison result while `value` cannot be
/// `undefined`: literals never are, and the reference also keeps plain
/// identifier comparisons, while call results (which may return
/// `undefined`) drop out of the family.
fn is_definite_value(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        // Literals and identifiers can never be `undefined`.
        Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::Identifier(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::UnaryExpression(unary) => {
            matches!(
                unary.operator,
                UnaryOperator::UnaryNegation | UnaryOperator::UnaryPlus
            ) && matches!(&unary.argument, Expression::NumericLiteral(_))
        }
        _ => false,
    }
}

/// Flattens the `&&` chain rooted at `logical` into its operands.
fn collect_and_operands<'a>(
    logical: &'a LogicalExpression<'a>,
    operands: &mut Vec<&'a Expression<'a>>,
) {
    collect_and_operand(&logical.left, operands);
    collect_and_operand(&logical.right, operands);
}

/// Collects one leaf operand, descending through nested `&&` chains.
fn collect_and_operand<'a>(expression: &'a Expression<'a>, operands: &mut Vec<&'a Expression<'a>>) {
    if let Expression::LogicalExpression(logical) = unparenthesized(expression)
        && logical.operator == LogicalOperator::And
    {
        collect_and_operands(logical, operands);
        return;
    }
    operands.push(unparenthesized(expression));
}

/// Whether the expression is `null` or the `undefined` identifier — the
/// nullish spellings an equality guard can test for (`S6582`).
fn is_nullish(expression: &Expression<'_>) -> bool {
    matches!(expression, Expression::NullLiteral(_))
        || identifier_name(expression) == Some("undefined")
}

/// De Morgan dual of the `&&` guard family: an `||` chain reports when it
/// rewrites to a single optional chain — a negated receiver guard
/// (`!fn`, `!a.b`) or a nullish-equality guard (`a == null`) followed by
/// operands that strictly extend the guard's chain (`!fn.handle`,
/// `node.type !== "directory"`). Sibling members of one root
/// (`!this.a || !this.b`) have no `?.` rewrite and stay silent.
fn negated_or_guard_reports(logical: &LogicalExpression<'_>, source: &str) -> bool {
    let mut operands = Vec::new();
    collect_or_operands(logical, &mut operands);
    let Some(base) = operands
        .first()
        .and_then(|first| or_guard_chain(first, source))
    else {
        return false;
    };
    operands[1..]
        .iter()
        .all(|operand| or_extender_chain(operand, &base, source))
}

/// The guard operand of an `||` chain: a single negation over a receiver
/// chain without calls (`!fn`, `!this.a.b`), or a nullish-equality test
/// (`a == null`, `a === undefined`).
fn or_guard_chain<'a>(
    expression: &'a Expression<'a>,
    source: &'a str,
) -> Option<Vec<ChainSegment<'a>>> {
    match unparenthesized(expression) {
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::LogicalNot => {
            let chain = receiver_chain(unparenthesized(&unary.argument), source)?;
            (!chain
                .iter()
                .any(|segment| matches!(segment, ChainSegment::Call)))
            .then_some(chain)
        }
        Expression::BinaryExpression(binary) => or_nullish_guard_chain(binary, source),
        _ => None,
    }
}

/// `a == null` and `a === undefined` guard `a` against nullish access in
/// an `||` chain; strict `=== null` does not cover `undefined`.
fn or_nullish_guard_chain<'a>(
    binary: &'a BinaryExpression<'a>,
    source: &'a str,
) -> Option<Vec<ChainSegment<'a>>> {
    let accepts = match binary.operator {
        BinaryOperator::Equality => is_nullish,
        BinaryOperator::StrictEquality => {
            |expression: &Expression<'_>| identifier_name(expression) == Some("undefined")
        }
        _ => return None,
    };
    for (chain_side, other) in [(&binary.left, &binary.right), (&binary.right, &binary.left)] {
        if accepts(unparenthesized(other))
            && let Some(chain) = receiver_chain(unparenthesized(chain_side), source)
        {
            return Some(chain);
        }
    }
    None
}

/// A later `||` operand must strictly extend the guard's chain: either a
/// negation over a longer call-free chain (`!fn.handle`) or a comparison
/// whose chain side extends it (`node.type !== "directory"`).
fn or_extender_chain<'a>(
    expression: &'a Expression<'a>,
    base: &[ChainSegment<'a>],
    source: &'a str,
) -> bool {
    let extends =
        |chain: &Vec<ChainSegment<'a>>| chain.len() > base.len() && chain.starts_with(base);
    match unparenthesized(expression) {
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::LogicalNot => {
            match receiver_chain(unparenthesized(&unary.argument), source) {
                Some(chain) => {
                    !chain
                        .iter()
                        .any(|segment| matches!(segment, ChainSegment::Call))
                        && extends(&chain)
                }
                None => false,
            }
        }
        Expression::BinaryExpression(binary) => or_comparison_chain(binary, base, source),
        _ => false,
    }
}

/// `ext !== value` extends the guard when `value` keeps the comparison
/// result while the receiver is nullish: `undefined !== v` is true for
/// definite values and `null`, and `undefined == null` holds loosely.
fn or_comparison_chain<'a>(
    binary: &'a BinaryExpression<'a>,
    base: &[ChainSegment<'a>],
    source: &'a str,
) -> bool {
    let accepts = |expression: &Expression<'_>| match binary.operator {
        BinaryOperator::StrictInequality => {
            (is_definite_value(expression) && identifier_name(expression) != Some("undefined"))
                || matches!(expression, Expression::NullLiteral(_))
        }
        BinaryOperator::Inequality => is_definite_value(expression) && !is_nullish(expression),
        BinaryOperator::Equality => is_nullish(expression),
        BinaryOperator::StrictEquality => identifier_name(expression) == Some("undefined"),
        _ => false,
    };
    for (chain_side, other) in [(&binary.left, &binary.right), (&binary.right, &binary.left)] {
        if accepts(unparenthesized(other))
            && let Some(chain) = receiver_chain(unparenthesized(chain_side), source)
            && chain.len() > base.len()
            && chain.starts_with(base)
        {
            return true;
        }
    }
    false
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
        let reports = match it.operator {
            LogicalOperator::And => and_chain_reports(it, self.source),
            LogicalOperator::Or => negated_or_guard_reports(it, self.source),
            LogicalOperator::Coalesce => false,
        };
        if reports {
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
