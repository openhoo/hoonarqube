// Rule module s6523_mixed_optional_chains (generated).
use crate::engine::scope_model::member_optional;
use crate::support::{IssueSink, RuleScope, member_object, unparenthesized};
use oxc_ast::ast::{Expression, LogicalOperator, MemberExpression};
use oxc_span::Span;

/// `S6523` (`no-unsafe-optional-chaining`): whether `expression` can
/// evaluate to `undefined` because an optional chain inside it
/// short-circuited. Parentheses are transparent in this parser's AST, so
/// `(a?.b)` resolves through to its chain. `||`/`??` only propagate the
/// right operand's undefined result; `&&` propagates either side's.
/// Mirrors the reference's `checkUndefinedShortCircuit`.
fn resolves_to_chain(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::ChainExpression(_) => true,
        Expression::LogicalExpression(logical) => match logical.operator {
            LogicalOperator::Or | LogicalOperator::Coalesce => resolves_to_chain(&logical.right),
            LogicalOperator::And => {
                resolves_to_chain(&logical.left) || resolves_to_chain(&logical.right)
            }
        },
        Expression::SequenceExpression(sequence) => sequence
            .expressions
            .last()
            .is_some_and(|last| resolves_to_chain(last)),
        Expression::ConditionalExpression(conditional) => {
            resolves_to_chain(&conditional.consequent) || resolves_to_chain(&conditional.alternate)
        }
        Expression::AwaitExpression(await_expression) => {
            resolves_to_chain(&await_expression.argument)
        }
        _ => false,
    }
}

/// Whether the member access `member` applies a plain `.`/`[]` to a value
/// that can be `undefined` from a short-circuited optional chain — the
/// chain was broken by a new expression scope such as parentheses
/// (`(a?.b).c`). A continuous chain like `a?.b.c` short-circuits the
/// remaining segments, so it is safe and stays clean (#820).
pub(crate) fn member_access_on_short_circuited_chain(member: &MemberExpression<'_>) -> bool {
    !member_optional(member) && resolves_to_chain(member_object(member))
}

/// Whether the call `callee` expression can be `undefined` from a
/// short-circuited optional chain, e.g. `(a?.b)()`. Optional call
/// segments (`a?.()`) short-circuit instead of throwing.
pub(crate) fn call_on_short_circuited_chain(callee: &Expression<'_>, optional: bool) -> bool {
    !optional && resolves_to_chain(callee)
}

/// Keeps only spans not contained in another candidate: whenever a chain
/// suffix mixes optionality, its enclosing head chain mixes too, so the
/// maximal spans correspond exactly to the reported chains.
fn maximal_spans(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
    });
    let mut kept: Vec<Span> = Vec::new();
    for span in spans {
        if !kept
            .iter()
            .any(|kept_span| kept_span.start <= span.start && span.end <= kept_span.end)
        {
            kept.push(span);
        }
    }
    kept
}

/// `S6523`: reports the maximal mixed-optional chain spans collected during
/// traversal once that traversal has finished.
pub(crate) fn report_mixed_chains(sink: &mut IssueSink, chains: Vec<Span>) {
    for span in maximal_spans(chains) {
        sink.emit_span(
            RuleScope::Both,
            "S6523",
            "This chain mixes optional and non-optional accesses; an intermediate 'undefined' will throw.",
            span,
        );
    }
}
