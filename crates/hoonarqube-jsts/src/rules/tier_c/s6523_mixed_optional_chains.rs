// Rule module s6523_mixed_optional_chains (generated).
use crate::engine::scope_model::member_optional;
use crate::support::{IssueSink, RuleScope, member_object, unparenthesized};
use oxc_ast::ast::MemberExpression;
use oxc_span::Span;

/// Whether the member chain rooted at `member` performs a plain access
/// above an optional one. Parenthesized objects end the analyzed chain:
/// `(a?.b).c` re-introduces a value boundary that this structural subset
/// deliberately does not cross.
pub(crate) fn chain_mixes_optional(member: &MemberExpression<'_>) -> bool {
    let mut seen_plain = false;
    let mut current = Some(member);
    while let Some(node) = current {
        if member_optional(node) {
            if seen_plain {
                return true;
            }
        } else {
            seen_plain = true;
        }
        current = unparenthesized(member_object(node)).as_member_expression();
    }
    false
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
