use crate::engine::rx::RxItem;
use crate::engine::rx::RxNode;
use crate::engine::rx::RxParsed;
use crate::engine::rx::RxSet;
use crate::engine::rx::for_each_rx_seq_deep;
use crate::engine::rx::rx_atom_first_set;
use crate::engine::rx::rx_equivalent;
use crate::engine::rx::rx_item_consuming;
use crate::engine::rx::rx_leading_anchor_span;
use crate::engine::rx::rx_lookahead_body;
use crate::engine::rx::rx_node_first_set;
use crate::engine::rx::rx_positive_lookahead_body;
use crate::engine::rx::rx_sets_intersect;
use crate::engine::rx::rx_trailing_anchor_span;
use crate::rules::rx_alternation_nodes::check_rx_alternation_nodes;
use crate::rules::rx_anchor_order::check_rx_anchor_order;
use crate::rules::rx_space_runs::check_rx_space_runs;
use ruff_text_size::TextRange;

pub(crate) fn check_rx_alternation_shapes(
    parsed: &RxParsed,
    verbose: bool,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    // python:S5850 — anchors in a top-level alternation need grouping.
    if let RxNode::Alternation(branches) = &parsed.root
        && branches.len() >= 2
    {
        let leading_start = branches.first().and_then(rx_leading_anchor_span);
        let trailing_end = branches.last().and_then(rx_trailing_anchor_span);
        if (leading_start.is_some() || trailing_end.is_some())
            && let (Some(first), Some(last)) = (branches.first(), branches.last())
        {
            push(
                "python:S5850",
                "Group parts of the regex together to make the intended operator precedence explicit.",
                TextRange::new(first.span.start(), last.span.end()),
            );
        }
    }
    for_each_rx_seq_deep(&parsed.root, &mut |seq| {
        // python:S6002 — contradictory lookarounds.
        check_contradictory_lookaheads(&seq.items, push);
        // python:S5996 — anchors that can never match.
        check_rx_anchor_order(seq, push);
        // python:S6326 — multiple consecutive literal spaces; skipped under
        // the extended/verbose flag where whitespace is formatting.
        if !verbose {
            check_rx_space_runs(seq, push);
        }
    });
    // python:S6035 / python:S6323 — single-character alternations and empty
    // alternatives.
    check_rx_alternation_nodes(&parsed.root, false, push);
}

/// python:S6002 — lookarounds that contradict the rest of their sequence.
fn check_contradictory_lookaheads(items: &[RxItem], push: &mut dyn FnMut(&str, &str, TextRange)) {
    check_adjacent_lookaheads(items, push);
    check_lookaheads_against_consumers(items, push);
}

fn check_adjacent_lookaheads(items: &[RxItem], push: &mut dyn FnMut(&str, &str, TextRange)) {
    for pair in items.windows(2) {
        if let (Some(a), Some(b)) = (
            rx_lookahead_body(&pair[0].atom),
            rx_lookahead_body(&pair[1].atom),
        ) && rx_equivalent(a, b)
        {
            push(
                "python:S6002",
                "Remove or fix this lookahead assertion that can never be true.",
                pair[1].span,
            );
        }
    }
}

fn check_lookaheads_against_consumers(
    items: &[RxItem],
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    let mut lookahead_sets: Vec<(&RxItem, Option<RxSet>)> = Vec::new();
    for item in items {
        if let Some(body) = rx_positive_lookahead_body(&item.atom) {
            lookahead_sets.push((item, rx_node_first_set(body)));
            continue;
        }
        if rx_item_consuming(item) {
            if let Some(set) = rx_atom_first_set(&item.atom) {
                push_disjoint_lookaheads(&lookahead_sets, &set, push);
            }
            lookahead_sets.clear();
        }
    }
}

fn push_disjoint_lookaheads(
    lookahead_sets: &[(&RxItem, Option<RxSet>)],
    consuming_set: &RxSet,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    for (lookahead, ahead_set) in lookahead_sets {
        if ahead_set
            .as_ref()
            .is_some_and(|ahead| !rx_sets_intersect(ahead, consuming_set))
        {
            push(
                "python:S6002",
                "Remove or fix this lookahead assertion that can never be true.",
                lookahead.span,
            );
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

    #[test]
    fn s6002_flags_contradictory_lookaheads() {
        assert!(regex_finds(
            "import re\nre.compile(r'(?=a)b')\n",
            "python:S6002"
        ));
        assert!(regex_finds(
            "import re\nre.compile(r'(?=a)(?!a)')\n",
            "python:S6002"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'a(?=b)')\n",
            "python:S6002"
        ));
        // Contradictions inside group bodies are reported too.
        assert!(regex_finds(
            "import re\nre.compile(r'x(?:(?=a)b)')\n",
            "python:S6002"
        ));
    }
}
