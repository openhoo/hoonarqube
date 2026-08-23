use crate::engine::rx::RxAtom;
use crate::engine::rx::RxNode;
use crate::engine::rx::for_each_rx_seq;
use crate::engine::rx::rx_branch_covered_by;
use ruff_text_size::TextRange;

/// python:S5855 — an alternative fully covered by an earlier one is dead.
pub(crate) fn check_rx_redundant_alternatives(
    node: &RxNode,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    if let RxNode::Alternation(branches) = node {
        for later in 1..branches.len() {
            if branches[later].items.is_empty() {
                continue;
            }
            for earlier in 0..later {
                if rx_branch_covered_by(&branches[earlier], &branches[later]) {
                    push(
                        "python:S5855",
                        "Remove this redundant alternative; an earlier alternative already matches it.",
                        branches[later].span,
                    );
                    break;
                }
            }
        }
    }
    for_each_rx_seq(node, &mut |seq| {
        for item in &seq.items {
            if let RxAtom::Group(group) = &item.atom {
                check_rx_redundant_alternatives(&group.body, push);
            }
        }
    });
}
