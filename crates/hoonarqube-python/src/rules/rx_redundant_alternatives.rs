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
        check_alternation(branches, push);
    }
    check_nested_groups(node, push);
}

fn check_alternation(
    branches: &[crate::engine::rx::RxSeq],
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    for later in 1..branches.len() {
        if branches[later].items.is_empty() {
            continue;
        }
        if branches[..later]
            .iter()
            .any(|earlier| rx_branch_covered_by(earlier, &branches[later]))
        {
            push(
                "python:S5855",
                "Remove or rework this redundant alternative.",
                branches[later].span,
            );
        }
    }
}

fn check_nested_groups(node: &RxNode, push: &mut dyn FnMut(&str, &str, TextRange)) {
    for_each_rx_seq(node, &mut |seq| {
        for item in &seq.items {
            if let RxAtom::Group(group) = &item.atom {
                check_rx_redundant_alternatives(&group.body, push);
            }
        }
    });
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

    #[test]
    fn s5855_flags_alternatives_covered_by_earlier_ones() {
        assert!(regex_finds(
            "import re\nre.compile(r'[ab]|a')\n",
            "python:S5855"
        ));
        assert!(regex_finds(
            "import re\nre.compile(r'.*|a')\n",
            "python:S5855"
        ));
        assert!(regex_finds(
            "import re\nre.compile(r'foo|foo')\n",
            "python:S5855"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'foo|bar')\n",
            "python:S5855"
        ));
    }
}
