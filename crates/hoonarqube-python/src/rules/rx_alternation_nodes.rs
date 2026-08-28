use crate::engine::rx::RxAtom;
use crate::engine::rx::RxItem;
use crate::engine::rx::RxNode;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

pub(crate) fn check_rx_alternation_nodes(
    node: &RxNode,
    top_level_unquantified: bool,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    fn visit_items<'a>(
        items: impl IntoIterator<Item = &'a RxItem>,
        push: &mut dyn FnMut(&str, &str, TextRange),
    ) {
        for item in items {
            if let RxAtom::Group(group) = &item.atom {
                check_rx_alternation_nodes(&group.body, item.quant.is_none(), push);
            }
        }
    }
    match node {
        RxNode::Alternation(branches) => {
            // python:S6035 — all-literal single-character branches.
            if branches.len() >= 2
                && branches.iter().all(|branch| {
                    branch.items.len() == 1
                        && branch.items[0].quant.is_none()
                        && matches!(branch.items[0].atom, RxAtom::Literal(_))
                })
            {
                push(
                    "python:S6035",
                    "Replace this alternation with a character class.",
                    TextRange::new(
                        branches[0].span.start(),
                        branches[branches.len() - 1].span.end(),
                    ),
                );
            }
            // python:S6323 — empty alternatives, except a trailing empty
            // alternative inside an unquantified group used as an
            // optional-marker idiom.
            for (position, branch) in branches.iter().enumerate() {
                if branch.items.is_empty()
                    && !(top_level_unquantified && position == branches.len() - 1)
                {
                    push(
                        "python:S6323",
                        "Remove this empty alternative.",
                        TextRange::new(branch.span.start(), branch.span.start() + TextSize::new(1)),
                    );
                }
                visit_items(&branch.items, push);
            }
        }
        RxNode::Seq(seq) => visit_items(&seq.items, push),
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

    #[test]
    fn s6035_flags_single_character_alternations() {
        assert!(regex_finds(
            "import re\nre.compile(r'a|b|c')\n",
            "python:S6035"
        ));
        assert!(regex_finds(
            "import re\nre.compile(r'gr(a|e)y')\n",
            "python:S6035"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'[abc]')\n",
            "python:S6035"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'ab|cd')\n",
            "python:S6035"
        ));
    }
}
