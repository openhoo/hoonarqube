use crate::engine::rx::RxAtom;
use crate::engine::rx::RxItem;
use crate::engine::rx::{RxNode, RxSeq};
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

pub(crate) fn check_rx_alternation_nodes(
    node: &RxNode,
    unquantified_group: bool,
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
            check_empty_alternatives(branches, unquantified_group, push);
            for branch in branches {
                visit_items(&branch.items, push);
            }
        }
        RxNode::Seq(seq) => visit_items(&seq.items, push),
    }
}

/// An unquantified group may express an optional match using one empty edge.
fn check_empty_alternatives(
    branches: &[RxSeq],
    unquantified_group: bool,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    let exempt = if !unquantified_group {
        None
    } else if branches.last().is_some_and(|b| b.items.is_empty()) {
        branches.len().checked_sub(1)
    } else {
        Some(0)
    };
    let mut previous_pipe = None;
    let mut last_reported = None;
    for (index, branch) in branches.iter().enumerate() {
        // A trailing empty branch has no token of its own. Its source location
        // is the preceding pipe, which can also mark the previous empty branch.
        let pipe = branch.following_pipe.or(previous_pipe);
        if branch.items.is_empty()
            && Some(index) != exempt
            && let Some(at) = pipe
            && Some(at) != last_reported
        {
            push(
                "python:S6323",
                "Remove this empty alternative.",
                TextRange::at(at, TextSize::new(1)),
            );
            last_reported = Some(at);
        }
        previous_pipe = branch.following_pipe;
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

    #[test]
    fn s6323_reports_only_redundant_empty_alternatives_at_their_pipe() {
        // Positions below are relative to the start of the regex literal contents.
        // Community 26.11: ordinary unquantified groups can use one empty edge.
        for (pattern, expected) in [
            ("(?:|a)", &[][..]),
            ("(a)?(?(1)|b)", &[][..]),
            ("(|a|)", &[1][..]),
            ("(||a)", &[2][..]),
            ("(a||b)", &[3][..]),
            ("(|a)+", &[1][..]),
            ("(a|)+", &[2][..]),
            ("a|", &[1][..]),
            ("|", &[0][..]),
            ("||", &[0, 1][..]),
        ] {
            let prefix = "re.compile(r\"";
            let report = crate::test_support::scan(&format!("import re\n{prefix}{pattern}\")\n"));
            let actual: Vec<_> = crate::test_support::findings(&report, "python:S6323")
                .into_iter()
                .map(|i| (i.range.start.column, i.range.end.column))
                .collect();
            let base = u32::try_from(prefix.len()).unwrap();
            assert_eq!(
                actual,
                expected
                    .iter()
                    .map(|n| (base + n, base + n + 1))
                    .collect::<Vec<_>>(),
                "{pattern}"
            );
        }
    }

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
