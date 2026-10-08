use crate::engine::rx::{
    RxAtom, RxGroupKind, RxItem, RxNode, RxSeq, lazy_next_forced_empty, rx_item_nullable_pub,
};
use ruff_text_size::TextRange;

pub(crate) fn check_rx_lazy_quantifiers(
    node: &RxNode,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    visit_node(node, &[], push);
}

fn visit_node<'a>(
    node: &'a RxNode,
    continuation: &[&'a RxItem],
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    match node {
        RxNode::Seq(seq) => visit_seq(seq, continuation, push),
        RxNode::Alternation(branches) => {
            for branch in branches {
                visit_seq(branch, continuation, push);
            }
        }
    }
}

fn visit_seq<'a>(
    seq: &'a RxSeq,
    continuation: &[&'a RxItem],
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    for (position, item) in seq.items.iter().enumerate() {
        let mut rest: Vec<&RxItem> = seq.items[position + 1..].iter().collect();
        rest.extend_from_slice(continuation);
        if let Some(quant) = &item.quant
            && quant.lazy
            && rest.iter().all(|next| empty_continuation(next))
        {
            push(
                "python:S6019",
                &format!(
                    "Fix this reluctant quantifier that will only ever match {} repetitions.",
                    quant.min
                ),
                item.span,
            );
        }
        if let RxAtom::Group(group) = &item.atom {
            // Assertions have their own matching boundary. Capture and
            // non-capture groups continue through the enclosing sequence.
            if matches!(group.kind, RxGroupKind::Capture | RxGroupKind::NonCapture) {
                visit_node(&group.body, &rest, push);
            } else {
                visit_node(&group.body, &[], push);
            }
        }
    }
}

fn empty_continuation(item: &RxItem) -> bool {
    if lazy_next_forced_empty(item) {
        return true;
    }
    // An end alternative preceded by an optional separator is already
    // reachable at the minimum match. A consuming terminator such as
    // `(end|$)` still gives the reluctant repetition useful work to do.
    if let RxAtom::Group(group) = &item.atom
        && let RxNode::Alternation(branches) = &group.body
        && branches.iter().any(|branch| {
            branch
                .items
                .iter()
                .any(|next| matches!(next.atom, RxAtom::Anchor(anchor) if anchor.is_end()))
        })
    {
        return branches.iter().any(|branch| {
            branch.items.first().is_some_and(|first| {
                !matches!(first.atom, RxAtom::Anchor(_)) && rx_item_nullable_pub(first)
            })
        });
    }
    false
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

    #[test]
    fn s6019_observes_enclosing_group_continuations() {
        use crate::test_support::{findings, scan};
        for pattern in [
            r"(.*?)x",
            r#"(.+?)["']"#,
            r"x(?:a*?b?)y",
            r"(?P<arguments>.*?)\)",
        ] {
            let source = format!("import re\nre.compile(r'''{pattern}''')\n");
            assert!(
                findings(&scan(&source), "python:S6019").is_empty(),
                "{pattern}"
            );
        }
        let source = "import re\nre.compile(r'/{2,}?')\n";
        let report = scan(source);
        let issues = findings(&report, "python:S6019");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Fix this reluctant quantifier that will only ever match 2 repetitions."
        );
    }

    #[test]
    fn s6019_flags_lazy_quantifiers_before_empty_matches() {
        assert!(regex_finds(
            "import re\nre.match(r'^\\d*?$', s)\n",
            "python:S6019"
        ));
        assert!(regex_finds(
            "import re\nre.sub(r'start\\w*?(end)?', 'x', s)\n",
            "python:S6019"
        ));
        // The sanctioned lazy-terminator idiom is exempt.
        assert!(!regex_finds(
            "import re\nre.sub(r'start\\w*?(end|$)', 'x', s)\n",
            "python:S6019"
        ));
        // A consuming parent continuation prevents an empty match.
        assert!(!regex_finds(
            "import re\nre.match(r'x(?:a*?b?)y', s)\n",
            "python:S6019"
        ));
    }
}
