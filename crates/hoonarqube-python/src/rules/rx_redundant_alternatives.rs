use crate::engine::rx::RxAtom;
use crate::engine::rx::RxNode;
use crate::engine::rx::for_each_rx_seq;
use crate::engine::rx::rx_branch_covered_by;
use ruff_text_size::TextRange;

/// python:S5855 — an alternative fully covered by another is redundant.
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
    for (position, candidate) in branches.iter().enumerate() {
        if candidate.items.is_empty() {
            continue;
        }
        let covered = branches.iter().enumerate().any(|(other_position, other)| {
            other_position != position
                && rx_branch_covered_by(other, candidate)
                // Equal alternatives preserve the first branch and report
                // the later duplicate; strict supersets can occur later.
                && (other_position < position || !rx_branch_covered_by(candidate, other))
        });
        if covered {
            push(
                "python:S5855",
                "Remove or rework this redundant alternative.",
                candidate.span,
            );
            return;
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
    fn regex_redundancy_covers_later_class_languages_and_preserves_delimiters() {
        use crate::test_support::{findings, scan};
        let source = "import re\nre.compile(r'True|False|[\\w\\d_.]+')\n";
        let report = scan(source);
        let issues = findings(&report, "python:S5855");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].range.start.column, 13);
        assert_eq!(issues[0].range.end.column, 17);
        for pattern in [
            r"foo|[ab]+",
            r"foo|[a-z]{1,2}",
            r"(?:\r\n|\r|\n){2,}",
            r#""(?:[^\\"]|\\.)*""#,
        ] {
            let source = format!("import re\nre.compile(r'''{pattern}''')\n");
            assert!(
                findings(&scan(&source), "python:S5852").is_empty(),
                "{pattern}"
            );
            assert!(
                findings(&scan(&source), "python:S5855").is_empty(),
                "{pattern}"
            );
        }
        assert!(regex_finds(
            "import re\nre.fullmatch(r'(a+)+', text)\n",
            "python:S5852"
        ));
    }

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
