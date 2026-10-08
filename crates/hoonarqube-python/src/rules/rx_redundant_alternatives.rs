use crate::engine::rx::RxAtom;
use crate::engine::rx::RxNode;
use crate::engine::rx::for_each_rx_alternation;
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
        if covering_alternative(branches, position).is_some() {
            push(
                "python:S5855",
                "Remove or rework this redundant alternative.",
                candidate.span,
            );
            return;
        }
    }
}

fn covering_alternative(branches: &[crate::engine::rx::RxSeq], position: usize) -> Option<usize> {
    let candidate = &branches[position];
    branches
        .iter()
        .enumerate()
        .find_map(|(other_position, other)| {
            // Equal alternatives preserve the first branch and report the later
            // duplicate; strict supersets can occur later.
            (other_position != position
                && rx_branch_covered_by(other, candidate)
                && (other_position < position || !rx_branch_covered_by(candidate, other)))
            .then_some(other_position)
        })
}

pub(crate) fn redundancy_locations(
    node: &RxNode,
    primary: TextRange,
) -> Vec<(&'static str, TextRange)> {
    let mut locations = Vec::new();
    for_each_rx_alternation(node, &mut |branches| {
        let Some(position) = branches.iter().position(|branch| branch.span == primary) else {
            return;
        };
        let Some(keep) = covering_alternative(branches, position) else {
            return;
        };
        locations.push(("Alternative to keep", branches[keep].span));
        for (other_position, other) in branches.iter().enumerate() {
            if other_position != position
                && other_position != keep
                && !other.items.is_empty()
                && rx_branch_covered_by(&branches[keep], other)
            {
                locations.push(("Other redundant alternative", other.span));
            }
        }
    });
    locations
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
        assert_eq!(issues[0].flows.len(), 2);
        for (flow, (message, start, end)) in issues[0].flows.iter().zip([
            ("Alternative to keep", 24, 33),
            ("Other redundant alternative", 18, 23),
        ]) {
            assert_eq!(flow.locations.len(), 1);
            let location = &flow.locations[0];
            assert_eq!(location.message, message);
            assert_eq!(location.range.start.line, 2);
            assert_eq!(location.range.end.line, 2);
            assert_eq!(location.range.start.column, start);
            assert_eq!(location.range.end.column, end);
        }
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
