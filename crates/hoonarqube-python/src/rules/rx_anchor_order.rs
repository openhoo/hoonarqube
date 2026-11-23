use crate::engine::rx::{RxAnchor, RxAtom, RxGroup, RxGroupKind, RxItem, RxNode, RxSeq};
use ruff_text_size::TextRange;

/// How much of the pattern on one side of a boundary consumes input.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Input {
    Empty,
    Optional,
    Required,
}

impl Input {
    fn either(self, other: Self) -> Self {
        if self == other { self } else { Self::Optional }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    BeforeStart,
    AfterEnd,
    AfterAbsoluteEnd,
}

type Emit<'a> = dyn FnMut(&str, &str, TextRange) + 'a;

/// Collected during the existing structural pass, so patterns without a
/// relevant boundary never need another traversal.
#[derive(Default)]
pub(crate) struct BoundaryChecks {
    start: bool,
    end: bool,
    absolute_end: bool,
}

impl BoundaryChecks {
    pub(crate) fn observe(&mut self, atom: &RxAtom) {
        match atom {
            RxAtom::Anchor(RxAnchor::Caret | RxAnchor::StringStart) => self.start = true,
            RxAtom::Anchor(RxAnchor::Dollar | RxAnchor::EndOrFinalTerminator) => self.end = true,
            RxAtom::Anchor(RxAnchor::AbsoluteEnd) => self.absolute_end = true,
            _ => {}
        }
    }

    pub(crate) fn check(&self, root: &RxNode, emit: &mut Emit<'_>) {
        for (needed, direction) in [
            (self.start, Direction::BeforeStart),
            (self.end, Direction::AfterEnd),
            (self.absolute_end, Direction::AfterAbsoluteEnd),
        ] {
            if needed {
                direction.node(root, Input::Empty, false, emit);
            }
        }
    }
}

impl Direction {
    fn node(self, node: &RxNode, input: Input, in_choice: bool, emit: &mut Emit<'_>) -> Input {
        match node {
            RxNode::Seq(seq) => self.sequence(seq, input, in_choice, emit),
            RxNode::Alternation(branches) => branches
                .iter()
                .map(|seq| self.sequence(seq, input, true, emit))
                .reduce(Input::either)
                .unwrap_or(input),
        }
    }

    fn sequence(self, seq: &RxSeq, input: Input, in_choice: bool, emit: &mut Emit<'_>) -> Input {
        let mut visit = |state, item: &RxItem| {
            let next = self.item(item, state, in_choice, emit);
            match &item.quant {
                Some(q) if q.max == Some(0) => state,
                Some(q) if q.min == 0 => state.either(next),
                _ => next,
            }
        };
        if self == Self::BeforeStart {
            seq.items.iter().fold(input, &mut visit)
        } else {
            seq.items.iter().rev().fold(input, &mut visit)
        }
    }

    fn item(self, item: &RxItem, input: Input, in_choice: bool, emit: &mut Emit<'_>) -> Input {
        match &item.atom {
            RxAtom::Group(group) => self.group(group, input, in_choice, emit),
            RxAtom::Anchor(a) => {
                if self.applies(*a)
                    && (input == Input::Required || !in_choice)
                    && let Some(message) = self.message(input)
                {
                    emit("python:S5996", message, item.span);
                }
                input
            }
            RxAtom::GlobalFlags | RxAtom::Comment => input,
            // Community does not use a trailing escaped code point alone
            // as proof that a soft end is impossible. A mandatory suffix
            // beyond it still proves the boundary cannot match.
            RxAtom::Literal(_) if self == Self::AfterEnd && item.code_point_escape => {
                if input == Input::Required {
                    input
                } else {
                    Input::Empty
                }
            }
            RxAtom::Backref(_) | RxAtom::NamedRef(_) => input.max(Input::Optional),
            _ => Input::Required,
        }
    }

    fn group(self, group: &RxGroup, input: Input, in_choice: bool, emit: &mut Emit<'_>) -> Input {
        let ahead = matches!(
            group.kind,
            RxGroupKind::Lookahead | RxGroupKind::NegativeLookahead
        );
        let behind = matches!(
            group.kind,
            RxGroupKind::Lookbehind | RxGroupKind::NegativeLookbehind
        );
        if !ahead && !behind {
            return self.node(&group.body, input, in_choice, emit);
        }
        // A lookahead can see the prefix already matched. A lookbehind can
        // see the suffix still to match. Neither consumes input outside itself.
        let inherited = (self == Self::BeforeStart) == ahead;
        self.node(
            &group.body,
            if inherited { input } else { Input::Empty },
            in_choice,
            emit,
        );
        input
    }

    fn applies(self, a: RxAnchor) -> bool {
        match self {
            Self::BeforeStart => matches!(a, RxAnchor::Caret | RxAnchor::StringStart),
            Self::AfterEnd => matches!(a, RxAnchor::Dollar | RxAnchor::EndOrFinalTerminator),
            Self::AfterAbsoluteEnd => a == RxAnchor::AbsoluteEnd,
        }
    }

    fn message(self, input: Input) -> Option<&'static str> {
        match (input, self == Self::BeforeStart) {
            (Input::Empty, _) => None,
            (Input::Required, true) => Some(
                "Remove or replace this boundary that will never match because it appears after mandatory input.",
            ),
            (Input::Required, false) => Some(
                "Remove or replace this boundary that will never match because it appears before mandatory input.",
            ),
            (Input::Optional, true) => Some(
                "Remove or replace this boundary that can only match if the previous part matched the empty string because it appears after mandatory input.",
            ),
            (Input::Optional, false) => Some(
                "Remove or replace this boundary that can only match if the previous part matched the empty string because it appears before mandatory input.",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, regex_finds, scan};

    #[test]
    fn s5996_flags_boundaries_that_can_never_match() {
        assert!(regex_finds(
            "import re\nre.compile(r'$[a-z]+^')\n",
            "python:S5996"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'^[a-z]+$')\n",
            "python:S5996"
        ));
    }

    #[test]
    fn multiline_flags_are_local_to_the_pattern_or_scoped_group() {
        for call in [
            r#"re.compile(r"a^b", re.VERBOSE | re.MULTILINE)"#,
            r#"re.sub(r"a$b", "", "", flags=re.M)"#,
            r#"re.compile(r"(?m:a$b)(?m:c^d)")"#,
            r#"re.compile(r"(?m)a$b")"#,
        ] {
            assert!(
                !regex_finds(&format!("import re\n{call}\n"), "python:S5996"),
                "{call}"
            );
        }
        for call in [
            r#"re.compile(r"(?m)(?-m:a$b)")"#,
            r#"re.compile(r"(?m:a$b)c$d")"#,
            r#"re.search(r"a^b", re.M.name)"#,
            r#"re.compile(r"a\Zb", flags=re.M)"#,
        ] {
            assert!(
                regex_finds(&format!("import re\n{call}\n"), "python:S5996"),
                "{call}"
            );
        }
    }

    #[test]
    fn consecutive_and_nested_anchors_use_the_full_primary_range() {
        let report = scan("import re\nre.compile(r'a(?:\\A^b)', re.I)\n");
        let issues = findings(&report, "python:S5996");
        let ranges: Vec<_> = issues
            .iter()
            .map(|i| (i.range.start.column, i.range.end.column))
            .collect();
        assert_eq!(ranges, [(17, 19), (19, 20)]);
    }
}
