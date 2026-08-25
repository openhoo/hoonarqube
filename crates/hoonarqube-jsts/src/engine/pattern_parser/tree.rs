use super::to_u32;

/// Character-class shorthand escapes (`\d`, `\w`, `\s` and negations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShorthandClass {
    Digit,
    Word,
    Space,
}

/// Zero-width assertions understood by the pattern parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnchorKind {
    Start,
    End,
    WordBoundary,
    NotWordBoundary,
}

/// Group headers the mini parser understands; anything else (`(?P`, …) is a
/// definite syntax error for `S5856`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GroupKind {
    Capturing,
    Named(String),
    NonCapturing,
    Lookahead { negated: bool },
    Lookbehind { negated: bool },
}

impl GroupKind {
    pub(crate) fn is_lookaround(&self) -> bool {
        matches!(self, Self::Lookahead { .. } | Self::Lookbehind { .. })
    }
}

/// One item inside a `[...]` character class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClassItem {
    Char {
        ch: char,
        pos: usize,
    },
    Range {
        low: char,
        high: char,
        start: usize,
    },
    Shorthand {
        negated: bool,
        kind: ShorthandClass,
        pos: usize,
    },
    Property {
        negated: bool,
        pos: usize,
    },
}

/// One node of the mini regex-pattern tree. Positions are byte offsets into
/// the pattern text so findings can be anchored at the offending construct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PatternNode {
    Literal {
        ch: char,
        pos: usize,
    },
    Dot,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
        start: usize,
        end: usize,
    },
    ClassEscape {
        negated: bool,
        kind: ShorthandClass,
        pos: usize,
    },
    PropertyEscape {
        negated: bool,
        pos: usize,
    },
    Anchor {
        kind: AnchorKind,
        pos: usize,
    },
    Group {
        kind: GroupKind,
        alternatives: Vec<Vec<PatternNode>>,
        start: usize,
        end: usize,
    },
    BackReference {
        pos: usize,
    },
    Quantified {
        node: Box<PatternNode>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
        pos: usize,
        /// Verbatim source text of the quantifier (`{1}` vs `{1,1}`).
        verbose: String,
    },
}

/// Parse result of [`parse_regex_pattern`].
pub(crate) struct ParsedRegex {
    pub(crate) alternatives: Vec<Vec<PatternNode>>,
    /// Byte offsets of empty alternation branches with at least one
    /// non-empty sibling (`S6323`); wholly empty groups belong to `S6331`.
    pub(crate) empty_branch_positions: Vec<usize>,
    pub(crate) capture_count: usize,
    pub(crate) capture_names: Vec<String>,
}
/// Whether a sequence can match the empty string.
pub(crate) fn sequence_can_match_empty(sequence: &[PatternNode]) -> bool {
    sequence.iter().all(node_can_match_empty)
}

/// Whether one node can match the empty string; lookarounds and anchors are
/// zero-width, groups when any alternative is empty-capable.
pub(crate) fn node_can_match_empty(node: &PatternNode) -> bool {
    match node {
        PatternNode::Anchor { .. } => true,
        PatternNode::Group {
            kind, alternatives, ..
        } => {
            kind.is_lookaround()
                || alternatives
                    .iter()
                    .any(|alternative| sequence_can_match_empty(alternative))
        }
        PatternNode::Quantified { min, node, .. } => *min == 0 || node_can_match_empty(node),
        _ => false,
    }
}

/// Pre-order traversal of the pattern tree behind `sequence`.
pub(crate) fn walk_pattern_nodes(sequence: &[PatternNode], visit: &mut dyn FnMut(&PatternNode)) {
    for node in sequence {
        visit(node);
        match node {
            PatternNode::Group { alternatives, .. } => {
                for alternative in alternatives {
                    walk_pattern_nodes(alternative, visit);
                }
            }
            PatternNode::Quantified { node: inner, .. } => {
                walk_pattern_nodes(std::slice::from_ref(inner.as_ref()), visit);
            }
            _ => {}
        }
    }
}

/// Documented subset approximation of the `S5843` complexity score:
/// literals/dots/anchors cost 1, shorthands 2, backreferences 2, property
/// escapes 3, classes `2 + items`, groups 2 (lookarounds 4) plus their
/// body, quantifiers 2 plus their target, and each additional alternation
/// branch costs 1.
pub(crate) fn pattern_complexity(alternatives: &[Vec<PatternNode>]) -> u32 {
    let extra_branches = alternatives.len().saturating_sub(1);
    alternatives
        .iter()
        .map(|alternative| alternative.iter().map(node_complexity).sum::<u32>())
        .sum::<u32>()
        .saturating_add(to_u32(extra_branches))
}

pub(crate) fn node_complexity(node: &PatternNode) -> u32 {
    match node {
        PatternNode::Literal { .. } | PatternNode::Dot | PatternNode::Anchor { .. } => 1,
        PatternNode::BackReference { .. } | PatternNode::ClassEscape { .. } => 2,
        PatternNode::PropertyEscape { .. } => 3,
        PatternNode::Class { items, .. } => 2u32.saturating_add(to_u32(items.len())),
        PatternNode::Group {
            kind, alternatives, ..
        } => {
            let base: u32 = if kind.is_lookaround() { 4 } else { 2 };
            base.saturating_add(pattern_complexity(alternatives))
        }
        PatternNode::Quantified { node, .. } => 2u32.saturating_add(node_complexity(node)),
    }
}
pub(crate) fn contains_unbounded_quantifier(node: &PatternNode) -> bool {
    match node {
        PatternNode::Quantified { max: None, .. } => true,
        PatternNode::Quantified { node: inner, .. } => contains_unbounded_quantifier(inner),
        PatternNode::Group { alternatives, .. } => alternatives
            .iter()
            .flatten()
            .any(contains_unbounded_quantifier),
        _ => false,
    }
}
