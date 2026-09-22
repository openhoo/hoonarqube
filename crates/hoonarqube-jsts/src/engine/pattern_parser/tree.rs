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
    /// An exact UTF-16 code unit from a fixed-width Unicode escape.  Lone
    /// surrogates are valid JavaScript regex atoms but cannot be represented
    /// as Rust `char`s, so downstream analyses must keep them opaque.
    CodeUnit {
        unit: u16,
        pos: usize,
    },
    /// A character-class range whose endpoints are exact UTF-16 code units.
    /// This is needed for surrogate ranges, which cannot inhabit `char`.
    CodeUnitRange {
        low: u16,
        high: u16,
        start: usize,
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
    /// An exact UTF-16 code unit from a fixed-width Unicode escape.
    CodeUnit {
        unit: u16,
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

/// `S5843` complexity score aligned with the reference implementations
/// (`SonarJS`'s `ComplexityCalculator` and the shared `ComplexRegexFinder`):
/// quantifiers, lookarounds, and each disjunction with two or more
/// alternatives charge the *current nesting level* and then nest their
/// contents one deeper; a disjunction with `k >= 2` alternatives charges
/// `nesting + (k - 2)` (first `|` at nesting, later `|`s flat 1).
/// Character classes and backreferences cost a flat 1 regardless of
/// nesting. Literals, dots, anchors, shorthand/property escapes, class
/// items, and single-alternative groups (capturing or not) are free.
///
/// Intentionally unscored or unsupported constructs: flag groups and
/// atomic groups are rejected by the mini parser (reported as `S5856`,
/// never scored); `v`-flag class intersections (`[a&&b]`) parse as plain
/// class items here, so their `&&` operators are uncounted; and regexes
/// assembled from multiple string parts or variables are out of scope
/// because [`RegexSite`] only covers single literals. Where the reference
/// semantics are uncertain this scorer prefers under-counting, so a
/// parity-profile run never reports a regex the reference leaves clean.
pub(crate) fn pattern_complexity(alternatives: &[Vec<PatternNode>]) -> u32 {
    disjunction_complexity(alternatives, 1)
}

/// Scores one disjunction (a pattern or group body) at `nesting`.
fn disjunction_complexity(alternatives: &[Vec<PatternNode>], nesting: u32) -> u32 {
    let mut score = 0u32;
    let mut inner_nesting = nesting;
    if alternatives.len() > 1 {
        // First `|` costs the current nesting level, later `|`s cost 1.
        score = nesting.saturating_add(to_u32(alternatives.len() - 2));
        inner_nesting = nesting.saturating_add(1);
    }
    for alternative in alternatives {
        for node in alternative {
            score = score.saturating_add(node_complexity(node, inner_nesting));
        }
    }
    score
}

fn node_complexity(node: &PatternNode, nesting: u32) -> u32 {
    match node {
        PatternNode::Literal { .. }
        | PatternNode::CodeUnit { .. }
        | PatternNode::Dot
        | PatternNode::Anchor { .. }
        | PatternNode::ClassEscape { .. }
        | PatternNode::PropertyEscape { .. } => 0,
        PatternNode::BackReference { .. } | PatternNode::Class { .. } => 1,
        PatternNode::Group {
            kind, alternatives, ..
        } => {
            let mut score = 0u32;
            let mut inner_nesting = nesting;
            if kind.is_lookaround() {
                score = nesting;
                inner_nesting = nesting.saturating_add(1);
            }
            score.saturating_add(disjunction_complexity(alternatives, inner_nesting))
        }
        PatternNode::Quantified { node, .. } => {
            nesting.saturating_add(node_complexity(node, nesting.saturating_add(1)))
        }
    }
}
