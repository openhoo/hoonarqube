// Rule module s8786_super_linear_regex (generated).
//
// `javascript:S8786` + `typescript:S8786` — regular expressions should not
// cause non-linear backtracking. Reference semantics: SonarJS 13.x S8786,
// which reports a regex literal when the `scslre` analysis finds at least
// one non-exponential (polynomial) report and no exponential report.
//
// Issue #399: 9 pinned campaign findings (exceljs 7, express 2) with no
// detector; the same check also serves the CodeQL `js/polynomial-redos`
// view. This implementation is a conservative true-positive-by-construction
// subset of the `scslre` "Move" report:
//
// * An unbounded quantified element (`*`, `+`, `{n,}`, or a quantifier over
//   an unbounded element) is a candidate when some single character can
//   pump it (`pump_set`).
// * The candidate is reachable at O(n) start positions on a pump-character
//   run when its prefix either can match empty at every position (all
//   elements empty-capable and every assertion inside passes on the run)
//   or can match a run of pump characters itself (every required element
//   pumps the character and every assertion passes on the run). `^`, `\b`,
//   `$`, and lookarounds constrain both paths through their boundary
//   character sets; `\B` never bounds.
// * Its continuation — the rest of its sequence, then the enclosing
//   quantified node (a further iteration) or the enclosing group's
//   continuation — must be able to reject a pumped run: some required
//   element fails on the pump set. Optional elements are skipped; anchors
//   reject; lookarounds reject by the same first/last-set polarity.
// * Nested unbounded quantifiers whose pump sets overlap with a rejecting
//   continuation are exponential in the reference analysis; those sites
//   are suppressed here because SonarJS drops literals that only produce
//   exponential reports.
//
// The `y` (sticky) flag anchors matching at `lastIndex`, so no Move-style
// report is possible and the literal stays silent. Patterns the mini
// parser rejects, dynamic `RegExp` arguments, and character sets the
// subset cannot compute (backreferences, property escapes, negated
// shorthands inside classes) stay silent. The literal or constructor
// argument anchors the finding. No auto-fix is offered.

use crate::context::AnalysisContext;
use crate::engine::pattern_parser::{
    AnchorKind, ClassItem, GroupKind, PatternNode, RegexSite, ShorthandClass,
    constructor_regex_site, node_can_match_empty, parse_regex_pattern, regex_site_from_literal,
    sequence_can_match_empty,
};
use crate::support::{IssueSink, RuleScope, callee_name, constructor_name};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{CallExpression, Expression, NewExpression};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_call_expression, walk_expression, walk_new_expression};

/// Entry point: `javascript:S8786` + `typescript:S8786` non-linear
/// backtracking check over every constant regex site.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut collector = RedosCollector {
        sink: IssueSink {
            index: ctx.index,
            language: ctx.language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(ctx.program);
    collector.sink.issues
}

struct RedosCollector<'index> {
    sink: IssueSink<'index>,
}

impl RedosCollector<'_> {
    /// Runs the subset analysis over one constant regex site and emits at
    /// most one finding anchored at the site span.
    fn check_site(&mut self, site: &RegexSite) {
        if site.has_flag('y') {
            return;
        }
        let unicode_mode = site.has_flag('u') || site.has_flag('v');
        let Ok(parsed) = parse_regex_pattern(&site.pattern, unicode_mode) else {
            return;
        };
        let flags = RegexFlags {
            insensitive: site.has_flag('i'),
            dot_all: site.has_flag('s'),
        };
        let mut sites = Vec::new();
        let mut ancestors = Vec::new();
        for alternative in &parsed.alternatives {
            collect_sites(alternative, &[], &[], &mut ancestors, &mut sites);
        }
        let mut polynomial = false;
        let mut exponential = false;
        for (index, entry) in sites.iter().enumerate() {
            if site_is_move(entry, flags) {
                polynomial = true;
            }
            if site_has_exponential(&sites, index, flags) {
                exponential = true;
            }
        }
        if polynomial && !exponential {
            self.sink.emit_span(
                RuleScope::Both,
                "S8786",
                "Simplify this regular expression to reduce its runtime, as it has super-linear performance due to backtracking.",
                site.span,
            );
        }
    }
}

impl Visit<'_> for RedosCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'_>) {
        if let Expression::RegExpLiteral(literal) = it {
            self.check_site(&regex_site_from_literal(literal));
        }
        walk_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'_>) {
        if constructor_name(it) == Some("RegExp") {
            if let Some(site) = constructor_regex_site(&it.arguments) {
                self.check_site(&site);
            }
        }
        walk_new_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'_>) {
        if callee_name(it) == Some("RegExp") {
            if let Some(site) = constructor_regex_site(&it.arguments) {
                self.check_site(&site);
            }
        }
        walk_call_expression(self, it);
    }
}

/// Regex flags the analysis needs: `i` folds ASCII case in character
/// sets; `s` (dotAll) widens `.` to include line terminators.
#[derive(Debug, Clone, Copy)]
struct RegexFlags {
    insensitive: bool,
    dot_all: bool,
}

// ----- Character sets -----

/// A character set the subset can reason about exactly. `Any` models `.`
/// (and unknown-but-total sets); `Set`/`Complement` hold sorted inclusive
/// UTF-16 code-unit ranges. Uncomputable sets surface as `None` and are
/// resolved conservatively at each use site.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CharClass {
    Any,
    Set(Vec<(u32, u32)>),
    Complement(Vec<(u32, u32)>),
}

impl CharClass {
    fn empty() -> Self {
        Self::Set(Vec::new())
    }

    fn is_empty(&self) -> bool {
        matches!(self, Self::Set(ranges) if ranges.is_empty())
    }

    fn complement(&self) -> Self {
        match self {
            Self::Any => Self::empty(),
            Self::Set(ranges) => Self::Complement(ranges.clone()),
            Self::Complement(ranges) => Self::Set(ranges.clone()),
        }
    }

    fn intersects(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => true,
            (Self::Set(left), Self::Set(right)) => ranges_intersect(left, right),
            (Self::Set(set), Self::Complement(comp)) | (Self::Complement(comp), Self::Set(set)) => {
                !ranges_subset(set, comp)
            }
            (Self::Complement(left), Self::Complement(right)) => {
                !ranges_cover_all(&merge_ranges(left, right))
            }
        }
    }

    /// Whether every character of `self` is inside `other`.
    fn subset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (_, Self::Any) => true,
            (Self::Any, _) => false,
            (Self::Set(left), Self::Set(right)) => ranges_subset(left, right),
            (Self::Set(set), Self::Complement(comp)) => !ranges_intersect(set, comp),
            (Self::Complement(left), Self::Set(right)) => {
                ranges_cover_all(&merge_ranges(left, right))
            }
            (Self::Complement(left), Self::Complement(right)) => ranges_subset(right, left),
        }
    }

    fn union(self, other: Self) -> Self {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => Self::Any,
            (Self::Set(a), Self::Set(b)) => Self::Set(merge_ranges(&a, &b)),
            (Self::Complement(a), Self::Complement(b)) => {
                // ¬A ∪ ¬B = ¬(A ∩ B): keep only ranges present in both.
                Self::Complement(intersect_ranges(&a, &b))
            }
            (Self::Set(a), Self::Complement(b)) | (Self::Complement(b), Self::Set(a)) => {
                // S ∪ ¬C = ¬(C \ S).
                Self::Complement(subtract_ranges(&b, &a))
            }
        }
    }

    fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (Self::Any, other) | (other, Self::Any) => other,
            (Self::Set(a), Self::Set(b)) => Self::Set(intersect_ranges(&a, &b)),
            (Self::Set(a), Self::Complement(b)) | (Self::Complement(b), Self::Set(a)) => {
                Self::Set(subtract_ranges(&a, &b))
            }
            (Self::Complement(a), Self::Complement(b)) => Self::Complement(merge_ranges(&a, &b)),
        }
    }
}

fn ranges_intersect(left: &[(u32, u32)], right: &[(u32, u32)]) -> bool {
    left.iter()
        .any(|&(ls, le)| right.iter().any(|&(rs, re)| ls <= re && rs <= le))
}

fn ranges_subset(left: &[(u32, u32)], right: &[(u32, u32)]) -> bool {
    left.iter()
        .all(|&(ls, le)| right.iter().any(|&(rs, re)| rs <= ls && le <= re))
}

/// Whether the ranges cover the whole code-point space.
fn ranges_cover_all(ranges: &[(u32, u32)]) -> bool {
    let mut next = 0u32;
    for &(start, end) in ranges {
        if start > next {
            return false;
        }
        next = next.max(end.saturating_add(1));
    }
    next > 0x10FFFF
}

fn intersect_ranges(left: &[(u32, u32)], right: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for &(ls, le) in left {
        for &(rs, re) in right {
            let start = ls.max(rs);
            let end = le.min(re);
            if start <= end {
                out.push((start, end));
            }
        }
    }
    normalize_ranges(&mut out);
    out
}

/// `left \ right` over sorted inclusive ranges.
fn subtract_ranges(left: &[(u32, u32)], right: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut remaining = left.to_vec();
    for &(start, end) in right {
        let mut next = Vec::new();
        for &(ls, le) in &remaining {
            if le < start || ls > end {
                next.push((ls, le));
                continue;
            }
            if ls < start {
                next.push((ls, start - 1));
            }
            if le > end {
                next.push((end + 1, le));
            }
        }
        remaining = next;
    }
    remaining
}

fn merge_ranges(left: &[(u32, u32)], right: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut merged: Vec<(u32, u32)> = left.iter().chain(right.iter()).copied().collect();
    normalize_ranges(&mut merged);
    merged
}

fn normalize_ranges(ranges: &mut Vec<(u32, u32)>) {
    ranges.sort_unstable();
    if ranges.is_empty() {
        return;
    }
    let mut write = 0;
    for read in 1..ranges.len() {
        let (ws, we) = ranges[write];
        let (rs, re) = ranges[read];
        if rs <= we.saturating_add(1) {
            ranges[write] = (ws, we.max(re));
        } else {
            write += 1;
            ranges[write] = (rs, re);
        }
    }
    ranges.truncate(write + 1);
}

fn push_char(ranges: &mut Vec<(u32, u32)>, ch: char, insensitive: bool) {
    ranges.push((ch as u32, ch as u32));
    if insensitive && ch.is_ascii_alphabetic() {
        let folded = if ch.is_ascii_lowercase() {
            ch.to_ascii_uppercase()
        } else {
            ch.to_ascii_lowercase()
        };
        ranges.push((folded as u32, folded as u32));
    }
}

fn push_range(ranges: &mut Vec<(u32, u32)>, low: u32, high: u32, insensitive: bool) {
    ranges.push((low, high));
    if insensitive {
        // ASCII case-fold closure: enough for the campaign patterns and
        // conservative elsewhere (non-ASCII folds stay unexpanded).
        for ch in b'a'..=b'z' {
            let lower = ch as u32;
            let upper = (ch as char).to_ascii_uppercase() as u32;
            if (low..=high).contains(&lower) {
                ranges.push((upper, upper));
            }
            if (low..=high).contains(&upper) {
                ranges.push((lower, lower));
            }
        }
    }
}

fn shorthand_ranges(kind: ShorthandClass) -> Vec<(u32, u32)> {
    match kind {
        ShorthandClass::Digit => vec![(0x30, 0x39)],
        ShorthandClass::Word => vec![(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)],
        ShorthandClass::Space => vec![
            (0x09, 0x0D),
            (0x20, 0x20),
            (0xA0, 0xA0),
            (0x1680, 0x1680),
            (0x2000, 0x200A),
            (0x2028, 0x2029),
            (0x202F, 0x202F),
            (0x205F, 0x205F),
            (0x3000, 0x3000),
            (0xFEFF, 0xFEFF),
        ],
    }
}

/// The character set of one single-character atom. `None` when the atom is
/// not single-character-shaped or its set is uncomputable.
fn atom_class(node: &PatternNode, flags: RegexFlags) -> Option<CharClass> {
    match node {
        PatternNode::Literal { ch, .. } => {
            let mut ranges = Vec::new();
            push_char(&mut ranges, *ch, flags.insensitive);
            normalize_ranges(&mut ranges);
            Some(CharClass::Set(ranges))
        }
        PatternNode::CodeUnit { unit, .. } => {
            Some(CharClass::Set(vec![(*unit as u32, *unit as u32)]))
        }
        PatternNode::Dot => Some(if flags.dot_all {
            CharClass::Any
        } else {
            // `.` excludes line terminators without the `s` flag.
            CharClass::Complement(vec![(0x0A, 0x0D), (0x2028, 0x2029)])
        }),
        PatternNode::Class { negated, items, .. } => class_set(*negated, items, flags.insensitive),
        PatternNode::ClassEscape { negated, kind, .. } => {
            let ranges = shorthand_ranges(*kind);
            Some(if *negated {
                CharClass::Complement(ranges)
            } else {
                CharClass::Set(ranges)
            })
        }
        // `\p{...}` and backreferences can match (almost) anything; the
        // subset treats them as the total set.
        PatternNode::PropertyEscape { .. } | PatternNode::BackReference { .. } => {
            Some(CharClass::Any)
        }
        _ => None,
    }
}

fn class_set(negated: bool, items: &[ClassItem], insensitive: bool) -> Option<CharClass> {
    let mut positive = Vec::new();
    // `\D` inside a class contributes the complement of digits; several
    // negated shorthands intersect (\D\S = ¬(digit ∩ space)).
    let mut negated_ranges: Option<Vec<(u32, u32)>> = None;
    for item in items {
        match item {
            ClassItem::Char { ch, .. } => push_char(&mut positive, *ch, insensitive),
            ClassItem::CodeUnit { unit, .. } => positive.push((*unit as u32, *unit as u32)),
            ClassItem::CodeUnitRange { low, high, .. } => {
                push_range(&mut positive, *low as u32, *high as u32, insensitive);
            }
            ClassItem::Range { low, high, .. } => {
                push_range(&mut positive, *low as u32, *high as u32, insensitive);
            }
            ClassItem::Shorthand {
                negated: item_negated,
                kind,
                ..
            } => {
                let ranges = shorthand_ranges(*kind);
                if *item_negated {
                    negated_ranges = Some(match negated_ranges {
                        None => ranges,
                        Some(acc) => intersect_ranges(&acc, &ranges),
                    });
                } else {
                    positive.extend(ranges);
                }
            }
            // A property escape widens the class to (almost) everything.
            ClassItem::Property { .. } => return Some(CharClass::Any),
        }
    }
    normalize_ranges(&mut positive);
    let base = match negated_ranges {
        None => CharClass::Set(positive),
        // ¬N ∪ P = ¬(N \ P).
        Some(negated) => CharClass::Complement(subtract_ranges(&negated, &positive)),
    };
    Some(if negated { base.complement() } else { base })
}

// ----- Set computations over the pattern tree -----

fn as_refs(sequence: &[PatternNode]) -> Vec<&PatternNode> {
    sequence.iter().collect()
}

/// Characters that can pump `node`: `node` can match `c^j` for some
/// `j >= 1`. `None` when uncomputable; the empty set when computable but
/// nothing pumps.
fn pump_set(node: &PatternNode, flags: RegexFlags) -> Option<CharClass> {
    match node {
        PatternNode::Group {
            kind, alternatives, ..
        } => {
            if kind.is_lookaround() {
                return Some(CharClass::empty());
            }
            let mut result = Some(CharClass::empty());
            for alternative in alternatives {
                match (result.take(), seq_pump(&as_refs(alternative), flags)) {
                    (Some(acc), Some(set)) => result = Some(acc.union(set)),
                    (acc, None) => result = acc,
                    (None, _) => result = None,
                }
            }
            result
        }
        PatternNode::Quantified { node, max, .. } => {
            if *max == Some(0) {
                Some(CharClass::empty())
            } else {
                pump_set(node, flags)
            }
        }
        PatternNode::Anchor { .. } => Some(CharClass::empty()),
        _ => atom_class(node, flags),
    }
}

/// Characters that can pump a whole sequence: every element that cannot
/// match empty must pump `c`, and at least one element must pump `c`.
fn seq_pump(sequence: &[&PatternNode], flags: RegexFlags) -> Option<CharClass> {
    let mut union = CharClass::empty();
    let mut required: Option<CharClass> = None;
    for node in sequence {
        let pump = pump_set(node, flags);
        if let Some(set) = &pump {
            union = union.union(set.clone());
        }
        if !node_can_match_empty(node) {
            let contribution = pump.unwrap_or_else(CharClass::empty);
            required = Some(match required {
                None => contribution,
                Some(acc) => acc.intersect(contribution),
            });
        }
    }
    Some(match required {
        None => union,
        Some(req) => union.intersect(req),
    })
}

/// First-character set of a sequence, skipping elements that can match
/// empty. `None` when uncomputable.
fn seq_first(sequence: &[&PatternNode], flags: RegexFlags) -> Option<CharClass> {
    let mut result = CharClass::empty();
    for node in sequence {
        result = result.union(first_set(node, flags)?);
        if !node_can_match_empty(node) {
            return Some(result);
        }
    }
    Some(result)
}

/// Last-character set of a sequence (for lookbehind bodies).
fn seq_last(sequence: &[&PatternNode], flags: RegexFlags) -> Option<CharClass> {
    let mut result = CharClass::empty();
    for node in sequence.iter().rev() {
        result = result.union(last_set(node, flags)?);
        if !node_can_match_empty(node) {
            return Some(result);
        }
    }
    Some(result)
}

fn first_set(node: &PatternNode, flags: RegexFlags) -> Option<CharClass> {
    match node {
        PatternNode::Group { alternatives, .. } => {
            let mut result = CharClass::empty();
            for alternative in alternatives {
                result = result.union(seq_first(&as_refs(alternative), flags)?);
            }
            Some(result)
        }
        PatternNode::Quantified { node, max, .. } => {
            if *max == Some(0) {
                Some(CharClass::empty())
            } else {
                first_set(node, flags)
            }
        }
        PatternNode::Anchor { .. } => Some(CharClass::empty()),
        _ => atom_class(node, flags),
    }
}

fn last_set(node: &PatternNode, flags: RegexFlags) -> Option<CharClass> {
    match node {
        PatternNode::Group { alternatives, .. } => {
            let mut result = CharClass::empty();
            for alternative in alternatives {
                result = result.union(seq_last(&as_refs(alternative), flags)?);
            }
            Some(result)
        }
        PatternNode::Quantified { node, max, .. } => {
            if *max == Some(0) {
                Some(CharClass::empty())
            } else {
                last_set(node, flags)
            }
        }
        PatternNode::Anchor { .. } => Some(CharClass::empty()),
        _ => atom_class(node, flags),
    }
}

// ----- Quantified-site collection -----

/// One `Quantified` node with the match-order context needed for the
/// subset analysis.
struct QuantSite<'a> {
    /// The quantified node itself.
    node: &'a PatternNode,
    /// Elements before it in match order (nearest last), including the
    /// enclosing groups' prefixes.
    prefix: Vec<&'a PatternNode>,
    /// Elements after it in match order, including enclosing quantified
    /// nodes (a further iteration) and enclosing groups' continuations.
    continuation: Vec<&'a PatternNode>,
    /// Enclosing `Quantified` nodes (site indices), innermost last.
    ancestors: Vec<usize>,
}

fn collect_sites<'a>(
    sequence: &'a [PatternNode],
    prefix: &[&'a PatternNode],
    tail: &[&'a PatternNode],
    ancestors: &mut Vec<usize>,
    sites: &mut Vec<QuantSite<'a>>,
) {
    for (index, node) in sequence.iter().enumerate() {
        let mut node_prefix: Vec<&PatternNode> = prefix.to_vec();
        node_prefix.extend(&sequence[..index]);
        let mut node_tail: Vec<&PatternNode> = sequence[index + 1..].iter().collect();
        node_tail.extend(tail.iter().copied());
        match node {
            PatternNode::Quantified { node: element, .. } => {
                let site_index = sites.len();
                sites.push(QuantSite {
                    node,
                    prefix: node_prefix.clone(),
                    continuation: node_tail.clone(),
                    ancestors: ancestors.clone(),
                });
                // Inside the repeated element the enclosing quantifier is
                // a further iteration of the continuation; the prefix is
                // the element's own prefix plus the outer prefix.
                let mut inner_tail: Vec<&PatternNode> = vec![node];
                inner_tail.extend(node_tail.iter().copied());
                ancestors.push(site_index);
                collect_element(element, &node_prefix, &inner_tail, ancestors, sites);
                ancestors.pop();
            }
            PatternNode::Group {
                kind, alternatives, ..
            } => {
                for alternative in alternatives {
                    if kind.is_lookaround() {
                        // Lookaround bodies are zero-width: their
                        // continuation is body-local and their prefix does
                        // not include outer elements.
                        collect_sites(alternative, &[], &[], ancestors, sites);
                    } else {
                        collect_sites(alternative, &node_prefix, &node_tail, ancestors, sites);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Recurse into a quantified element: group alternatives each form their
/// own sequence; anything else is a single-element sequence.
fn collect_element<'a>(
    element: &'a PatternNode,
    prefix: &[&'a PatternNode],
    tail: &[&'a PatternNode],
    ancestors: &mut Vec<usize>,
    sites: &mut Vec<QuantSite<'a>>,
) {
    match element {
        PatternNode::Group {
            kind, alternatives, ..
        } if !kind.is_lookaround() => {
            for alternative in alternatives {
                collect_sites(alternative, prefix, tail, ancestors, sites);
            }
        }
        _ => collect_sites(
            std::slice::from_ref(element),
            prefix,
            tail,
            ancestors,
            sites,
        ),
    }
}

// ----- Move / exponential evaluation -----

/// Whether the quantified node is unbounded: `max` open and the element
/// pumpable, or the element itself unbounded.
fn node_unbounded(node: &PatternNode, flags: RegexFlags) -> bool {
    let PatternNode::Quantified {
        node: element, max, ..
    } = node
    else {
        return false;
    };
    if *max == Some(0) {
        return false;
    }
    if max.is_none() && pump_set(element, flags).is_some_and(|set| !set.is_empty()) {
        return true;
    }
    node_unbounded(element, flags)
}

/// The `scslre` "Move" subset: an unbounded quantified element reachable
/// at O(n) start positions whose continuation can reject a pumped run.
fn site_is_move(site: &QuantSite<'_>, flags: RegexFlags) -> bool {
    let PatternNode::Quantified { node: element, .. } = site.node else {
        return false;
    };
    if !node_unbounded(site.node, flags) {
        return false;
    }
    let Some(pump) = pump_set(element, flags) else {
        return false;
    };
    if pump.is_empty() {
        return false;
    }
    if !prefix_unbounded(&site.prefix, &pump, flags) {
        return false;
    }
    continuation_rejects(&site.continuation, &pump, flags)
}

/// Whether any enclosing unbounded quantified node overlaps the pump set
/// with a rejecting continuation — the exponential case the reference
/// rule suppresses.
fn site_has_exponential(sites: &[QuantSite<'_>], index: usize, flags: RegexFlags) -> bool {
    let site = &sites[index];
    let PatternNode::Quantified { node: element, .. } = site.node else {
        return false;
    };
    if !node_unbounded(site.node, flags) {
        return false;
    }
    let Some(pump) = pump_set(element, flags) else {
        return false;
    };
    if pump.is_empty() {
        return false;
    }
    site.ancestors.iter().any(|&ancestor_index| {
        let ancestor = &sites[ancestor_index];
        let PatternNode::Quantified {
            node: ancestor_element,
            max: ancestor_max,
            ..
        } = ancestor.node
        else {
            return false;
        };
        if ancestor_max.is_some() {
            return false;
        }
        pump_set(ancestor_element, flags).is_some_and(|set| {
            set.intersects(&pump) && continuation_rejects(&ancestor.continuation, &pump, flags)
        })
    })
}

/// Whether the quantified site can start at O(n) positions on a run of
/// pump characters: either the prefix matches empty at every position, or
/// the prefix itself can match a run of pump characters.
fn prefix_unbounded(prefix: &[&PatternNode], pump: &CharClass, flags: RegexFlags) -> bool {
    if prefix
        .iter()
        .all(|element| prefix_element_matches_empty(element, pump, flags))
    {
        return true;
    }
    prefix_viable_set(prefix, pump, flags).is_some_and(|viable| !viable.is_empty())
}

/// Whether `element` can match empty at a pump-run position: it must be
/// empty-capable and every assertion inside must pass on the run.
fn prefix_element_matches_empty(
    element: &PatternNode,
    pump: &CharClass,
    flags: RegexFlags,
) -> bool {
    node_can_match_empty(element) && assertions_pass_on_run(element, pump, flags)
}

/// Whether every assertion inside `element` passes at a pump-run
/// position. Anchors never do; lookarounds pass by boundary polarity.
fn assertions_pass_on_run(element: &PatternNode, pump: &CharClass, flags: RegexFlags) -> bool {
    match element {
        PatternNode::Anchor { .. } => false,
        PatternNode::Group {
            kind, alternatives, ..
        } if kind.is_lookaround() => lookaround_passes_on_run(kind, alternatives, pump, flags),
        PatternNode::Group { alternatives, .. } => alternatives.iter().all(|alt| {
            alt.iter()
                .all(|node| assertions_pass_on_run(node, pump, flags))
        }),
        PatternNode::Quantified { node, .. } => assertions_pass_on_run(node, pump, flags),
        _ => true,
    }
}

/// Whether a lookaround passes at a pump-run position: positive
/// lookarounds pass when the pump character can appear at the checked
/// boundary or the body matches empty; negated ones pass when it cannot.
fn lookaround_passes_on_run(
    kind: &GroupKind,
    alternatives: &[Vec<PatternNode>],
    pump: &CharClass,
    flags: RegexFlags,
) -> bool {
    let Some((boundary, negated)) = lookaround_boundary(kind, alternatives, flags) else {
        return false;
    };
    let body_empty = alternatives.iter().any(|alt| sequence_can_match_empty(alt));
    match boundary {
        Some(set) => {
            if negated {
                !body_empty && !pump.intersects(&set)
            } else {
                body_empty || pump.intersects(&set)
            }
        }
        None => false,
    }
}

/// The pump characters for which the whole prefix can match a non-empty
/// run: every required element must pump the character and every
/// assertion must pass on the run. `None` when uncomputable.
fn prefix_viable_set(
    prefix: &[&PatternNode],
    pump: &CharClass,
    flags: RegexFlags,
) -> Option<CharClass> {
    let mut viable = pump.clone();
    for element in prefix {
        if !node_can_match_empty(element) {
            viable = viable.intersect(pump_set(element, flags)?);
        }
        viable = apply_assertion_constraints(element, viable, flags);
        if viable.is_empty() {
            return Some(viable);
        }
    }
    Some(viable)
}

/// Narrows `viable` by the assertions inside `element`: anchors empty it;
/// lookarounds constrain it by their boundary set.
fn apply_assertion_constraints(
    element: &PatternNode,
    viable: CharClass,
    flags: RegexFlags,
) -> CharClass {
    match element {
        PatternNode::Anchor { .. } => CharClass::empty(),
        PatternNode::Group {
            kind, alternatives, ..
        } if kind.is_lookaround() => lookaround_constraint(kind, alternatives, viable, flags),
        PatternNode::Group { alternatives, .. } => {
            // A group constrains the run only through assertions shared by
            // every alternative; per-alternative assertions are handled
            // conservatively by requiring all of them to pass.
            let mut result = viable;
            for alternative in alternatives {
                for node in alternative {
                    result = apply_assertion_constraints(node, result, flags);
                }
            }
            result
        }
        PatternNode::Quantified { node, .. } => apply_assertion_constraints(node, viable, flags),
        _ => viable,
    }
}

/// The viable-set contribution of one lookaround: positive lookarounds
/// keep pump characters their boundary accepts, negated ones keep the
/// complement; an empty-capable body disables the constraint.
fn lookaround_constraint(
    kind: &GroupKind,
    alternatives: &[Vec<PatternNode>],
    viable: CharClass,
    flags: RegexFlags,
) -> CharClass {
    let Some((boundary, negated)) = lookaround_boundary(kind, alternatives, flags) else {
        return CharClass::empty();
    };
    let body_empty = alternatives.iter().any(|alt| sequence_can_match_empty(alt));
    match boundary {
        Some(set) => {
            if negated {
                if body_empty {
                    CharClass::empty()
                } else {
                    viable.intersect(set.complement())
                }
            } else if body_empty {
                viable
            } else {
                viable.intersect(set)
            }
        }
        None => CharClass::empty(),
    }
}

/// Whether the continuation can reject a run of pump characters: some
/// required element fails on the pump set.
fn continuation_rejects(
    continuation: &[&PatternNode],
    pump: &CharClass,
    flags: RegexFlags,
) -> bool {
    continuation.iter().any(|element| {
        matches!(
            continuation_step(element, pump, flags),
            ContinuationStep::Reject
        )
    })
}

enum ContinuationStep {
    /// The element can reject a pumped run.
    Reject,
    /// The element consumes pump characters or can match empty; keep
    /// scanning.
    Pass,
}

fn continuation_step(
    element: &PatternNode,
    pump: &CharClass,
    flags: RegexFlags,
) -> ContinuationStep {
    match element {
        // `\B` passes at every position of a uniform run; `^`, `$`, and
        // `\b` can reject mid-run.
        PatternNode::Anchor { kind, .. } => {
            if matches!(kind, AnchorKind::NotWordBoundary) {
                ContinuationStep::Pass
            } else {
                ContinuationStep::Reject
            }
        }
        PatternNode::Group {
            kind, alternatives, ..
        } if kind.is_lookaround() => {
            if lookaround_rejects(kind, alternatives, pump, flags) {
                ContinuationStep::Reject
            } else {
                ContinuationStep::Pass
            }
        }
        _ => {
            if node_can_match_empty(element) {
                return ContinuationStep::Pass;
            }
            match pump_set(element, flags) {
                Some(set) if pump.subset_of(&set) => ContinuationStep::Pass,
                Some(_) => ContinuationStep::Reject,
                None => ContinuationStep::Pass,
            }
        }
    }
}

/// Whether a lookaround rejects a pumped run: positive lookarounds reject
/// when the pump character cannot appear at the checked boundary; negated
/// ones reject when it always can (or the body matches empty).
fn lookaround_rejects(
    kind: &GroupKind,
    alternatives: &[Vec<PatternNode>],
    pump: &CharClass,
    flags: RegexFlags,
) -> bool {
    let Some((boundary, negated)) = lookaround_boundary(kind, alternatives, flags) else {
        return true;
    };
    let body_empty = alternatives.iter().any(|alt| sequence_can_match_empty(alt));
    match boundary {
        Some(set) => {
            if negated {
                body_empty || pump.subset_of(&set)
            } else {
                !body_empty && !pump.intersects(&set)
            }
        }
        None => true,
    }
}

/// The boundary character set a lookaround checks (first set for
/// lookaheads, last set for lookbehinds) plus its polarity.
fn lookaround_boundary(
    kind: &GroupKind,
    alternatives: &[Vec<PatternNode>],
    flags: RegexFlags,
) -> Option<(Option<CharClass>, bool)> {
    let (negated, behind) = match kind {
        GroupKind::Lookahead { negated } => (*negated, false),
        GroupKind::Lookbehind { negated } => (*negated, true),
        _ => return None,
    };
    let boundary = if behind {
        alternatives_last(alternatives, flags)
    } else {
        alternatives_first(alternatives, flags)
    };
    Some((boundary, negated))
}

fn alternatives_first(alternatives: &[Vec<PatternNode>], flags: RegexFlags) -> Option<CharClass> {
    let mut result = CharClass::empty();
    for alternative in alternatives {
        result = result.union(seq_first(&as_refs(alternative), flags)?);
    }
    Some(result)
}

fn alternatives_last(alternatives: &[Vec<PatternNode>], flags: RegexFlags) -> Option<CharClass> {
    let mut result = CharClass::empty();
    for alternative in alternatives {
        result = result.union(seq_last(&as_refs(alternative), flags)?);
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s8786_flags_pinned_campaign_anchors() {
        // Pinned anchors: express examples/markdown/index.js:20 and
        // examples/view-constructor/index.js:17 (`\{([^}]+)\}`), exceljs
        // lib/doc/cell.js:789 (range/cell patterns) and
        // lib/utils/col-cache.js:217 (sheet-name prefix).
        let source = r#"
var html = marked.parse(str).replace(/\{([^}]+)\}/g, function(_, name){
  return escapeHtml(options[name] || '');
});
html = html.replace(/\{([^}]+)\}/g, function(_, name){
  return options[name] || '';
});
const ranges = this.formula.match(/([a-zA-Z0-9]+!)?[A-Z]{1,3}\d{1,4}:[A-Z]{1,3}\d{1,4}/g);
const cells = this.formula
  .replace(/([a-zA-Z0-9]+!)?[A-Z]{1,3}\d{1,4}:[A-Z]{1,3}\d{1,4}/g, '')
  .match(/([a-zA-Z0-9]+!)?[A-Z]{1,3}\d{1,4}/g);
const groups = value.match(/(?:(?:(?:'((?:[^']|'')*)')|([^'^ !]*))!)?(.*)/);
"#;
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S8786"), 6);
    }

    #[test]
    fn s8786_flags_move_shape_variants() {
        // Unbounded quantifier at an unbounded position with a rejecting
        // continuation: disjoint required follower, `$`, `\b`, lookahead.
        let source = r#"
const a = /a+b/;
const b = /\w+\d+/;
const c = /[a-z]+[0-9]+/;
const d = /\s*:/;
const e = /.*x/;
const f = /a+$/;
const g = /a+\b/;
const h = /a+(?=b)/;
const i = /a*ab/;
const j = /a{3,}b/;
const k = /(a+)?b/;
const l = /a+?b/;
const m = /(a|b)+c/;
const n = /a+b|c/;
"#;
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S8786"), 14);
    }

    #[test]
    fn s8786_flags_regexp_constructor_sites() {
        let source = r#"
const a = new RegExp("a+b");
const b = RegExp("\\w+\\d+", "g");
const c = new RegExp(`[a-z]+[0-9]+`);
"#;
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S8786"), 3);
    }

    #[test]
    fn s8786_suppresses_exponential_only_patterns() {
        // Nested unbounded quantifiers with a rejecting continuation are
        // exponential in the reference analysis; SonarJS drops literals
        // whose reports are all exponential.
        let source = r#"
const a = /(a+)+b/;
const b = /(a*)*b/;
const c = /(\w+)+\d/;
const d = /(a+|b)+c/;
const e = /(a*b*)+c/;
"#;
        assert_eq!(count_key(&js_keys(source), "javascript:S8786"), 0);
    }

    #[test]
    fn s8786_clean_controls() {
        // Anchored, sticky, bounded, disjoint-prefix, never-rejecting, and
        // multi-char-unit patterns stay silent.
        let source = r#"
const a = /^a+b/;
const b = /a+b/y;
const c = /\d+/;
const d = /a+a+/;
const e = /\d+\w+/;
const f = /a{3,5}b/;
const g = /ba+b/;
const h = /x(a+b)/;
const i = /(ab)+c/;
const j = /foo\w*bar/;
const k = /a+(?!b)/;
const l = /(?=x)a+b/;
const m = /a?b/;
const n = /x*y*z*/;
const o = /[A-Z]{1,3}\d{1,4}/;
const p = /a+\d*/;
const q = /\{([^}]+)\}/y;
const r = /^\{([^}]+)\}$/;
"#;
        assert_eq!(count_key(&js_keys(source), "javascript:S8786"), 0);
    }

    #[test]
    fn s8786_reports_in_both_languages() {
        let source = "const re = /a+b/;\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S8786"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S8786"), 1);
    }
}
