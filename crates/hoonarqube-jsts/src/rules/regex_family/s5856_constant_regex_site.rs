// Rule module s5856_constant_regex_site (generated).
use crate::engine::pattern_parser::{
    AnchorKind, ClassItem, GraphemeComponentKind, ParsedRegex, PatternNode, RegexSite,
    ShorthandClass, contains_unbounded_quantifier, grapheme_component_kind, node_can_match_empty,
    parse_regex_pattern, pattern_complexity, walk_pattern_nodes,
};
use crate::rules::regex_family::collectors::{
    REGEX_COMPLEXITY_THRESHOLD, emit_concise_class_rewrite, emit_space_runs_in_sequence,
    flag_single_char_alternation, for_every_sequence, is_bare_control_character,
};
use crate::support::{IssueSink, RuleScope};

// ----- Shared-walker rule drivers -----

/// Runs every pattern-text rule over one constant regex site. The raw-text
/// scans also run on patterns the mini parser rejects; everything
/// structure-based needs a successful parse.
pub(crate) fn check_constant_regex_site(sink: &mut IssueSink, site: &RegexSite) {
    if !valid_flags(&site.flags) {
        sink.emit_span(
            RuleScope::Both,
            "S5856",
            "Invalid regular expression flags.",
            site.span,
        );
        return;
    }
    check_control_characters(sink, site);
    check_unicode_constructs_without_u_flag(sink, site);
    let unicode_mode = site.has_flag('u') || site.has_flag('v');
    let Ok(parsed) = parse_regex_pattern(&site.pattern, unicode_mode) else {
        // Upstream embeds the validator's detail text; the subset reports
        // statically because the mini parser carries no error messages.
        sink.emit_span(
            RuleScope::Both,
            "S5856",
            "Invalid regular expression.",
            site.whole_pattern_span(),
        );
        return;
    };
    check_empty_character_class(sink, site, &parsed);
    check_empty_alternatives(sink, site, &parsed);
    check_empty_groups(sink, site, &parsed);
    check_duplicate_class_members(sink, site, &parsed);
    check_single_member_class(sink, site, &parsed);
    check_concise_shapes(sink, site, &parsed);
    check_space_runs(sink, site, &parsed);
    check_empty_string_repetition(sink, site, &parsed);
    check_pointless_reluctant_quantifier(sink, site, &parsed);
    check_single_char_alternation(sink, site, &parsed);
    check_anchor_precedence(sink, site, &parsed);
    check_misleading_class_characters(sink, site, &parsed);
    check_regex_complexity(sink, site, &parsed);
    check_exponential_backtracking(sink, site, &parsed);
}

fn valid_flags(flags: &str) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    flags.chars().all(|flag| {
        matches!(flag, 'd' | 'g' | 'i' | 'm' | 's' | 'u' | 'v' | 'y') && seen.insert(flag)
    }) && !(seen.contains(&'u') && seen.contains(&'v'))
}

/// `S6324`: bare C0 control characters other than the tab/newline
/// conventions.
fn check_control_characters(sink: &mut IssueSink, site: &RegexSite) {
    for (offset, ch) in site.pattern.char_indices() {
        if is_bare_control_character(ch) {
            sink.emit_span(
                RuleScope::Both,
                "S6324",
                "Remove this control character.",
                site.sub_span(offset, offset + ch.len_utf8()),
            );
        }
    }
}

/// `S5867`: `\p{…}` / `\P{…}` / `\u{…}` without the `u` (or `v`) flag
/// behave nothing like their intent.
fn check_unicode_constructs_without_u_flag(sink: &mut IssueSink, site: &RegexSite) {
    if site.has_flag('u') || site.has_flag('v') {
        return;
    }
    for construct in ["\\p{", "\\P{", "\\u{"] {
        let mut search_from = 0;
        while let Some(found) = site.pattern[search_from..].find(construct) {
            let start = search_from + found;
            let end = start + construct.len();
            sink.emit_span(
                RuleScope::Both,
                "S5867",
                "Enable the 'u' flag for this regex using Unicode constructs.",
                site.span,
            );
            search_from = end;
        }
    }
}

/// `S2639`: `[]` never matches anything and `[^]` matches everything —
/// both are defects.
fn check_empty_character_class(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Class {
                items, start, end, ..
            } = node
                && items.is_empty()
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S2639",
                    "Rework this empty character class that doesn't match anything.",
                    site.sub_span(*start, *end),
                );
            }
        });
    }
}

/// `S6323`: an alternation branch that can never participate (`|`, `(a|)`).
fn check_empty_alternatives(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for pos in &parsed.empty_branch_positions {
        let start = pos.saturating_sub(1);
        sink.emit_span(
            RuleScope::Both,
            "S6323",
            "Remove this empty alternative.",
            site.sub_span(start, *pos),
        );
    }
}

/// `S6331`: a wholly empty group `()` / `(?:)`.
fn check_empty_groups(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Group {
                kind,
                alternatives,
                start,
                end,
            } = node
                && !kind.is_lookaround()
                && alternatives.len() == 1
                && alternatives[0].is_empty()
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S6331",
                    "Remove this empty group.",
                    site.sub_span(*start, *end),
                );
            }
        });
    }
}

/// `S5869`: overlapping members inside `[...]`. Character ranges,
/// shorthands, and ASCII case folding are represented as small unions of
/// code-point ranges so each later member can be compared with prior ones.
fn check_duplicate_class_members(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    let unicode_mode = site.has_flag('u') || site.has_flag('v');
    let ignore_case = site.has_flag('i');
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            let PatternNode::Class { items, end, .. } = node else {
                return;
            };
            let mut seen: Vec<(RegexCharacterSet, usize, usize)> = Vec::new();
            for (index, item) in items.iter().enumerate() {
                let Some(set) = class_item_set(item, unicode_mode, ignore_case) else {
                    continue;
                };
                let next = items.get(index + 1);
                let (start, end) = class_item_span(site, item, next, *end);
                let overlap = seen
                    .iter()
                    .find(|(previous, _, _)| previous.intersects(&set))
                    .map(|(_, start, end)| (*start, *end));
                if let Some((start, end)) = overlap {
                    sink.emit_span(
                        RuleScope::Both,
                        "S5869",
                        "Remove duplicates in this character class.",
                        site.sub_span(start, end),
                    );
                }
                seen.push((set, start, end));
            }
        });
    }
}

const MAX_REGEX_CODE_POINT: u32 = 0x10_FFFF;

#[derive(Debug)]
struct RegexCharacterSet {
    ranges: Vec<(u32, u32)>,
}

impl RegexCharacterSet {
    fn intersects(&self, other: &Self) -> bool {
        self.ranges.iter().any(|&(left, left_end)| {
            other
                .ranges
                .iter()
                .any(|&(right, right_end)| left <= right_end && right <= left_end)
        })
    }

    fn add_ascii_case_variants(&mut self) {
        let original = self.ranges.clone();
        for (low, high) in original {
            let high = high.min(0x7F);
            if low > high {
                continue;
            }
            for code_point in low..=high {
                let Some(ch) = char::from_u32(code_point) else {
                    continue;
                };
                if ch.is_ascii_alphabetic() {
                    let lower = u32::from(ch.to_ascii_lowercase());
                    let upper = u32::from(ch.to_ascii_uppercase());
                    self.ranges.push((lower, lower));
                    self.ranges.push((upper, upper));
                }
            }
        }
    }
}

fn class_item_set(
    item: &ClassItem,
    unicode_mode: bool,
    ignore_case: bool,
) -> Option<RegexCharacterSet> {
    let mut set = match item {
        ClassItem::Char { ch, .. } => RegexCharacterSet {
            ranges: vec![(u32::from(*ch), u32::from(*ch))],
        },
        ClassItem::Range { low, high, .. } => RegexCharacterSet {
            ranges: vec![(u32::from(*low), u32::from(*high))],
        },
        ClassItem::Shorthand { negated, kind, .. } => RegexCharacterSet {
            ranges: shorthand_ranges(*kind, *negated, unicode_mode, ignore_case),
        },
        ClassItem::Property { .. } => return None,
    };
    if ignore_case {
        set.add_ascii_case_variants();
    }
    Some(set)
}

fn shorthand_ranges(
    kind: ShorthandClass,
    negated: bool,
    unicode_mode: bool,
    ignore_case: bool,
) -> Vec<(u32, u32)> {
    let mut ranges = match kind {
        ShorthandClass::Digit => vec![(u32::from(b'0'), u32::from(b'9'))],
        ShorthandClass::Word => vec![
            (u32::from(b'0'), u32::from(b'9')),
            (u32::from(b'A'), u32::from(b'Z')),
            (u32::from(b'_'), u32::from(b'_')),
            (u32::from(b'a'), u32::from(b'z')),
        ],
        ShorthandClass::Space => vec![(0x09, 0x0D), (0x20, 0x20)],
    };
    if matches!(kind, ShorthandClass::Space) {
        ranges.extend([
            (0xA0, 0xA0),
            (0x1680, 0x1680),
            (0x2000, 0x200A),
            (0x2028, 0x2029),
            (0x202F, 0x202F),
            (0x205F, 0x205F),
            (0x3000, 0x3000),
            (0xFEFF, 0xFEFF),
        ]);
    }
    if unicode_mode && ignore_case && matches!(kind, ShorthandClass::Word) {
        ranges.extend([(0x017F, 0x017F), (0x212A, 0x212A)]);
    }
    if negated {
        complement_ranges(&ranges)
    } else {
        ranges
    }
}

fn complement_ranges(ranges: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut complement = Vec::new();
    let mut next = 0;
    for &(low, high) in ranges {
        if next < low {
            complement.push((next, low - 1));
        }
        next = high.saturating_add(1);
    }
    if next <= MAX_REGEX_CODE_POINT {
        complement.push((next, MAX_REGEX_CODE_POINT));
    }
    complement
}

fn class_item_start(site: &RegexSite, item: &ClassItem) -> usize {
    let position = match item {
        ClassItem::Char { pos, .. }
        | ClassItem::Shorthand { pos, .. }
        | ClassItem::Property { pos, .. } => *pos,
        ClassItem::Range { start, .. } => *start,
    };
    if position > 0 && site.pattern.as_bytes().get(position - 1) == Some(&b'\\') {
        position - 1
    } else {
        position
    }
}

fn class_item_span(
    site: &RegexSite,
    item: &ClassItem,
    next: Option<&ClassItem>,
    class_end: usize,
) -> (usize, usize) {
    if let ClassItem::Char { ch, pos } = item {
        // Preserve the historical duplicate span for literal characters.
        (*pos, *pos + ch.len_utf8())
    } else {
        let start = class_item_start(site, item);
        let end = next.map_or(class_end.saturating_sub(1), |next_item| {
            class_item_start(site, next_item)
        });
        (start, end)
    }
}

/// `S6397`: a safe singleton class (`[a]`, `[\d]`, or `[\p{L}]`) asserts no
/// more than the same atom. Negated classes, ranges, and regex metacharacters
/// must stay classes because replacing them would change the pattern.
fn check_single_member_class(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Class {
                negated,
                items,
                start,
                end,
                ..
            } = node
                && !*negated
                && items.len() == 1
                && singleton_class_item_is_safe(site, &items[0])
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S6397",
                    "Replace this character class by the character itself.",
                    site.sub_span(*start, *end),
                );
            }
        });
    }
}

fn singleton_class_item_is_safe(site: &RegexSite, item: &ClassItem) -> bool {
    match item {
        ClassItem::Char { ch, pos } => singleton_char_is_safe(site, *ch, *pos),
        ClassItem::Shorthand { .. } => true,
        ClassItem::Property { .. } => site.has_flag('u') || site.has_flag('v'),
        ClassItem::Range { .. } => false,
    }
}

fn singleton_char_is_safe(site: &RegexSite, ch: char, pos: usize) -> bool {
    // Without `u`/`v`, a non-BMP class member is matched as UTF-16 code
    // units, while the replacement atom would match the full scalar.
    if !site.has_flag('u') && !site.has_flag('v') && ch.len_utf16() > 1 {
        return false;
    }
    if "[{(.?+*$^\\|)]}/".contains(ch) {
        return false;
    }
    if pos == 0 || site.pattern.as_bytes().get(pos - 1) != Some(&b'\\') {
        return true;
    }
    site.pattern
        .as_bytes()
        .get(pos)
        .is_none_or(|byte| !matches!(*byte, b'b' | b'B' | b'k' | b'1'..=b'9'))
}

/// `S6353`: `{1}` / `{1,1}` quantifiers and duplicate-only classes with a
/// concise rewrite.
fn check_concise_shapes(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| match node {
            PatternNode::Quantified {
                node,
                min,
                max,
                verbose,
                pos,
                ..
            } if *min == 1 && *max == Some(1) => {
                sink.emit_span(
                    RuleScope::Both,
                    "S6353",
                    &format!("Remove redundant quantifier {verbose}."),
                    site.sub_span(node_start(node).unwrap_or(*pos), pos + verbose.len()),
                );
            }
            PatternNode::Class {
                items, start, end, ..
            } => {
                emit_concise_class_rewrite(sink, site, items, *start, *end);
            }
            _ => {}
        });
    }
}

/// `S6326`: runs of two or more spaces outside character classes.
fn check_space_runs(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        for_every_sequence(alternative, &mut |sequence| {
            emit_space_runs_in_sequence(sink, site, sequence);
        });
    }
}

/// `S5842`: a quantified body that can match the empty string can be
/// repeated without consuming input. The body's nullability is independent
/// of the outer quantifier minimum (`(a?)*` and `(a?)+` are both reported).
fn check_empty_string_repetition(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Quantified {
                node: target, pos, ..
            } = node
                && node_can_match_empty(target)
            {
                let start = node_start(target).unwrap_or(*pos);
                sink.emit_span(
                    RuleScope::Both,
                    "S5842",
                    "Rework this part of the regex to not match the empty string.",
                    site.sub_span(start, *pos),
                );
            }
        });
    }
}

fn emit_pointless_reluctant_quantifier(
    sink: &mut IssueSink,
    site: &RegexSite,
    quantifier: &PatternNode,
) {
    let PatternNode::Quantified {
        node,
        min,
        pos,
        verbose,
        ..
    } = quantifier
    else {
        return;
    };
    let plural = if *min == 1 { "" } else { "s" };
    sink.emit_span(
        RuleScope::Both,
        "S6019",
        &format!(
            "Fix this reluctant quantifier that will only ever match {min} repetition{plural}."
        ),
        site.sub_span(node_start(node).unwrap_or(*pos), *pos + verbose.len()),
    );
}

/// `S6019`: a reluctant quantifier at the end of a sequence is pointless.
/// A required suffix keeps laziness meaningful; an optional suffix or an end
/// assertion does not.
fn check_pointless_reluctant_quantifier(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
    for alternative in &parsed.alternatives {
        check_reluctant_sequence(sink, site, alternative);
    }
}

fn check_reluctant_sequence(sink: &mut IssueSink, site: &RegexSite, sequence: &[PatternNode]) {
    let Some(last) = sequence.last() else {
        return;
    };
    if matches!(last, PatternNode::Quantified { greedy: false, .. }) {
        emit_pointless_reluctant_quantifier(sink, site, last);
        return;
    }
    if sequence.len() < 2 {
        return;
    }
    let previous = &sequence[sequence.len() - 2];
    let PatternNode::Quantified {
        greedy: false,
        node,
        pos,
        verbose,
        ..
    } = previous
    else {
        return;
    };
    match last {
        PatternNode::Anchor {
            kind: AnchorKind::End,
            ..
        } => {
            sink.emit_span(
                RuleScope::Both,
                "S6019",
                "Remove the '?' from this unnecessarily reluctant quantifier.",
                site.sub_span(node_start(node).unwrap_or(*pos), *pos + verbose.len()),
            );
        }
        PatternNode::Quantified { min: 0, .. } => {
            emit_pointless_reluctant_quantifier(sink, site, previous);
        }
        _ => {}
    }
}

/// `S6035`: every branch of an alternation being one literal char is a
/// character class in disguise (`a|b|c`).
fn check_single_char_alternation(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    flag_single_char_alternation(sink, &parsed.alternatives, site.whole_pattern_span());
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Group {
                alternatives,
                start,
                end,
                ..
            } = node
            {
                flag_single_char_alternation(sink, alternatives, site.sub_span(*start, *end));
            }
        });
    }
}

/// `S5850`: `^a|b$` — anchors under a top-level alternation bind to one
/// branch only unless the branches are grouped.
fn check_anchor_precedence(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    if parsed.alternatives.len() < 2 {
        return;
    }
    let starts_anchored = matches!(
        parsed.alternatives[0].first(),
        Some(PatternNode::Anchor {
            kind: AnchorKind::Start,
            ..
        })
    );
    let ends_anchored = matches!(
        parsed.alternatives.last().and_then(|branch| branch.last()),
        Some(PatternNode::Anchor {
            kind: AnchorKind::End,
            ..
        })
    );
    if !(starts_anchored || ends_anchored) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S5850",
        "Group parts of the regex together to make the intended operator precedence explicit.",
        site.whole_pattern_span(),
    );
}

fn node_start(node: &PatternNode) -> Option<usize> {
    match node {
        PatternNode::Literal { pos, .. }
        | PatternNode::ClassEscape { pos, .. }
        | PatternNode::PropertyEscape { pos, .. }
        | PatternNode::Anchor { pos, .. }
        | PatternNode::BackReference { pos }
        | PatternNode::Quantified { pos, .. } => Some(*pos),
        PatternNode::Class { start, .. } | PatternNode::Group { start, .. } => Some(*start),
        PatternNode::Dot => None,
    }
}

/// `S5868`: combining marks, ZWJ sequences, variation selectors, skin-tone
/// modifiers, and regional indicators inside `[...]` match one scalar, not
/// the grapheme the pattern author sees. Subset: UTF-16 surrogate pairs
/// cannot appear as `char`s and stay out of scope.
fn check_misleading_class_characters(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            let PatternNode::Class { start, end, .. } = node else {
                return;
            };
            let Some(slice) = site.pattern.get(*start..*end) else {
                return;
            };
            // Skip the leading `[`, plus `^` for negated classes.
            let skip = usize::from(slice.starts_with("[^")) + 1;
            for (relative, ch) in slice.char_indices().skip(skip) {
                let Some(kind) = grapheme_component_kind(ch) else {
                    continue;
                };
                let message = match kind {
                    GraphemeComponentKind::CombiningMark => {
                        let previous = slice[..relative].chars().last().unwrap_or('\0');
                        format!(
                            "Move this Unicode combined character '{previous}{ch}' outside of [...]"
                        )
                    }
                    GraphemeComponentKind::JoinSequence => String::from(
                        "Move this Unicode joined character sequence outside of the character class.",
                    ),
                    GraphemeComponentKind::ModifiedEmoji => format!(
                        "Move this Unicode modified Emoji '{ch}' outside of the character class.",
                    ),
                    GraphemeComponentKind::RegionalIndicator => format!(
                        "Move this Unicode regional indicator '{ch}' outside of the character class.",
                    ),
                };
                let absolute = start + relative;
                sink.emit_span(
                    RuleScope::Both,
                    "S5868",
                    &message,
                    site.sub_span(absolute, absolute + ch.len_utf8()),
                );
            }
        });
    }
}

/// `S5843`: complexity budget exceeded (subset scoring, see
/// [`pattern_complexity`]).
fn check_regex_complexity(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    let score = pattern_complexity(&parsed.alternatives);
    if score > REGEX_COMPLEXITY_THRESHOLD {
        sink.emit_span(
            RuleScope::Both,
            "S5843",
            &format!(
                "Simplify this regular expression to reduce its complexity from {score} to the {REGEX_COMPLEXITY_THRESHOLD} allowed."
            ),
            site.whole_pattern_span(),
        );
    }
}

/// `S5852`: unbounded quantifiers nested inside unbounded quantifiers
/// (`(a+)+`) risk exponential backtracking. Conservative subset: any
/// containment counts; disjointness analysis stays out of scope.
fn check_exponential_backtracking(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Quantified {
                max: None,
                node: target,
                pos: _,
                ..
            } = node
                && contains_unbounded_quantifier(target)
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S5852",
                    "Make sure the regex used here, which is vulnerable to super-linear runtime due to backtracking, cannot lead to denial of service.",
                    site.span,
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn invalid_regex_literals_are_flagged() {
        // Unbalanced parenthesis, unknown group header, and reversed class
        // range are definite syntax errors for the mini parser.
        assert_eq!(
            count_key(&js_keys("const re = /(/;\n"), "javascript:S5856"),
            1
        );
        assert_eq!(
            count_key(&js_keys("const re = /(?P<name>a)/;\n"), "javascript:S5856"),
            1
        );
        assert_eq!(
            count_key(&js_keys("const re = /[z-a]/;\n"), "javascript:S5856"),
            1
        );

        let clean = js_keys("const re = /ab+/;\n");
        assert_eq!(count_key(&clean, "javascript:S5856"), 0);

        // Forward class ranges are valid JavaScript; only reversed ones are
        // definite errors.
        let ranges = js_keys("const re = /[A-Z][a-z0-9]*/;\n");
        assert_eq!(count_key(&ranges, "javascript:S5856"), 0);

        // An escape on either side of a dash stays valid: `[a-z\d]` parses
        // as range plus shorthand, and `[a-\d]` keeps the dash literal
        // (Annex B) instead of failing.
        let mixed = js_keys("const re = /[a-z\\d]/;\n");
        assert_eq!(count_key(&mixed, "javascript:S5856"), 0);
        let dash_escape = js_keys("const re = /[a-\\d]/;\n");
        assert_eq!(count_key(&dash_escape, "javascript:S5856"), 0);

        // The family is cataloged for both languages; the prefix follows the
        // file language.
        let typescript = findings("const re = /[z-a]/;\n", JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S5856"), 1);
    }

    #[test]
    fn empty_character_classes_are_flagged() {
        let empty = js_keys("const re = /[]/;\n");
        assert_eq!(count_key(&empty, "javascript:S2639"), 1);

        let negated = js_keys("const re = /[^]/;\n");
        assert_eq!(count_key(&negated, "javascript:S2639"), 1);

        let clean = js_keys("const re = /[ab]/;\n");
        assert_eq!(count_key(&clean, "javascript:S2639"), 0);
    }

    #[test]
    fn empty_alternation_branches_are_flagged() {
        let trailing = js_keys("const re = /a|/;\n");
        assert_eq!(count_key(&trailing, "javascript:S6323"), 1);

        let leading = js_keys("const re = /|b/;\n");
        assert_eq!(count_key(&leading, "javascript:S6323"), 1);

        // An empty branch inside a group belongs here, not to S6331.
        let in_group = js_keys("const re = /(a|)/;\n");
        assert_eq!(count_key(&in_group, "javascript:S6323"), 1);

        let clean = js_keys("const re = /a|b/;\n");
        assert_eq!(count_key(&clean, "javascript:S6323"), 0);
    }

    #[test]
    fn single_member_classes_are_flagged_only_when_safe() {
        let single = js_keys("const re = /[a]/;\n");
        assert_eq!(count_key(&single, "javascript:S6397"), 1);

        // Shorthand and Unicode property escapes are single safe atoms too.
        let shorthand = js_keys("const re = /[\\d]/;\n");
        assert_eq!(count_key(&shorthand, "javascript:S6397"), 1);
        let property = js_keys("const re = /[\\p{L}]/u;\n");
        assert_eq!(count_key(&property, "javascript:S6397"), 1);
        // Without Unicode mode, `\p{L}` is a sequence of class literals.
        let legacy_property = js_keys("const re = /[\\p{L}]/;\n");
        assert_eq!(count_key(&legacy_property, "javascript:S6397"), 0);

        // Negation, ranges, and metacharacters cannot be replaced safely.
        let negated = js_keys("const re = /[^a]/;\n");
        assert_eq!(count_key(&negated, "javascript:S6397"), 0);
        let range = js_keys("const re = /[a-z]/;\n");
        assert_eq!(count_key(&range, "javascript:S6397"), 0);
        for source in [
            "const re = /[.]/;\n",
            "const re = /[|]/;\n",
            "const re = /[)]/;\n",
            "const re = /[\\]]/;\n",
            "const re = /[}]/;\n",
            "const re = /[\\.]/;\n",
        ] {
            assert_eq!(count_key(&js_keys(source), "javascript:S6397"), 0);
        }
        let constructor_slash = js_keys("const re = new RegExp('[/]');\n");
        assert_eq!(count_key(&constructor_slash, "javascript:S6397"), 0);

        // A non-BMP literal is not a safely replaceable singleton without
        // Unicode mode because the class and bare atom use UTF-16 differently.
        let legacy_emoji = js_keys("const re = /[😀]/;\n");
        assert_eq!(count_key(&legacy_emoji, "javascript:S6397"), 0);
        let unicode_emoji = js_keys("const re = /[😀]/u;\n");
        assert_eq!(count_key(&unicode_emoji, "javascript:S6397"), 1);

        let constructor = js_keys("const re = new RegExp('[a]');\n");
        assert_eq!(count_key(&constructor, "javascript:S6397"), 1);
        let typescript = findings("const re = /[\\d]/;\n", JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S6397"), 1);
    }

    #[test]
    fn redundant_quantifier_shapes_are_flagged() {
        let exact = js_keys("const re = /a{1}/;\n");
        assert_eq!(count_key(&exact, "javascript:S6353"), 1);

        let explicit_range = js_keys("const re = /ab{1,1}c/;\n");
        assert_eq!(count_key(&explicit_range, "javascript:S6353"), 1);

        let clean = js_keys("const re = /a{2}/;\n");
        assert_eq!(count_key(&clean, "javascript:S6353"), 0);
    }

    #[test]
    fn bare_control_characters_are_flagged() {
        let control = js_keys("const re = /a\u{0001}b/;\n");
        assert_eq!(count_key(&control, "javascript:S6324"), 1);

        // Tab/newline conventions are exempt.
        let tab = js_keys("const re = /a\tb/;\n");
        assert_eq!(count_key(&tab, "javascript:S6324"), 0);
    }

    #[test]
    fn reluctant_quantifiers_follow_trailing_suffix_rules() {
        let ending_star = js_keys("const re = /a*?/;\n");
        assert_eq!(count_key(&ending_star, "javascript:S6019"), 1);
        let ending_plus = js_keys("const re = /a+?/;\n");
        assert_eq!(count_key(&ending_plus, "javascript:S6019"), 1);

        let required_suffix = js_keys("const re = /a*?b/;\n");
        assert_eq!(count_key(&required_suffix, "javascript:S6019"), 0);
        let optional_suffix = js_keys("const re = /a*?b*/;\n");
        assert_eq!(count_key(&optional_suffix, "javascript:S6019"), 1);
        let optional_group = js_keys("const re = /a*?(?:b)?/;\n");
        assert_eq!(count_key(&optional_group, "javascript:S6019"), 1);
        let end_anchor = js_keys("const re = /a*?$/;\n");
        assert_eq!(count_key(&end_anchor, "javascript:S6019"), 1);
        let top_level_alternation = js_keys("const re = /a*?|b/;\n");
        assert_eq!(count_key(&top_level_alternation, "javascript:S6019"), 1);

        // Group internals are not candidates on their own; the containing
        // pattern must end at the reluctant quantifier.
        let grouped = js_keys("const re = /(?:a*?)/;\n");
        assert_eq!(count_key(&grouped, "javascript:S6019"), 0);
        let alternation = js_keys("const re = /(?:a*?|b)/;\n");
        assert_eq!(count_key(&alternation, "javascript:S6019"), 0);
        let required_group = js_keys("const re = /(a*?)b/;\n");
        assert_eq!(count_key(&required_group, "javascript:S6019"), 0);

        let constructor = js_keys("const re = new RegExp('a+?');\n");
        assert_eq!(count_key(&constructor, "javascript:S6019"), 1);
        let typescript = findings("const re = /a+?/;\n", JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S6019"), 1);
    }

    #[test]
    fn anchored_alternations_need_explicit_grouping() {
        let both_anchors = js_keys("const re = /^a|b$/;\n");
        assert_eq!(count_key(&both_anchors, "javascript:S5850"), 1);

        let start_only = js_keys("const re = /^a|b/;\n");
        assert_eq!(count_key(&start_only, "javascript:S5850"), 1);

        let grouped = js_keys("const re = /^(a|b)$/;\n");
        assert_eq!(count_key(&grouped, "javascript:S5850"), 0);

        let unanchored = js_keys("const re = /a|b/;\n");
        assert_eq!(count_key(&unanchored, "javascript:S5850"), 0);
    }

    #[test]
    fn unicode_constructs_require_the_u_flag() {
        let property_escape = js_keys("const re = /\\p{L}/;\n");
        assert_eq!(count_key(&property_escape, "javascript:S5867"), 1);

        let brace_escape = js_keys("const re = /\\u{1F600}/;\n");
        assert_eq!(count_key(&brace_escape, "javascript:S5867"), 1);

        let with_flag = js_keys("const re = /\\p{L}/u;\n");
        assert_eq!(count_key(&with_flag, "javascript:S5867"), 0);
    }

    #[test]
    fn grapheme_components_inside_classes_are_flagged() {
        // Combining acute accent after `e` matches one scalar, not `é`.
        let combining = js_keys("const re = /[e\u{0301}]/u;\n");
        assert_eq!(count_key(&combining, "javascript:S5868"), 1);

        // Each regional indicator inside a class is its own defect.
        let regional = js_keys("const flags = /[\u{1F1E6}\u{1F1E7}]/u;\n");
        assert_eq!(count_key(&regional, "javascript:S5868"), 2);

        let clean = js_keys("const re = /[ab]/u;\n");
        assert_eq!(count_key(&clean, "javascript:S5868"), 0);

        // Combining marks after a closed class are outside `[...]`.
        let trailing = js_keys("const re = /[a]x\u{0301}/u;\n");
        assert_eq!(count_key(&trailing, "javascript:S5868"), 0);
    }

    #[test]
    fn regex_complexity_budget_is_enforced() {
        // Scores 29 against the budget of 20: three alternation branches
        // of quantified shorthands and classes.
        let over = js_keys("const re = /\\d{4}-\\d{2}-\\d{2}|\\d{8}|\\d{2}[A-Z]{4}/;\n");
        assert_eq!(count_key(&over, "javascript:S5843"), 1);

        let under = js_keys("const re = /\\d{4}-\\d{2}-\\d{2}/;\n");
        assert_eq!(count_key(&under, "javascript:S5843"), 0);
    }

    #[test]
    fn overlapping_character_class_members_are_flagged() {
        let range_and_character = js_keys("const re = /[a-zb]/;\n");
        assert_eq!(count_key(&range_and_character, "javascript:S5869"), 1);
        let overlapping_ranges = js_keys("const re = /[a-ca-f]/;\n");
        assert_eq!(count_key(&overlapping_ranges, "javascript:S5869"), 1);
        let digit_shorthand = js_keys("const re = /[\\d0]/;\n");
        assert_eq!(count_key(&digit_shorthand, "javascript:S5869"), 1);
        let word_shorthand = js_keys("const re = /[\\w_]/;\n");
        assert_eq!(count_key(&word_shorthand, "javascript:S5869"), 1);
        let space_shorthand = js_keys("const re = /[\\s ]/;\n");
        assert_eq!(count_key(&space_shorthand, "javascript:S5869"), 1);
        let insensitive = js_keys("const re = /[aA]/i;\n");
        assert_eq!(count_key(&insensitive, "javascript:S5869"), 1);

        let bom = js_keys("const re = /[\\s\u{FEFF}]/;\n");
        assert_eq!(count_key(&bom, "javascript:S5869"), 1);
        let nel = js_keys("const re = /[\\s\u{0085}]/u;\n");
        assert_eq!(count_key(&nel, "javascript:S5869"), 0);
        let non_space = js_keys("const re = /[\\S\u{00A0}]/;\n");
        assert_eq!(count_key(&non_space, "javascript:S5869"), 0);
        let non_bom_space = js_keys("const re = /[\\S\u{FEFF}]/u;\n");
        assert_eq!(count_key(&non_bom_space, "javascript:S5869"), 0);
        let long_s = js_keys("const re = /[\\Wſ]/iu;\n");
        assert_eq!(count_key(&long_s, "javascript:S5869"), 0);
        let kelvin = js_keys("const re = /[\\WK]/iu;\n");
        assert_eq!(count_key(&kelvin, "javascript:S5869"), 0);

        // Existing direct duplicates still produce one finding per
        // duplicate occurrence.
        let direct = js_keys("const re = /[aaa]/;\n");
        assert_eq!(count_key(&direct, "javascript:S5869"), 2);
        let clean = js_keys("const re = /[ab]/;\n");
        assert_eq!(count_key(&clean, "javascript:S5869"), 0);

        let constructor = js_keys("const re = new RegExp('[a-zb]');\n");
        assert_eq!(count_key(&constructor, "javascript:S5869"), 1);
        let typescript = findings("const re = /[a-zb]/;\n", JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S5869"), 1);
    }

    #[test]
    fn empty_matchable_repetitions_ignore_outer_minimum() {
        let star = js_keys("const re = /(a?)*/;\n");
        assert_eq!(count_key(&star, "javascript:S5842"), 1);
        let plus = js_keys("const re = /(a?)+/;\n");
        assert_eq!(count_key(&plus, "javascript:S5842"), 1);
        let bounded = js_keys("const re = /(a?){2}/;\n");
        assert_eq!(count_key(&bounded, "javascript:S5842"), 1);
        let zero_bounded = js_keys("const re = /(a?){0,2}/;\n");
        assert_eq!(count_key(&zero_bounded, "javascript:S5842"), 1);

        let clean = js_keys("const re = /(a+)*/;\n");
        assert_eq!(count_key(&clean, "javascript:S5842"), 0);
        let constructor = js_keys("const re = new RegExp('(a?)*');\n");
        assert_eq!(count_key(&constructor, "javascript:S5842"), 1);
        let typescript = findings("const re = /(a?)*/;\n", JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S5842"), 1);
    }
}
