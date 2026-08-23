// Rule module s5856_constant_regex_site (generated).
use crate::engine::pattern_parser::{
    AnchorKind, ClassItem, GraphemeComponentKind, ParsedRegex, PatternNode, RegexSite,
    contains_unbounded_quantifier, grapheme_component_kind, node_can_match_empty,
    parse_regex_pattern, pattern_complexity, sequence_can_match_empty, walk_pattern_nodes,
};
use crate::support::{IssueSink, RuleScope};
use crate::{
    REGEX_COMPLEXITY_THRESHOLD, emit_concise_class_rewrite, emit_space_runs_in_sequence,
    flag_single_char_alternation, for_every_sequence, is_bare_control_character,
};

// ----- Shared-walker rule drivers -----

/// Runs every pattern-text rule over one constant regex site. The raw-text
/// scans also run on patterns the mini parser rejects; everything
/// structure-based needs a successful parse.
pub(crate) fn check_constant_regex_site(sink: &mut IssueSink, site: &RegexSite) {
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

/// `S6324`: bare C0 control characters other than the tab/newline
/// conventions.
pub(crate) fn check_control_characters(sink: &mut IssueSink, site: &RegexSite) {
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
pub(crate) fn check_unicode_constructs_without_u_flag(sink: &mut IssueSink, site: &RegexSite) {
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
                site.sub_span(start, end),
            );
            search_from = end;
        }
    }
}

/// `S2639`: `[]` never matches anything and `[^]` matches everything —
/// both are defects.
pub(crate) fn check_empty_character_class(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
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
pub(crate) fn check_empty_alternatives(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
    for pos in &parsed.empty_branch_positions {
        sink.emit_span(
            RuleScope::Both,
            "S6323",
            "Remove this empty alternative.",
            site.sub_span(*pos, *pos),
        );
    }
}

/// `S6331`: a wholly empty group `()` / `(?:)`.
pub(crate) fn check_empty_groups(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
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

/// `S5869`: repeated characters inside `[...]`. Case-insensitive folding is
/// out of subset scope.
pub(crate) fn check_duplicate_class_members(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            let PatternNode::Class { items, .. } = node else {
                return;
            };
            let mut seen: Vec<char> = Vec::new();
            for item in items {
                if let ClassItem::Char { ch, pos } = item {
                    if seen.contains(ch) {
                        sink.emit_span(
                            RuleScope::Both,
                            "S5869",
                            "Remove duplicates in this character class.",
                            site.sub_span(*pos, pos + ch.len_utf8()),
                        );
                    } else {
                        seen.push(*ch);
                    }
                }
            }
        });
    }
}

/// `S6397`: `[a]` asserts no more than `a`.
pub(crate) fn check_single_member_class(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Class {
                items, start, end, ..
            } = node
                && items.len() == 1
                && matches!(items[0], ClassItem::Char { .. })
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

/// `S6353`: `{1}` / `{1,1}` quantifiers and duplicate-only classes with a
/// concise rewrite.
pub(crate) fn check_concise_shapes(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| match node {
            PatternNode::Quantified {
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
                    site.sub_span(*pos, *pos),
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
pub(crate) fn check_space_runs(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        for_every_sequence(alternative, &mut |sequence| {
            emit_space_runs_in_sequence(sink, site, sequence);
        });
    }
}

/// `S5842`: a consuming quantifier over an empty-matchable group loops
/// forever (`(a*)+`). Subset: `min >= 1` over non-lookaround groups.
pub(crate) fn check_empty_string_repetition(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Quantified {
                min,
                node: target,
                pos,
                ..
            } = node
                && *min >= 1
                && let PatternNode::Group {
                    kind, alternatives, ..
                } = target.as_ref()
                && !kind.is_lookaround()
                && alternatives
                    .iter()
                    .any(|branch| sequence_can_match_empty(branch))
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S5842",
                    "Rework this part of the regex to not match the empty string.",
                    site.sub_span(*pos, *pos),
                );
            }
        });
    }
}

/// `S6019`: a reluctant quantifier directly followed by something that can
/// match empty renders the laziness pointless.
pub(crate) fn check_pointless_reluctant_quantifier(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
    for alternative in &parsed.alternatives {
        for_every_sequence(alternative, &mut |sequence| {
            for pair in sequence.windows(2) {
                if let PatternNode::Quantified {
                    greedy: false,
                    min,
                    pos,
                    ..
                } = pair[0]
                    && node_can_match_empty(&pair[1])
                {
                    let plural = if min == 1 { "" } else { "s" };
                    sink.emit_span(
                        RuleScope::Both,
                        "S6019",
                        &format!(
                            "Fix this reluctant quantifier that will only ever match {min} repetition{plural}."
                        ),
                        site.sub_span(pos, pos),
                    );
                }
            }
        });
    }
}

/// `S6035`: every branch of an alternation being one literal char is a
/// character class in disguise (`a|b|c`).
pub(crate) fn check_single_char_alternation(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
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
pub(crate) fn check_anchor_precedence(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
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
    let pos = if starts_anchored {
        match parsed.alternatives[0].first() {
            Some(PatternNode::Anchor { pos, .. }) => *pos,
            _ => 0,
        }
    } else {
        match parsed.alternatives.last().and_then(|branch| branch.last()) {
            Some(PatternNode::Anchor { pos, .. }) => *pos,
            _ => 0,
        }
    };
    sink.emit_span(
        RuleScope::Both,
        "S5850",
        "Group parts of the regex together to make the intended operator precedence explicit.",
        site.sub_span(pos, pos),
    );
}

/// `S5868`: combining marks, ZWJ sequences, variation selectors, skin-tone
/// modifiers, and regional indicators inside `[...]` match one scalar, not
/// the grapheme the pattern author sees. Subset: UTF-16 surrogate pairs
/// cannot appear as `char`s and stay out of scope.
pub(crate) fn check_misleading_class_characters(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
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
                    GraphemeComponentKind::CombiningMark => format!(
                        "Move this Unicode combined character '{ch}' outside of the character class"
                    ),
                    GraphemeComponentKind::JoinSequence => String::from(
                        "Move this Unicode joined character sequence outside of the character class",
                    ),
                    GraphemeComponentKind::ModifiedEmoji => format!(
                        "Move this Unicode modified Emoji '{ch}' outside of the character class"
                    ),
                    GraphemeComponentKind::RegionalIndicator => format!(
                        "Move this Unicode regional indicator '{ch}' outside of the character class"
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
pub(crate) fn check_regex_complexity(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
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
pub(crate) fn check_exponential_backtracking(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Quantified {
                max: None,
                node: target,
                pos,
                ..
            } = node
                && contains_unbounded_quantifier(target)
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S5852",
                    "Fix this regular expression that is vulnerable to exponential backtracking, as it can lead to denial of service.",
                    site.sub_span(*pos, *pos),
                );
            }
        });
    }
}
