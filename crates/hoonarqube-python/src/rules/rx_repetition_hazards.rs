use crate::engine::rx::RxAtom;
use crate::engine::rx::RxGroupKind;
use crate::engine::rx::RxMatchType;
use crate::engine::rx::RxParsed;
use crate::engine::rx::for_each_rx_item;
use crate::engine::rx::for_each_rx_seq_deep;
use crate::engine::rx::is_repetitive;
use crate::engine::rx::rx_body_ambiguous;
use crate::rules::rx_lazy_quantifiers::check_rx_lazy_quantifiers;
use crate::rules::rx_possessive_deadlock::check_rx_possessive_deadlock;
use crate::rules::s8786_super_linear_regex::collect_continuations;
use ruff_text_size::TextRange;
use std::collections::HashMap;

// --- repetition hazards (S5852, S5855, S5994, S6019) -------------------------

pub(crate) fn check_rx_repetition_hazards(
    parsed: &RxParsed,
    match_type: RxMatchType,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    check_rx_lazy_quantifiers(&parsed.root, push);
    for_each_rx_seq_deep(&parsed.root, &mut |seq| {
        check_rx_possessive_deadlock(seq, push);
    });
    // python:S5852 — nested ambiguous repetition inside an open-ended
    // quantified group (Sonar's BacktrackingFinder); sibling overlapping
    // repeats are the super-linear concern of python:S8786.
    let mut continuations = HashMap::new();
    collect_continuations(&parsed.root, false, true, &mut continuations);
    for_each_rx_item(&parsed.root, &mut |item| {
        if let Some(quant) = &item.quant
            && !quant.possessive
            && is_repetitive(quant)
            && let RxAtom::Group(group) = &item.atom
            && matches!(group.kind, RxGroupKind::Capture | RxGroupKind::NonCapture)
            && rx_body_ambiguous(&group.body)
            && (matches!(match_type, RxMatchType::Full | RxMatchType::Both)
                || continuations
                    .get(&item.span)
                    .is_none_or(|(anchored, nullable)| *anchored || !nullable))
        {
            push(
                "python:S5852",
                "Make sure this regular expression cannot cause a denial of service.",
                quant.span,
            );
        }
    });
}
