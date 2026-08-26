use crate::engine::rx::RxAtom;
use crate::engine::rx::RxGroupKind;
use crate::engine::rx::RxParsed;
use crate::engine::rx::for_each_rx_item;
use crate::engine::rx::for_each_rx_seq_deep;
use crate::engine::rx::is_repetitive;
use crate::engine::rx::rx_body_ambiguous;
use crate::rules::rx_lazy_quantifiers::check_rx_lazy_quantifiers;
use crate::rules::rx_overlapping_repeats::check_rx_overlapping_repeats;
use crate::rules::rx_possessive_deadlock::check_rx_possessive_deadlock;
use ruff_text_size::TextRange;

// --- repetition hazards (S5852, S5855, S5994, S6019) -------------------------

pub(crate) fn check_rx_repetition_hazards(
    parsed: &RxParsed,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    for_each_rx_seq_deep(&parsed.root, &mut |seq| {
        check_rx_lazy_quantifiers(seq, push);
        check_rx_possessive_deadlock(seq, push);
        check_rx_overlapping_repeats(seq, push);
    });
    for_each_rx_item(&parsed.root, &mut |item| {
        if let Some(quant) = &item.quant
            && !quant.possessive
            && is_repetitive(quant)
            && let RxAtom::Group(group) = &item.atom
            && matches!(group.kind, RxGroupKind::Capture | RxGroupKind::NonCapture)
            && rx_body_ambiguous(&group.body)
        {
            push(
                "python:S5852",
                "Make sure this regular expression cannot cause a denial of service.",
                quant.span,
            );
        }
    });
}
