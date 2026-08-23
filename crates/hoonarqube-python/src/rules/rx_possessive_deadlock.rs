use crate::engine::rx::RxSeq;
use crate::engine::rx::rx_atom_first_set;
use crate::engine::rx::rx_sets_intersect;
use ruff_text_size::TextRange;

/// python:S5994 — content after a possessive quantifier that the possessive
/// run already consumed can never match.
pub(crate) fn check_rx_possessive_deadlock(
    seq: &RxSeq,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    for window in seq.items.windows(2) {
        let (possessive, next) = (&window[0], &window[1]);
        let Some(quant) = &possessive.quant else {
            continue;
        };
        if !(quant.possessive && quant.max.is_none()) {
            continue;
        }
        let mandatory = next
            .quant
            .as_ref()
            .is_none_or(|next_quant| next_quant.min >= 1);
        if !mandatory {
            continue;
        }
        if let (Some(consumed), Some(wanted)) = (
            rx_atom_first_set(&possessive.atom),
            rx_atom_first_set(&next.atom),
        ) && rx_sets_intersect(&wanted, &consumed)
        {
            push(
                "python:S5994",
                "This sub-pattern can never match what the possessive quantifier consumed.",
                next.span,
            );
        }
    }
}
