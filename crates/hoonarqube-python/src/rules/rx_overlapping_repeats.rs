use crate::engine::rx::RxSeq;
use crate::engine::rx::rx_atom_first_set;
use crate::engine::rx::rx_atom_zero_width;
use crate::engine::rx::rx_is_unbounded_repeat;
use crate::engine::rx::rx_item_nullable_pub;
use crate::engine::rx::rx_optional_separator_overlaps;
use crate::engine::rx::rx_sets_intersect;
use ruff_text_size::TextRange;

/// python:S5852 — consecutive overlapping unbounded repetitions.
pub(crate) fn check_rx_overlapping_repeats(
    seq: &RxSeq,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    for index in 0..seq.items.len() {
        let first = &seq.items[index];
        if !rx_is_unbounded_repeat(first) || rx_atom_zero_width(&first.atom) {
            continue;
        }
        let first_set = rx_atom_first_set(&first.atom);
        for offset in 1..=2usize {
            let Some(second_index) = seq.items.get(index + offset) else {
                break;
            };
            let second = second_index;
            if !rx_is_unbounded_repeat(second) || rx_atom_zero_width(&second.atom) {
                continue;
            }
            let separator_ok = if offset == 1 {
                true
            } else {
                let middle = &seq.items[index + 1];
                rx_item_nullable_pub(middle)
                    || rx_optional_separator_overlaps(middle, first, second)
            };
            if separator_ok
                && let (Some(a), Some(b)) = (first_set.clone(), rx_atom_first_set(&second.atom))
                && rx_sets_intersect(&a, &b)
            {
                push(
                    "python:S5852",
                    "Make sure this regular expression cannot cause a denial of service.",
                    second.span,
                );
            }
            break;
        }
    }
}
