use crate::engine::rx::RxAtom;
use crate::engine::rx::RxSeq;
use crate::engine::rx::rx_item_consuming;
use ruff_text_size::TextRange;

pub(crate) fn check_rx_anchor_order(seq: &RxSeq, push: &mut dyn FnMut(&str, &str, TextRange)) {
    let mut misplaced_end: Option<TextRange> = None;
    let mut seen_consuming = false;
    for item in &seq.items {
        if let RxAtom::Anchor(anchor) = &item.atom {
            if anchor.is_end() && seen_consuming && misplaced_end.is_none() {
                misplaced_end = Some(item.span);
            }
            if anchor.is_start() && seen_consuming {
                push(
                    "python:S5996",
                    "This anchor placement can never match; reorder the anchors.",
                    item.span,
                );
                return;
            }
        }
        if rx_item_consuming(item) {
            seen_consuming = true;
            if let Some(span) = misplaced_end {
                push(
                    "python:S5996",
                    "This anchor placement can never match; reorder the anchors.",
                    span,
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

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
}
