use crate::engine::rx::RxAtom;
use crate::engine::rx::RxGroupKind;
use crate::engine::rx::RxNode;
use crate::engine::rx::RxParsed;
use crate::engine::rx::for_each_rx_item;
use ruff_text_size::TextRange;

pub(crate) fn check_rx_pointless_groups(
    parsed: &RxParsed,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    for_each_rx_item(&parsed.root, &mut |item| {
        if item.quant.is_some() {
            return;
        }
        if let RxAtom::Group(group) = &item.atom
            && group.kind == RxGroupKind::NonCapture
            && !matches!(&group.body, RxNode::Seq(seq) if seq.items.is_empty())
            && !matches!(group.body, RxNode::Alternation(_))
        {
            push(
                "python:S6395",
                "Remove this redundant non-capturing group or apply a quantifier to it.",
                group.span,
            );
        }
    });
}
