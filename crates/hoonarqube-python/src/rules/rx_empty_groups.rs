use crate::engine::rx::RxAtom;
use crate::engine::rx::RxGroupKind;
use crate::engine::rx::RxNode;
use crate::engine::rx::RxParsed;
use crate::engine::rx::for_each_rx_item;
use ruff_text_size::TextRange;

pub(crate) fn check_rx_empty_groups(
    parsed: &RxParsed,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    for_each_rx_item(&parsed.root, &mut |item| {
        if let RxAtom::Group(group) = &item.atom
            && matches!(group.kind, RxGroupKind::Capture | RxGroupKind::NonCapture)
            && matches!(&group.body, RxNode::Seq(seq) if seq.items.is_empty())
        {
            push("python:S6331", "Remove this empty group.", group.span);
        }
    });
}
