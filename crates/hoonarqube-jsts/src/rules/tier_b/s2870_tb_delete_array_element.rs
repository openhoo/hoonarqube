// Rule module s2870_tb_delete_array_element (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};
use oxc_span::Span;

/// S2870 — `delete` on an element of an array-initialized binding.
pub(crate) fn check_tb_delete_array_element(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for &(binding, span) in &model.array_deletes {
        let _ = binding;
        sink.emit_span(
            RuleScope::Both,
            "S2870",
            "Remove this use of \"delete\".",
            Span::new(span.start, span.start.saturating_add(6)),
        );
    }
}
