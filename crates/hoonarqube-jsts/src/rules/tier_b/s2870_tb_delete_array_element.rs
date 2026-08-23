// Rule module s2870_tb_delete_array_element (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

/// S2870 — `delete` on an element of an array-initialized binding.
pub(crate) fn check_tb_delete_array_element(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for &(binding, span) in &model.array_deletes {
        let name = model.bindings[binding].name;
        sink.emit_span(
            RuleScope::Both,
            "S2870",
            &format!("Remove this 'delete'; it targets an element of the array '{name}'."),
            span,
        );
    }
}
