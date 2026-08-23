// Rule module s2814_tb_duplicates (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

/// S2814 (JS only) — `var`/function declared twice in the same scope.
pub(crate) fn check_tb_duplicates(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for (_, second, name) in &model.duplicates {
        sink.emit_span(
            RuleScope::JsOnly,
            "S2814",
            &format!("'{name}' is declared more than once in this scope."),
            *second,
        );
    }
}
