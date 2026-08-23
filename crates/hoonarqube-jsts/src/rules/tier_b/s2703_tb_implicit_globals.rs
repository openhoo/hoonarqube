// Rule module s2703_tb_implicit_globals (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

/// S2703 (JS only) — assignments to names declared nowhere in the file.
pub(crate) fn check_tb_implicit_globals(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for (name, span) in &model.implicit_globals {
        sink.emit_span(
            RuleScope::JsOnly,
            "S2703",
            &format!("Declare '{name}' explicitly; this assignment creates an implicit global."),
            *span,
        );
    }
}
