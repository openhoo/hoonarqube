// Rule module s3500_tb_const_reassigned (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S3500 (JS only) — reassignments of `const` bindings.
pub(crate) fn check_tb_const_reassigned(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        if binding.kind == TbKind::Const {
            let name = binding.name;
            for write in &binding.writes {
                sink.emit_span(
                    RuleScope::JsOnly,
                    "S3500",
                    &format!("Remove this reassignment of the constant '{name}'."),
                    *write,
                );
            }
        }
    }
}
