// Rule module s1172_tb_unused_parameters (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S1172 — function parameters that are never read.
pub(crate) fn check_tb_unused_parameters(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        if binding.kind == TbKind::Param && binding.reads.is_empty() {
            let name = binding.name;
            sink.emit_span(
                RuleScope::Both,
                "S1172",
                &format!("Remove this unused function parameter '{name}'."),
                binding.decl,
            );
        }
    }
}
