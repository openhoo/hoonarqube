// Rule module s1128_tb_unused_imports (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S1128 (JS only) — imported bindings never referenced anywhere.
pub(crate) fn check_tb_unused_imports(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        if binding.kind == TbKind::Import && binding.reads.is_empty() && binding.writes.is_empty() {
            let name = binding.name;
            sink.emit_span(
                RuleScope::JsOnly,
                "S1128",
                &format!("Remove this unused import of '{name}'."),
                binding.decl,
            );
        }
    }
}
