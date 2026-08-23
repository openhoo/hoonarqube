// Rule module s1117_tb_shadowing (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

// ---------------------------------------------------------------------------
// Tier B rule queries over the scope model.

/// S1117 — an inner declaration shadowing an outer binding that is still
/// referenced later.
pub(crate) fn check_tb_shadowing(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for &(outer, inner) in &model.shadows {
        let outer_binding = &model.bindings[outer];
        let decl = model.bindings[inner].decl;
        let used_after = outer_binding
            .reads
            .iter()
            .any(|read| read.start > decl.start);
        if used_after {
            let name = outer_binding.name;
            sink.emit_span(
                RuleScope::Both,
                "S1117",
                &format!("Rename this '{name}' declaration; it shadows one from an outer scope."),
                decl,
            );
        }
    }
}
