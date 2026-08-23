// Rule module s1526_tb_var_hoisting_order (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S1526 (JS only) — identifiers read textually before their `var`
/// declarator (hoisting order).
pub(crate) fn check_tb_var_hoisting_order(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        if binding.kind != TbKind::Var {
            continue;
        }
        let name = binding.name;
        for read in binding
            .reads
            .iter()
            .filter(|read| read.end < binding.decl.start)
            .copied()
        {
            sink.emit_span(
                RuleScope::JsOnly,
                "S1526",
                &format!("Move the declaration of '{name}' above this usage; 'var' is hoisted."),
                read,
            );
        }
    }
}
