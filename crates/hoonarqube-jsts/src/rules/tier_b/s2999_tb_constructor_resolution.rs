// Rule module s2999_tb_constructor_resolution (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S2999 — `new` applied to something that does not resolve to a
/// file-local function/class declaration.
pub(crate) fn check_tb_constructor_resolution(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for &(binding, span) in &model.news {
        let constructed = matches!(
            model.bindings[binding].kind,
            TbKind::Function | TbKind::Class
        );
        if !constructed {
            let name = model.bindings[binding].name;
            sink.emit_span(
                RuleScope::Both,
                "S2999",
                &format!("Make sure '{name}' holds a constructor before using 'new' on it."),
                span,
            );
        }
    }
}
