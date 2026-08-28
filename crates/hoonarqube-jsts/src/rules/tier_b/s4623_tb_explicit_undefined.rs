// Rule module s4623_tb_explicit_undefined (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

/// S4623 (TS only) — an explicit `undefined` at an optional-parameter
/// position of a file-local signature.
pub(crate) fn check_tb_explicit_undefined(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for call in &model.calls {
        if call.spread {
            continue;
        }
        let Some(signature) = &model.bindings[call.binding].arity else {
            continue;
        };
        for &(position, span) in &call.explicit_undefined {
            if signature.optional.contains(&position) {
                sink.emit_span(
                    RuleScope::TsOnly,
                    "S4623",
                    "Remove this redundant \"undefined\".",
                    span,
                );
            }
        }
    }
}
