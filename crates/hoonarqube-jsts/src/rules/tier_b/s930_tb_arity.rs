// Rule module s930_tb_arity (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

/// S930 (JS only) — call-site arity against file-local function signatures.
pub(crate) fn check_tb_arity(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for call in &model.calls {
        let binding = &model.bindings[call.binding];
        let Some(signature) = &binding.arity else {
            continue;
        };
        let wrong =
            call.arity < signature.minimum || signature.maximum.is_some_and(|max| call.arity > max);
        if !wrong {
            continue;
        }
        let expected = match (signature.minimum, signature.maximum) {
            (min, Some(max)) if min == max => format!("{min}"),
            (min, Some(max)) => format!("{min} to {max}"),
            (min, None) => format!("at least {min}"),
        };
        let name = binding.name;
        sink.emit_span(
            RuleScope::JsOnly,
            "S930",
            &format!(
                "'{name}' expects {expected} arguments, but {} were provided.",
                call.arity
            ),
            call.span,
        );
    }
}
