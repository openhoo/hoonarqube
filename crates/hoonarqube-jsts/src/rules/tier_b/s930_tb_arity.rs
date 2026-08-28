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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn arity_mismatch_against_local_function_flagged() {
        let flagged = js("function add(a, b) { return a + b; }\nadd(1);\nadd(1, 2, 3);\n");
        assert_eq!(count_key(&report_keys(&flagged), "javascript:S930"), 2);
        let rest_clean =
            js("function pick(first, ...rest) { return rest; }\npick(1);\npick(1, 2, 3);\n");
        assert_eq!(count_key(&report_keys(&rest_clean), "javascript:S930"), 0);
    }
}
