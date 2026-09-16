// Rule module s4623_tb_explicit_undefined (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

/// S4623 (TS only) — an explicit `undefined` passed as the LAST argument at
/// an optional-parameter position of a file-local signature. `SonarJS` only
/// examines the final argument: a middle-position `undefined` cannot be
/// omitted without shifting the arguments after it, so it is never
/// redundant.
pub(crate) fn check_tb_explicit_undefined(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for call in &model.calls {
        if call.spread {
            continue;
        }
        let Some(signature) = &model.bindings[call.binding].arity else {
            continue;
        };
        for &(position, span) in &call.explicit_undefined {
            if position + 1 == call.arity && signature.optional.contains(&position) {
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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn only_trailing_undefined_at_optional_position_flags() {
        // Middle-position `undefined` keeps the arguments after it aligned;
        // only the final argument can be dropped without shifting.
        let middle =
            ts("function f(state, value?, failure?) {}\nf(group.parent, undefined, { error });\n");
        assert_eq!(filtered(&middle, "S4623").len(), 0);
        let trailing = ts("function f(state, value?, failure?) {}\nf(s, v, undefined);\n");
        assert_eq!(filtered(&trailing, "S4623").len(), 1);
        let required = ts("function f(state, value) {}\nf(s, undefined);\n");
        assert_eq!(filtered(&required, "S4623").len(), 0);
    }
}
