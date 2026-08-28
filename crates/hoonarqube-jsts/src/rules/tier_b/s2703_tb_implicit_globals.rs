// Rule module s2703_tb_implicit_globals (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

/// S2703 (JS only) — assignments to names declared nowhere in the file.
pub(crate) fn check_tb_implicit_globals(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for (name, span) in &model.implicit_globals {
        sink.emit_span(
            RuleScope::JsOnly,
            "S2703",
            &format!(
                "Add the \"let\", \"const\" or \"var\" keyword to this declaration of \"{name}\" to make it explicit."
            ),
            *span,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn implicit_global_assignment_flagged_in_javascript_only() {
        let source = "function f() {\n  leaked = 1;\n}\nf();\n";
        assert_eq!(filtered(&js(source), "S2703").len(), 1);
        assert_eq!(
            filtered(&ts("function f() {\n  leaked = 1;\n}\nf();\n"), "S2703").len(),
            0
        );
    }
}
