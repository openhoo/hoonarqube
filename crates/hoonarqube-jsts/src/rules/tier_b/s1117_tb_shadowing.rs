// Rule module s1117_tb_shadowing (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

// ---------------------------------------------------------------------------
// Tier B rule queries over the scope model.

/// S1117 — any inner declaration shadowing a binding from an enclosing
/// scope. CE-parity: the documented rule and the captured engine flag
/// shadowing unconditionally, even when the outer binding is never read
/// afterwards (oracle-js `s1117_good.js`), so no usage gate is applied.
pub(crate) fn check_tb_shadowing(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for &(outer, inner) in &model.shadows {
        let name = model.bindings[outer].name;
        sink.emit_span(
            RuleScope::Both,
            "S1117",
            &format!("Rename this '{name}' declaration; it shadows one from an outer scope."),
            model.bindings[inner].decl,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn shadowing_flagged_regardless_of_outer_usage() {
        // CE-parity flip: SQ fires on the shadowing declaration itself even
        // when the outer variable is unused afterwards (s1117_good.js); the
        // old usage gate made us silently pass such controls.
        let used = js("let x = 1;\nfunction g() {\n  let x = 2;\n}\ng(x);\n");
        assert_eq!(filtered(&used, "S1117").len(), 1);

        let unused_outer = js("let x = 1;\nfunction g() {\n  let x = 2;\n}\ng();\n");
        assert_eq!(filtered(&unused_outer, "S1117").len(), 1);
    }
}
