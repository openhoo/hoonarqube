// Rule module s1172_tb_unused_parameters (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S1172 — function parameters that are never read.
pub(crate) fn check_tb_unused_parameters(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        if binding.kind == TbKind::Param && binding.reads.is_empty() {
            let name = binding.name;
            sink.emit_span(
                RuleScope::Both,
                "S1172",
                &format!(
                    "Remove the unused function parameter \"{name}\" or rename it to \"_{name}\" to make intention explicit."
                ),
                binding.decl,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn unused_parameters_flagged_but_setters_exempt() {
        let flagged = js("function f(unused) {\n  return 1;\n}\nf(2);\n");
        assert_eq!(filtered(&flagged, "S1172").len(), 1);
        let clean =
            js("const obj = { set value(next) { this.stored = next; } };\nobj.value = 3;\n");
        assert_eq!(filtered(&clean, "S1172").len(), 0);
    }
}
