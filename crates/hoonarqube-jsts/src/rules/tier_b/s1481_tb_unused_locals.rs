// Rule module s1481_tb_unused_locals (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S1481 (JS only) — local variables/functions/classes without any reference.
pub(crate) fn check_tb_unused_locals(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        let unreferenced = binding.reads.is_empty() && binding.writes.is_empty();
        if binding.kind.is_local_value() && !binding.global && unreferenced {
            let noun = match binding.kind {
                TbKind::Function => "function",
                TbKind::Class => "class",
                _ => "local variable",
            };
            let name = binding.name;
            sink.emit_span(
                RuleScope::JsOnly,
                "S1481",
                &format!("Remove this unused {noun} '{name}'."),
                binding.decl,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn unused_locals_flagged_inside_functions_but_not_at_top_level() {
        let source = "const kept = 1;\nfunction f() {\n  const orphan = 2;\n}\nf();\n";
        let issues = filtered(&js(source), "S1481");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("orphan"));
    }
}
