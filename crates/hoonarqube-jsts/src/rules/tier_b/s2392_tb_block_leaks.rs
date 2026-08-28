// Rule module s2392_tb_block_leaks (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

/// S2392 — `var` leaking out of its declaring block and used beyond it.
pub(crate) fn check_tb_block_leaks(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        let Some(home) = binding.home_block else {
            continue;
        };
        let leaks = binding
            .reads
            .iter()
            .find(|read| read.start < home.start || read.end > home.end);
        if leaks.is_some() {
            let name = binding.name;
            sink.emit_span(
                RuleScope::Both,
                "S2392",
                &format!(
                    "Consider moving declaration of '{name}' as it is referenced outside current binding context."
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
    fn var_leaking_out_of_its_block_flagged_once() {
        let flagged = js("if (cond) {\n  var leaky = 1;\n}\nuse(leaky);\n");
        assert_eq!(filtered(&flagged, "S2392").len(), 1);
        let clean = js("if (cond) {\n  let scoped = 1;\n  use(scoped);\n}\n");
        assert_eq!(filtered(&clean, "S2392").len(), 0);
    }
}
