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
        if let Some(read) = leaks {
            let name = binding.name;
            sink.emit_span(
                RuleScope::Both,
                "S2392",
                &format!("Narrow the scope of '{name}'; it is used outside its declaring block."),
                *read,
            );
        }
    }
}
