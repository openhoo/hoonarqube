// Rule module s1128_tb_unused_imports (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S1128 — imported bindings never referenced anywhere.
pub(crate) fn check_tb_unused_imports(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        if binding.kind == TbKind::Import && binding.reads.is_empty() && binding.writes.is_empty() {
            let name = binding.name;
            sink.emit_span(
                RuleScope::Both,
                "S1128",
                &format!("Remove this unused import of '{name}'."),
                binding.decl,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn unused_imports_flagged_in_both_languages() {
        let source = "import { helper } from './helper';\n";
        assert_eq!(filtered(&js(source), "S1128").len(), 1);
        assert_eq!(count_key(&report_keys(&ts(source)), "typescript:S1128"), 1);
        let used = "import { helper } from './helper';\nhelper();\n";
        assert_eq!(filtered(&js(used), "S1128").len(), 0);
        assert_eq!(count_key(&report_keys(&ts(used)), "typescript:S1128"), 0);
    }
}
