// Rule module s6522_tb_import_reassigned (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S6522 — assignments targeting import-declared bindings.
pub(crate) fn check_tb_import_reassigned(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        if binding.kind != TbKind::Import {
            continue;
        }
        let name = binding.name;
        for write in &binding.writes {
            sink.emit_span(
                RuleScope::Both,
                "S6522",
                &format!(
                    "Remove this reassignment of the imported '{name}'; imports are read-only."
                ),
                *write,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn import_reassignment_flagged() {
        let flagged = js("import { helper } from './helper';\nhelper = null;\n");
        assert_eq!(filtered(&flagged, "S6522").len(), 1);
    }

    #[test]
    fn typescript_files_receive_tier_b_keys_with_typescript_prefix() {
        let source = "import { helper } from './helper';\nhelper = null;\n";
        let report = ts(source);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.rule_key == "typescript:S6522")
        );
    }
}
