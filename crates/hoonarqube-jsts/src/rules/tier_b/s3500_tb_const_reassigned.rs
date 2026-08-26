// Rule module s3500_tb_const_reassigned (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S3500 (JS only) — reassignments of `const` bindings.
pub(crate) fn check_tb_const_reassigned(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        if binding.kind == TbKind::Const {
            let name = binding.name;
            for write in &binding.writes {
                sink.emit_span(
                    RuleScope::JsOnly,
                    "S3500",
                    &format!("Remove this reassignment of the constant '{name}'."),
                    *write,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn const_reassignment_flagged() {
        let flagged = js("const fixed = 1;\nfixed = 2;\n");
        assert_eq!(filtered(&flagged, "S3500").len(), 1);
        let clean = js("const fixed = 1;\nconsole.log(fixed);\n");
        assert_eq!(filtered(&clean, "S3500").len(), 0);
    }

    #[test]
    fn member_writes_do_not_reassign_the_root_constant() {
        let member = js("const c = {};\nc.x = 1;\nuse(c);\n");
        assert_eq!(filtered(&member, "S3500").len(), 0);
        let update = js("const c = {x: 0};\nc.x++;\n");
        assert_eq!(filtered(&update, "S3500").len(), 0);
        let direct = js("const fixed = 1;\nfixed = 2;\n");
        assert_eq!(filtered(&direct, "S3500").len(), 1);
    }
}
