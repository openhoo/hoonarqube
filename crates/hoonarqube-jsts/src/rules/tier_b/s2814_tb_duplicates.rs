// Rule module s2814_tb_duplicates (generated).
use crate::engine::scope_model::TbModel;
use crate::support::{IssueSink, RuleScope};

/// S2814 (JS only) — `var`/function declared twice in the same scope.
pub(crate) fn check_tb_duplicates(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for (_, second, name) in &model.duplicates {
        sink.emit_span(
            RuleScope::JsOnly,
            "S2814",
            &format!("'{name}' is already defined."),
            *second,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn duplicate_var_declarations_in_same_scope_flagged() {
        let flagged = js("var dup = 1;\nvar dup = 2;\n");
        assert_eq!(filtered(&flagged, "S2814").len(), 1);
        let clean = js("var first = 1;\nvar second = 2;\n");
        assert_eq!(filtered(&clean, "S2814").len(), 0);
    }

    #[test]
    fn every_redeclaration_is_reported_once_without_pairwise_duplicates() {
        let report = js("var dup;\nvar dup;\nvar dup;\n");
        let issues: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S2814"))
            .collect();
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].range.start.line, 2);
        assert_eq!(issues[1].range.start.line, 3);
    }
}
