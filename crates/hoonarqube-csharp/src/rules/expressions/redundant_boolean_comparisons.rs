use super::support::boolean_literal_side;
use super::support::comparisons;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1125 — identity comparisons against boolean literals drop
/// the literal.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let literal = boolean_literal_side(left, right, source);
        let redundant = matches!(
            (operator_of(expression), literal),
            (Some("=="), Some(true)) | (Some("!="), Some(false))
        );
        if redundant {
            issues.push(issue(
                language,
                "S1125",
                "Remove the redundant boolean literal from this comparison.",
                range_of(expression, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1125_plain_boolean_uses_have_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M(bool flag)\n    {\n        Keep(flag);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1125").is_empty());
    }

    #[test]
    fn s1125_flags_identity_with_true_and_difference_with_false() {
        let report = analyze_default(
            "class A\n{\n    void M(bool flag, bool gate)\n    {\n        var a = flag == true;\n        var b = gate != false;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1125");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s1125_flags_literal_on_the_left_operand_too() {
        let report = analyze_default(
            "class A\n{\n    void M(bool flag, bool gate)\n    {\n        var a = true == flag;\n        var b = false != gate;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1125");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s1125_non_redundant_shapes_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(bool flag, bool gate)\n    {\n        var negated = flag == false;\n        var kept = gate != true;\n        var conjunct = flag && true;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1125").is_empty());
    }
}
