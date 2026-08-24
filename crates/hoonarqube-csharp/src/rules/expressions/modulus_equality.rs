use super::support::comparisons;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2197 — remainders compare against ranges, not values.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    fn modulus(operand: Node<'_>) -> bool {
        operand.kind() == "binary_expression" && operator_of(operand) == Some("%")
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if matches!(operator_of(expression), Some("==" | "!=")) && (modulus(left) || modulus(right))
        {
            issues.push(issue(
                language,
                "S2197",
                "Compare remainder results against ranges, not single values.",
                range_of(expression),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2197_plain_arithmetic_has_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M(int total)\n    {\n        var remainder = total % 4;\n        var bounded = total > 3;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2197").is_empty());
    }

    #[test]
    fn s2197_flags_equality_comparisons_on_remainders() {
        let report = analyze_default(
            "class A\n{\n    void M(int i, int j)\n    {\n        var even = i % 2 == 0;\n        var odd = j % 3 != 1;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2197");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2197_remainder_on_right_counts_but_relational_forms_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(int i)\n    {\n        var even = 0 == i % 2;\n        var small = i % 2 < 2;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2197");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }
}
