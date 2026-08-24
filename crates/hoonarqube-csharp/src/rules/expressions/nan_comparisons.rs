use super::support::comparisons;
use super::support::expression_name;
use super::support::operator_of;
use crate::cst::{issue, range_of};
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2688 — NaN compares unequal to everything, itself included.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("==" | "!=")) {
            continue;
        }
        let names_nan = [left, right]
            .iter()
            .any(|operand| expression_name(*operand, source) == Some("NaN"));
        if names_nan {
            issues.push(issue(
                language,
                "S2688",
                "Use 'IsNaN' to test for NaN; equality comparisons never hold.",
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
    fn s2688_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2688").is_empty());
    }

    #[test]
    fn s2688_flags_nan_equality_with_full_comparison_range() {
        let report = analyze_default(
            "class C\n{\n    void M(double x)\n    {\n        if (x == NaN)\n        {\n            Stop();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2688");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[0].range.end.line, 5);
    }

    #[test]
    fn s2688_flags_inequality_and_qualified_nan_operand() {
        let report = analyze_default(
            "class C\n{\n    void M(double x)\n    {\n        var a = x != double.NaN;\n        var b = NaN != x;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2688");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2688_ignores_ordering_comparisons_against_nan() {
        let report = analyze_default(
            "class C\n{\n    void M(double x)\n    {\n        if (x < NaN || x > NaN)\n        {\n            Stop();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2688").is_empty());
    }
}
