use super::support::comparisons;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::operator_of;
use super::support::resolved_identifier_type;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2688 — NaN compares unequal to everything, itself included.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("==" | "!=")) {
            continue;
        }
        let numeric_type = [left, right]
            .into_iter()
            .find_map(|operand| nan_type(operand, source));
        if let Some(numeric_type) = numeric_type {
            issues.push(issue(
                language,
                "S2688",
                format!("Use {numeric_type}.IsNaN() instead."),
                range_of(expression, source),
            ));
        }
    }
    issues
}

fn nan_type(operand: Node<'_>, source: &str) -> Option<&'static str> {
    if operand.kind() == "identifier" {
        return (node_text(operand, source) == "NaN"
            && resolved_identifier_type(operand, source).is_none())
        .then_some("double");
    }
    if operand.kind() != "member_access_expression"
        || expression_name(operand, source) != Some("NaN")
    {
        return None;
    }
    let receiver = first_named_child(operand).map(|node| node_text(node, source))?;
    match receiver {
        "float" | "Single" | "System.Single" => Some("float"),
        "double" | "Double" | "System.Double" => Some("double"),
        _ => None,
    }
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

    #[test]
    fn s2688_ignores_bound_or_unrelated_nan_members() {
        let report = analyze_default(
            "class C { bool M(double NaN, double value) => value == NaN || value == Constants.NaN; }",
        );
        assert!(with_key(&report, "csharpsquid:S2688").is_empty());
    }
}
