use super::support::comparisons;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::integer_literal_value;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3981 — collection sizes never compare against negatives.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn negative_value(operand: Node<'_>, source: &str) -> Option<i64> {
        if operand.kind() != "prefix_unary_expression" || operator_of(operand) != Some("-") {
            return None;
        }
        let literal = first_named_child(operand)?;
        integer_literal_value(node_text(literal, source))
            .and_then(|value| i64::try_from(value).ok())
            .map(|value| -value)
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let size_side = [left, right].iter().any(|o| count_member_tail(*o, source));
        let negative_side = [left, right]
            .iter()
            .any(|o| negative_value(*o, source).is_some());
        if size_side && negative_side {
            issues.push(issue(
                language,
                "S3981",
                "Collection sizes are never negative; fix this comparison.",
                range_of(expression, source),
            ));
        }
    }
    issues
}

/// Collection-count member tails (`Count`, `Length`).
fn count_member_tail(operand: Node<'_>, source: &str) -> bool {
    matches!(expression_name(operand, source), Some("Count" | "Length"))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3981_non_negative_bounds_have_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M(int[] items)\n    {\n        var roomy = items.Length < 10;\n        var empty_ok = items.Length < 0;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3981").is_empty());
    }

    #[test]
    fn s3981_flags_each_count_against_negative_bound() {
        let report = analyze_default(
            "class A\n{\n    void M(System.Collections.Generic.List<int> list, int[] items)\n    {\n        var a = list.Count < -1;\n        var b = -2 >= items.Length;\n        var c = list.Count == -3;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3981");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
        assert_eq!(flagged[2].range.start.line, 7);
    }

    #[test]
    fn s3981_plain_variables_and_non_literal_negatives_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(int size, int margin)\n    {\n        var plain = size < -1;\n        var symbolic = margin < -margin;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3981").is_empty());
    }
}
