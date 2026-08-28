use super::support::first_named_child;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1940 — negated equality flips into the opposite operator.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &["prefix_unary_expression"]) {
        if is_error_tainted(unary) || operator_of(unary) != Some("!") {
            continue;
        }
        let opposite = first_named_child(unary)
            .filter(|operand| operand.kind() == "parenthesized_expression")
            .and_then(first_named_child)
            .filter(|inner| inner.kind() == "binary_expression")
            .and_then(operator_of)
            .and_then(|operator| match operator {
                "==" => Some("!="),
                "!=" => Some("=="),
                _ => None,
            });
        if let Some(opposite) = opposite {
            issues.push(issue(
                language,
                "S1940",
                format!("Use the opposite operator ('{opposite}') instead."),
                range_of(unary, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1940_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1940").is_empty());
    }

    #[test]
    fn s1940_ignores_non_invertible_negations() {
        let report = analyze_default(
            "class C\n{\n    void M(bool a, bool b, int x, int y)\n    {\n        if (!a) { Stop(); }\n        if (!(x < y)) { Stop(); }\n        if (!(a && b)) { Stop(); }\n        if (!(a)) { Stop(); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1940").is_empty());
    }

    #[test]
    fn s1940_flags_negated_equality_and_inequality() {
        let report = analyze_default(
            "class C { bool M(int left, int right) => !(left == right) || !(left != right); }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1940").len(), 2);
    }
}
