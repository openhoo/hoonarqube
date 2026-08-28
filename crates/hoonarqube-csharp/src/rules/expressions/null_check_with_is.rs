use super::support::binary_operands;
use super::support::first_named_child;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4201 — null checks merge into 'is' patterns.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn is_pattern_name<'a>(operand: Node<'_>, source: &'a str) -> Option<&'a str> {
        let operand = unwrap_parentheses(operand);
        if operand.kind() != "is_expression" {
            return None;
        }
        first_named_child(operand)
            .filter(|target| target.kind() == "identifier")
            .map(|target| node_text(target, source))
    }
    fn negated_pattern_name<'a>(operand: Node<'_>, source: &'a str) -> Option<&'a str> {
        let operand = unwrap_parentheses(operand);
        if operand.kind() != "prefix_unary_expression" || operator_of(operand) != Some("!") {
            return None;
        }
        first_named_child(operand).and_then(|inner| is_pattern_name(inner, source))
    }
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        let logical_operator = operator_of(expression);
        if is_error_tainted(expression) || !matches!(logical_operator, Some("&&" | "||")) {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let candidates = [(left, right), (right, left)];
        if let Some((null_check, _)) = candidates.into_iter().find(|(null_check, pattern)| {
            let expected_null_operator = if logical_operator == Some("&&") {
                "!="
            } else {
                "=="
            };
            operator_of(*null_check) == Some(expected_null_operator)
                && null_operand_name(*null_check, source).is_some_and(|null_name| {
                    let pattern_name = if logical_operator == Some("&&") {
                        is_pattern_name(*pattern, source)
                    } else {
                        negated_pattern_name(*pattern, source)
                    };
                    pattern_name == Some(null_name)
                })
        }) {
            issues.push(issue(
                language,
                "S4201",
                "Remove this unnecessary null check; 'is' returns false for nulls.",
                range_of(null_check, source),
            ));
        }
    }
    issues
}

fn null_operand_name<'a>(comparison: Node<'_>, source: &'a str) -> Option<&'a str> {
    let (left, right) = binary_operands(comparison)?;
    if left.kind() == "null_literal" && right.kind() == "identifier" {
        Some(node_text(right, source))
    } else if right.kind() == "null_literal" && left.kind() == "identifier" {
        Some(node_text(left, source))
    } else {
        None
    }
}

fn unwrap_parentheses(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(inner) = first_named_child(node) else {
            break;
        };
        node = inner;
    }
    node
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4201_plain_method_has_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M(object x)\n    {\n        Keep(x);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4201").is_empty());
    }

    #[test]
    fn s4201_flags_conjunction_of_null_check_and_predefined_is_pattern() {
        let report = analyze_default(
            "class A\n{\n    void M(object x)\n    {\n        var typed = x != null && x is string;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4201");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let swapped = analyze_default(
            "class A\n{\n    void M(object x)\n    {\n        var typed = x is string && x != null;\n    }\n}\n",
        );
        assert_eq!(with_key(&swapped, "csharpsquid:S4201").len(), 1);
    }

    #[test]
    fn s4201_non_matching_logical_shapes_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(object x)\n    {\n        var opposite = x == null && x is string;\n        var plain = x is Widget;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4201").is_empty());
    }

    #[test]
    fn s4201_mismatched_names_and_disjunction_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(object x, object y)\n    {\n        var other = x == null && y is Widget;\n        var either = x == null || x is Widget;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4201").is_empty());
    }
}
