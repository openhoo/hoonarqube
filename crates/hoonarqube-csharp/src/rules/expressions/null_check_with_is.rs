use super::support::binary_operands;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::null_check_name;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4201 — null checks merge into 'is' patterns.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn is_pattern_name<'a>(operand: Node<'_>, source: &'a str) -> Option<&'a str> {
        if operand.kind() != "is_expression" {
            return None;
        }
        first_named_child(operand)
            .filter(|target| target.kind() == "identifier")
            .and_then(|target| expression_name(target, source))
    }
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || operator_of(expression) != Some("&&") {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let redundant = [
            (
                null_check_name(left, source),
                is_pattern_name(right, source),
            ),
            (
                null_check_name(right, source),
                is_pattern_name(left, source),
            ),
        ]
        .iter()
        .any(|(null_name, pattern)| null_name.is_some() && *null_name == *pattern);
        if redundant {
            issues.push(issue(
                language,
                "S4201",
                "Drop the null check; the 'is' type test already rejects null.",
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
    fn s4201_plain_method_has_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M(object x)\n    {\n        Keep(x);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4201").is_empty());
    }

    #[test]
    fn s4201_flags_conjunction_of_null_check_and_predefined_is_pattern() {
        let report = analyze_default(
            "class A\n{\n    void M(object x)\n    {\n        var typed = x == null && x is string;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4201");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let swapped = analyze_default(
            "class A\n{\n    void M(object x)\n    {\n        var typed = x is string && x == null;\n    }\n}\n",
        );
        assert_eq!(with_key(&swapped, "csharpsquid:S4201").len(), 1);
    }

    #[test]
    fn s4201_canonical_not_null_and_named_type_shapes_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(object x)\n    {\n        var canonical = x != null && x is string;\n        var named = x == null && x is Widget;\n    }\n}\n",
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
