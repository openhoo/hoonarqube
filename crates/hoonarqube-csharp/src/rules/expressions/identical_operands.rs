use super::support::binary_operands;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1764 — identical sub-expressions on both sides of an
/// arithmetic or relational operator.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some(operator) = operator_of(expression) else {
            continue;
        };
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        if IDENTICAL_OPERAND_OPERATORS.contains(&operator)
            && !node_text(left, source).is_empty()
            && node_text(left, source) == node_text(right, source)
        {
            issues.push(issue(
                language,
                "S1764",
                "Identical sub-expressions are used on both sides of this operator.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// Operators whose identical operands betray a bug (`a * a` may be intended,
/// `a - a` never is).
const IDENTICAL_OPERAND_OPERATORS: [&str; 7] = ["-", "/", "%", "<", ">", "<=", ">="];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1764_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1764").is_empty());
    }

    #[test]
    fn s1764_flags_division_and_modulo_at_distinct_lines() {
        let report = analyze_default(
            "class C\n{\n    void M(int x)\n    {\n        var a = x / x;\n        var b = x % x;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1764");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s1764_flags_relational_identical_operands() {
        let report = analyze_default(
            "class C\n{\n    void M(int a)\n    {\n        if (a < a) { Less(); }\n        if (a >= a) { AtLeast(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1764");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s1764_ignores_excluded_operators_and_distinct_operands() {
        let report = analyze_default(
            "class C\n{\n    void M(int a, int b)\n    {\n        var e = a == a;\n        var d = a - b;\n        var p = a * a;\n        var l = a && a;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1764").is_empty());
    }

    #[test]
    fn s1764_parenthesized_left_operand_parses_as_cast_not_subtraction() {
        let report = analyze_default(
            "class C\n{\n    void M(int a)\n    {\n        var s = (a) - (a);\n        var m = a - (a);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1764");
        // tree-sitter-c-sharp 0.23.5 parses `(a) - (a)` as a cast_expression
        // combined with prefix unary minus, so no binary_expression exists
        // here and neither initializer reaches this rule.
        assert!(flagged.is_empty());
    }
}
