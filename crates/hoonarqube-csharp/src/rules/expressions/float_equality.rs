use super::support::comparisons;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1244 — floating-point equality needs a tolerance.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let float_side = is_floating_literal(left, source) || is_floating_literal(right, source);
        let Some(operator @ ("==" | "!=")) = operator_of(expression) else {
            continue;
        };
        if float_side {
            let operator_node = collect_operator(expression, operator).unwrap_or(expression);
            issues.push(issue(
                language,
                "S1244",
                if operator == "==" {
                    "Do not check floating point equality with exact values, use a range instead."
                } else {
                    "Do not check floating point inequality with exact values, use a range instead."
                },
                range_of(operator_node, source),
            ));
        }
    }
    issues
}

fn is_floating_literal(node: Node<'_>, source: &str) -> bool {
    node.kind() == "real_literal"
        && !node_text(node, source)
            .chars()
            .last()
            .is_some_and(|suffix| matches!(suffix, 'm' | 'M'))
}

fn collect_operator<'t>(expression: Node<'t>, operator: &str) -> Option<Node<'t>> {
    let mut cursor = expression.walk();
    expression
        .children(&mut cursor)
        .find(|child| !child.is_named() && child.kind() == operator)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1244_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1244").is_empty());
    }

    #[test]
    fn s1244_flags_real_literal_equality() {
        let report = analyze_default(
            "class C\n{\n    void M(double d)\n    {\n        if (d == 0.1)\n        {\n            Close();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1244");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[0].range.end.line, 5);
    }

    #[test]
    fn s1244_flags_reversed_and_suffixed_literal_forms() {
        let report = analyze_default(
            "class C\n{\n    void M(double d)\n    {\n        var a = 0.5 == d;\n        var b = d != 1.5f;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1244");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s1244_ignores_integer_relational_and_identifier_comparisons() {
        let report = analyze_default(
            "class C\n{\n    void M(int n, double d)\n    {\n        if (n == 42) { Hit(); }\n        if (d < 0.5) { Near(); }\n        if (d == d) { Same(); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1244").is_empty());
    }

    #[test]
    fn s1244_flags_exponent_notation_literal() {
        let report = analyze_default(
            "class C\n{\n    void M(double d)\n    {\n        var e = d == 1e-3;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1244");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s1244_ignores_exact_decimal_equality() {
        let report = analyze_default("class C { bool M(decimal value) => value == 0.1m; }");
        assert!(with_key(&report, "csharpsquid:S1244").is_empty());
    }
}
