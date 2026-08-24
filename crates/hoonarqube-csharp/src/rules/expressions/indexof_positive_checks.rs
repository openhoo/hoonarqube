use super::support::comparisons;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::is_zero_literal;
use super::support::operator_of;
use crate::cst::{issue, range_of};
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2692 — '`IndexOf`' presence tests use '>=' not '>'.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn indexof_call(operand: Node<'_>, source: &str) -> bool {
        operand.kind() == "invocation_expression"
            && first_named_child(operand).is_some_and(|callee| {
                callee.kind() == "member_access_expression"
                    && matches!(
                        expression_name(callee, source),
                        Some("IndexOf" | "LastIndexOf")
                    )
            })
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let pattern = operator_of(expression) == Some(">")
            && ((indexof_call(left, source) && is_zero_literal(right, source))
                || (indexof_call(right, source) && is_zero_literal(left, source)));
        if pattern {
            issues.push(issue(
                language,
                "S2692",
                "Test 'IndexOf' results with '>= 0'; '>' wrongly rejects index 0.",
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
    fn s2692_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2692").is_empty());
    }

    #[test]
    fn s2692_flags_indexof_greater_than_zero() {
        let report = analyze_default(
            "class C\n{\n    void M(string s)\n    {\n        if (s.IndexOf('a') > 0)\n        {\n            Found();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2692");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[0].range.end.line, 5);
    }

    #[test]
    fn s2692_flags_lastindexof_and_reversed_zero_operand() {
        let report = analyze_default(
            "class C\n{\n    void M(string s)\n    {\n        var a = s.LastIndexOf('a') > 0;\n        var b = 0 > s.IndexOf(\"x\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2692");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2692_ignores_correct_and_unrelated_forms() {
        let report = analyze_default(
            "class C\n{\n    void M(string s)\n    {\n        if (s.IndexOf('a') >= 0) { Found(); }\n        if (s.IndexOf('a') > 1) { Found(); }\n        if (s.Contains('a')) { Found(); }\n        if (IndexOf(s) > 0) { Found(); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2692").is_empty());
    }

    #[test]
    fn s2692_flags_expression_bodied_member() {
        let report =
            analyze_default("class C\n{\n    bool M(string s) => s.IndexOf('x') > 0;\n}\n");
        let flagged = with_key(&report, "csharpsquid:S2692");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }
}
