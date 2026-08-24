use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{binary_operands, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2589 — boolean literals next to a short-circuit operator
/// change nothing about the result. Comparisons against literals and
/// doubled negations are covered by S1125 and S2761 instead.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || !matches!(operator_of(expression), Some("&&" | "||")) {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        for operand in [left, right] {
            if operand.kind() == "boolean_literal" {
                issues.push(issue(
                    language,
                    "S2589",
                    "This boolean literal is gratuitous in a short-circuit operation.",
                    range_of(operand),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S2589";

    #[test]
    fn s2589_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2589_literal_on_either_side_flags() {
        let report = analyze_default(
            "class C {\n    bool M(bool ready) {\n        return ready && true;\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s2589_both_literals_yield_two_findings() {
        let report =
            analyze_default("class C {\n    bool M() {\n        return true || false;\n    }\n}\n");
        assert_eq!(with_key(&report, KEY).len(), 2);
    }

    #[test]
    fn s2589_comparison_against_literal_belongs_to_s1125() {
        let report = analyze_default(
            "class C {\n    bool M(bool flag) {\n        return flag == true;\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2589_non_short_circuit_operators_are_ignored() {
        let report = analyze_default(
            "class C {\n    bool M(bool a, bool b) {\n        return a & true | b;\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2589_plain_boolean_operands_stay_clean() {
        let report = analyze_default(
            "class C {\n    bool M(bool a, bool b) {\n        return a && b;\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
