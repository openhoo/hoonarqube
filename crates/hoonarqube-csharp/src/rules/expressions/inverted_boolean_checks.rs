use super::support::first_named_child;
use super::support::operator_of;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1940 — negated equality flips into the opposite operator.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &["prefix_unary_expression"]) {
        if is_error_tainted(unary) || operator_of(unary) != Some("!") {
            continue;
        }
        let invertible = first_named_child(unary).is_some_and(|operand| {
            operand.kind() == "parenthesized_expression"
                && first_named_child(operand).is_some_and(|inner| {
                    inner.kind() == "binary_expression"
                        && matches!(operator_of(inner), Some("==" | "!="))
                })
        });
        if invertible {
            issues.push(issue(
                language,
                "S1940",
                "Invert this comparison instead of negating it.",
                range_of(unary),
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

    // DISCREPANCY vs SonarQube S1940: the rule currently never fires.
    // `operator_of` (expressions/support.rs) matches only its 23-entry
    // operator table, which lacks `!`, so `prefix_unary_expression` nodes
    // yield `None` and every `!(a == b)` is silently skipped. Flagging
    // cases are omitted until the implementation recognizes unary tokens;
    // SQ would report each invertible negation once at its line.
}
