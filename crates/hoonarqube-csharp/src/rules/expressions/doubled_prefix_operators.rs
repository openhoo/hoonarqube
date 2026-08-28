use super::support::first_named_child;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_from_byte_offsets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2761 — prefix operators do not double up.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &["prefix_unary_expression"]) {
        let Some(operator) = operator_of(unary) else {
            continue;
        };
        if is_error_tainted(unary) || !matches!(operator, "!" | "~") {
            continue;
        }
        let doubled = first_named_child(unary).is_some_and(|operand| {
            operand.kind() == "prefix_unary_expression" && operator_of(operand) == Some(operator)
        });
        if doubled {
            issues.push(issue(
                language,
                "S2761",
                format!("Use the '{operator}' operator just once or not at all."),
                range_from_byte_offsets(unary.start_byte(), unary.start_byte() + 2, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2761_flags_doubled_prefix_operators() {
        let bad = analyze_default("class C { bool M(bool value) => !!value; }");
        assert_eq!(with_key(&bad, "csharpsquid:S2761").len(), 1);

        let good = analyze_default("class C { bool M(bool value) => !value; }");
        assert!(with_key(&good, "csharpsquid:S2761").is_empty());
    }
}
