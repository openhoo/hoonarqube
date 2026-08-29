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
        if unary.parent().is_some_and(|parent| {
            parent.kind() == "prefix_unary_expression" && operator_of(parent) == Some(operator)
        }) {
            continue;
        }
        let inner = first_named_child(unary).filter(|operand| {
            operand.kind() == "prefix_unary_expression" && operator_of(*operand) == Some(operator)
        });
        if let Some(inner) = inner {
            let outer_operator = operator_token(unary, operator).unwrap_or(unary);
            let inner_operator = operator_token(inner, operator).unwrap_or(inner);
            issues.push(issue(
                language,
                "S2761",
                format!("Use the '{operator}' operator just once or not at all."),
                range_from_byte_offsets(
                    outer_operator.start_byte(),
                    inner_operator.end_byte(),
                    source,
                ),
            ));
        }
    }
    issues
}

fn operator_token<'t>(unary: Node<'t>, operator: &str) -> Option<Node<'t>> {
    let mut cursor = unary.walk();
    unary
        .children(&mut cursor)
        .find(|child| !child.is_named() && child.kind() == operator)
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

    #[test]
    fn s2761_reports_operator_chains_once_with_exact_multiline_range() {
        let report = analyze_default("class C { bool M(bool value) => !\n!!value; }");
        let flagged = with_key(&report, "csharpsquid:S2761");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[0].range.end.line, 2);
    }
}
