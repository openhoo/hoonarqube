use super::support::identifier_usages;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, integer_literal_value, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4426 — weak asymmetric providers and short keys give way.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const WEAK_ASYMMETRIC_PROVIDERS: [&str; 2] =
        ["RSACryptoServiceProvider", "DSACryptoServiceProvider"];
    const MINIMUM_ASYMMETRIC_KEY_SIZE: u64 = 2048;
    let mut issues: Vec<Issue> = identifier_usages(root, source, &WEAK_ASYMMETRIC_PROVIDERS)
        .into_iter()
        .map(|identifier| {
            issue(
                language,
                "S4426",
                "Generate this key with 'RSA.Create' at 2048 bits or more.",
                range_of(identifier),
            )
        })
        .collect();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some((target, value)) = binary_operands(assignment) else {
            continue;
        };
        if !node_text(target, source).ends_with("KeySize") || value.kind() != "integer_literal" {
            continue;
        }
        let undersized = integer_literal_value(node_text(value, source))
            .is_some_and(|bits| bits < MINIMUM_ASYMMETRIC_KEY_SIZE);
        if undersized {
            issues.push(issue(
                language,
                "S4426",
                "Keep cryptographic keys at 2048 bits or more.",
                range_of(assignment),
            ));
        }
    }
    issues
}
