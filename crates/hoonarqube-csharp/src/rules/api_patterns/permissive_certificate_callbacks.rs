use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::{expression_name, lambda_shape, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4830 — callbacks that accept any certificate disable
/// TLS server verification entirely.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if operator_of(assignment) != Some("=") {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        if !CERT_VALIDATION_CALLBACKS.contains(&expression_name(left, source).unwrap_or("")) {
            continue;
        }
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        let accepts_everything = match right.kind() {
            "lambda_expression" => lambda_shape(right, source).is_some_and(|(_, body)| {
                body.kind() == "boolean_literal" && node_text(body, source) == "true"
            }),
            _ => false,
        };
        if accepts_everything {
            issues.push(issue(
                language,
                "S4830",
                "Validate the certificate chain here instead of accepting everything.",
                range_of(assignment),
            ));
        }
    }
    issues
}

/// Certificate-validation callback properties.
const CERT_VALIDATION_CALLBACKS: [&str; 2] = [
    "ServerCertificateValidationCallback",
    "ServerCertificateCustomValidationCallback",
];
