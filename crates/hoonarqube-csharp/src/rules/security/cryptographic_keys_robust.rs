use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    binary_operands, creation_type_text, integer_literal_value, operator_of,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4426 — weak asymmetric providers and short keys give way.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const MINIMUM_ASYMMETRIC_KEY_SIZE: u64 = 2048;
    let mut algorithms_by_variable = std::collections::HashMap::new();
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        let algorithm = match creation_type_text(creation, source) {
            "RSACryptoServiceProvider" => "RSA",
            "DSACryptoServiceProvider" => "DSA",
            _ => continue,
        };
        if let Some(variable) = ancestors_of(creation)
            .find(|ancestor| ancestor.kind() == "variable_declarator")
            .and_then(|declarator| declarator.child_by_field_name("name"))
        {
            algorithms_by_variable.insert(node_text(variable, source), algorithm);
        }
        issues.push(issue(
            language,
            "S4426",
            format!("Use a key length of at least 2048 bits for {algorithm} cipher algorithm."),
            range_of(creation, source),
        ));
    }
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
            let variable = node_text(target, source).split('.').next().unwrap_or("");
            let algorithm = algorithms_by_variable
                .get(variable)
                .copied()
                .unwrap_or("RSA");
            issues.push(issue(
                language,
                "S4426",
                format!(
                    "Use a key length of at least 2048 bits for {algorithm} cipher algorithm. This assignment does not update the underlying key size."
                ),
                range_of(assignment, source),
            ));
        }
    }
    issues
}
