use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{expression_name, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2755 — XML resolvers that can reach external entities enable
/// XXE attacks.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        let enables_external_entities = expression_name(left, source) == Some("XmlResolver")
            && left.kind() == "member_access_expression"
            && right.kind() == "object_creation_expression"
            && node_text(right, source).contains("XmlUrlResolver");
        if enables_external_entities {
            issues.push(issue(
                language,
                "S2755",
                "Disable access to external entities in XML parsing.",
                range_of(assignment, source),
            ));
        }
    }
    issues
}
