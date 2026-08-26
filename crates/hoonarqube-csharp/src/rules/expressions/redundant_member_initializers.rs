use super::support::binary_operands;
use super::support::expression_name;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3604 — object initializers assigning a member to an equally
/// named variable (`new P { X = x }`).
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for initializer in collect_kinds(root, &["initializer_expression"]) {
        if initializer
            .parent()
            .is_none_or(|parent| parent.kind() != "object_creation_expression")
        {
            continue;
        }
        let mut cursor = initializer.walk();
        for entry in initializer
            .children(&mut cursor)
            .filter(|child| child.kind() == "assignment_expression")
        {
            if is_error_tainted(entry) {
                continue;
            }
            let Some((left, right)) = binary_operands(entry) else {
                continue;
            };
            if expression_name(left, source).is_some()
                && expression_name(left, source) == expression_name(right, source)
            {
                issues.push(issue(
                    language,
                    "S3604",
                    "This member initializer assigns the member to itself.",
                    range_of(entry, source),
                ));
            }
        }
    }
    issues
}
