use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3871 — exception types should be public so callers can catch
/// them across assembly boundaries.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let is_exception = base_simple_names(class_node, source).iter().any(|name| {
            matches!(
                *name,
                "Exception" | "SystemException" | "ApplicationException"
            )
        });
        if !is_exception || has_modifier(&modifiers_of(class_node, source), "public") {
            continue;
        }
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S3871",
            "Make this exception 'public'.",
            range_of(name, source),
        ));
    }
    issues
}
