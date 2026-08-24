use super::support::body_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3880 — finalizers either work or disappear.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for destructor in collect_kinds(root, &["destructor_declaration"]) {
        if is_error_tainted(destructor) {
            continue;
        }
        let Some(body) = body_of(destructor) else {
            continue;
        };
        let mut cursor = body.walk();
        if !body.children(&mut cursor).any(|child| child.is_named()) {
            issues.push(issue(
                language,
                "S3880",
                "Remove this empty finalizer.",
                range_of(destructor),
            ));
        }
    }
    issues
}
