use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::{
    banned_member_accesses, enclosing_type, member_declarations_of_kind,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3971 — `GC.SuppressFinalize` usage is tracked everywhere.
/// csharpsquid:S3234 additionally flags calls in finalizerless types where it
/// does nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for access in banned_member_accesses(root, source, "GC", &["SuppressFinalize"]) {
        issues.push(issue(
            language,
            "S3971",
            "Track uses of 'GC.SuppressFinalize'.",
            range_of(access),
        ));
        if enclosing_type(access).is_none_or(|type_node| !has_destructor(type_node)) {
            issues.push(issue(
                language,
                "S3234",
                "Only call 'GC.SuppressFinalize' when a finalizer is defined.",
                range_of(access),
            ));
        }
    }
    issues
}

/// Whether a type declares a finalizer.
fn has_destructor(type_node: Node<'_>) -> bool {
    !member_declarations_of_kind(type_node, "destructor_declaration").is_empty()
}
