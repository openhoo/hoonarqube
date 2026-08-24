use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{member_declarations_of_kind, overloaded_operator};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3875 — overloading `==` on reference types invites identity
/// confusion; structs are exempt.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        for declaration in member_declarations_of_kind(class_declaration, "operator_declaration") {
            if is_error_tainted(declaration) || overloaded_operator(declaration) != Some("==") {
                continue;
            }
            issues.push(issue(
                language,
                "S3875",
                "Do not overload the equality operator on this reference type.",
                range_of(declaration),
            ));
        }
    }
    let _ = source;
    issues
}
