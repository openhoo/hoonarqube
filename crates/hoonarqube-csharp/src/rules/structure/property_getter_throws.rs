use super::support::accessor_keyword;
use super::support::accessors_of;
use super::support::body_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::modifiers::subtree_contains_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2372 — property getters do not throw.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        for accessor in accessors_of(property) {
            if accessor_keyword(accessor, source) != "get" {
                continue;
            }
            let throws = body_of(accessor)
                .is_some_and(|body| subtree_contains_kind(body, "throw_statement"));
            if throws {
                issues.push(issue(
                    language,
                    "S2372",
                    "A property getter must not throw exceptions.",
                    range_of(accessor),
                ));
            }
        }
    }
    issues
}
