use super::support::accessor_keyword;
use super::support::accessors_of;
use super::support::name_anchor;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2376 — write-only properties hide their intent.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) || accessors_of(property).is_empty() {
            continue;
        }
        let has_getter = accessors_of(property)
            .iter()
            .any(|accessor| accessor_keyword(*accessor, source) == "get");
        if !has_getter {
            issues.push(issue(
                language,
                "S2376",
                "Add a getter to this write-only property.",
                range_of(name_anchor(property)),
            ));
        }
    }
    issues
}
