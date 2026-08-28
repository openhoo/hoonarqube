use super::support::accessor_keyword;
use super::support::accessors_of;
use super::support::getter_field;
use super::support::name_anchor;
use super::support::setter_field;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2292 — trivial getter/setter pairs become auto-properties.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let accessors = accessors_of(property);
        let reads_backing_field = accessors.iter().any(|accessor| {
            accessor_keyword(*accessor, source) == "get"
                && getter_field(*accessor, source).is_some()
        });
        let writes_backing_field = accessors.iter().any(|accessor| {
            accessor_keyword(*accessor, source) == "set"
                && setter_field(*accessor, source).is_some()
        });
        if reads_backing_field && writes_backing_field && accessors.len() == 2 {
            issues.push(issue(
                language,
                "S2292",
                "Make this an auto-implemented property and remove its backing field.",
                range_of(name_anchor(property), source),
            ));
        }
    }
    issues
}
