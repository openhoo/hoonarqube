use super::support::has_attribute;
use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3450 — `[DefaultParameterValue]` only takes effect together
/// with `[Optional]`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parameter in collect_kinds(root, &["parameter"]) {
        let attributes = attributes_of(parameter, source);
        if has_attribute(&attributes, "DefaultParameterValue")
            && !has_attribute(&attributes, "Optional")
        {
            let default_attribute = collect_kinds(parameter, &["attribute"])
                .into_iter()
                .find(|attribute| {
                    node_text(*attribute, source).starts_with("DefaultParameterValue")
                })
                .unwrap_or(parameter);
            issues.push(issue(
                language,
                "S3450",
                "Add the 'Optional' attribute to this parameter.",
                range_of(default_attribute, source),
            ));
        }
    }
    issues
}
