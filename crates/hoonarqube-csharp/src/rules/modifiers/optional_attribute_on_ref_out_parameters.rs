use super::support::has_modifier;
use super::support::{attribute_named, has_attribute};
use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3447 — `[Optional]` cannot travel through by-reference
/// parameters.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parameter in collect_kinds(root, &["parameter"]) {
        let parameter_modifiers = modifiers_of(parameter, source);
        if !(has_modifier(&parameter_modifiers, "ref") || has_modifier(&parameter_modifiers, "out"))
        {
            continue;
        }
        if has_attribute(&attributes_of(parameter, source), "Optional") {
            let modifier = if has_modifier(&parameter_modifiers, "out") {
                "out"
            } else {
                "ref"
            };
            let optional = attribute_named(parameter, source, "Optional")
                .and_then(|attribute| attribute.child_by_field_name("name"))
                .unwrap_or(parameter);
            issues.push(issue(
                language,
                "S3447",
                format!("Remove the 'Optional' attribute, it cannot be used with '{modifier}'."),
                range_of(optional, source),
            ));
        }
    }
    issues
}
