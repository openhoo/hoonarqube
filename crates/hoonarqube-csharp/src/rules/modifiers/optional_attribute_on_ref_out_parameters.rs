use super::support::has_attribute;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::first_named_child;
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
            let optional = collect_kinds(parameter, &["attribute"])
                .into_iter()
                .find(|attribute| node_text(*attribute, source).starts_with("Optional"))
                .and_then(first_named_child)
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
