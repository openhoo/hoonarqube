use super::support::has_attribute;
use super::support::has_modifier;
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
            issues.push(issue(
                language,
                "S3447",
                "Remove this '[Optional]' attribute; the parameter is by reference.",
                range_of(parameter),
            ));
        }
    }
    issues
}
