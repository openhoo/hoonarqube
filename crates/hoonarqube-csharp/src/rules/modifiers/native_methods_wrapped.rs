use super::support::has_any_attribute;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4200 — native entry points belong behind managed wrappers,
/// so every `DllImport` extern declaration is flagged.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if !has_modifier(&modifiers, "extern") || !has_any_attribute(method, source, &["DllImport"])
        {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4200",
            "Wrap this native method behind a managed API.",
            range_of(name),
        ));
    }
    issues
}
