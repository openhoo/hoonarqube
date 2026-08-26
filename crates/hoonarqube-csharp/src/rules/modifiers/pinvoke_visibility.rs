use super::support::accessibility_rank;
use super::support::has_any_attribute;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4214 — P/Invoke entry points stay hidden behind internal
/// wrappers; `protected` and `public` expose them.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if !has_modifier(&modifiers, "extern")
            || !has_any_attribute(method, source, &["DllImport"])
            || !matches!(accessibility_rank(&modifiers), 4..=6)
        {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4214",
            "Make this P/Invoke method 'internal' or more restricted.",
            range_of(name, source),
        ));
    }
    issues
}
