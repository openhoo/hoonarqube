use super::support::has_any_accessibility;
use super::support::has_modifier;
use super::support::type_declared_rank;
use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, issue, modifiers_of, node_text, range_of, simple_name,
};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3260 — private types that nothing in this file derives from
/// gain nothing by staying open for inheritance. Partial types span files
/// and stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let bases = referenced_base_names(root, source);
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &["class_declaration", "record_declaration"]) {
        let modifiers = modifiers_of(type_node, source);
        if has_modifier(&modifiers, "partial")
            || has_modifier(&modifiers, "abstract")
            || has_modifier(&modifiers, "sealed")
            || has_modifier(&modifiers, "static")
        {
            continue;
        }
        // Private means explicitly marked, or nested without accessibility.
        if has_any_accessibility(&modifiers) && !has_modifier(&modifiers, "private") {
            continue;
        }
        if !has_any_accessibility(&modifiers) && type_declared_rank(type_node, source) != 1 {
            continue;
        }
        let Some(name) = type_node.child_by_field_name("name") else {
            continue;
        };
        if bases.contains(simple_name(node_text(name, source))) {
            continue;
        }
        issues.push(issue(
            language,
            "S3260",
            "Mark this private type 'sealed'.",
            range_of(name, source),
        ));
    }
    issues
}

/// Every type name used as a base somewhere in the file.
fn referenced_base_names(root: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .iter()
        .flat_map(|declaration| base_simple_names(*declaration, source))
        .map(str::to_string)
        .collect()
}
