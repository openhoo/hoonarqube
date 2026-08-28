use super::support::TYPE_DECLARATION_KINDS;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4041 — type names do not match namespace segments
/// (case-insensitively).
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if !has_modifier(&modifiers_of(type_node, source), "public") {
            continue;
        }
        let Some(name) = type_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        let lowered = name_text.to_ascii_lowercase();
        if FRAMEWORK_NAMESPACES
            .iter()
            .any(|namespace| namespace.eq_ignore_ascii_case(&lowered))
        {
            issues.push(issue(
                language,
                "S4041",
                format!(
                    "Change the name of type '{name_text}' to be different from an existing framework namespace."
                ),
                range_of(name, source),
            ));
        }
    }
    issues
}

const FRAMEWORK_NAMESPACES: [&str; 12] = [
    "collections",
    "componentmodel",
    "configuration",
    "data",
    "diagnostics",
    "globalization",
    "io",
    "net",
    "reflection",
    "resources",
    "text",
    "threading",
];
