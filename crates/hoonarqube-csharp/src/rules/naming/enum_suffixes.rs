use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2344 — enum names carry neither an `Enum` nor a `Flags`
/// suffix.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for enum_node in collect_kinds(root, &["enum_declaration"]) {
        let Some(name) = enum_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        for suffix in ["Enum", "Flags"] {
            if name_text.ends_with(suffix) {
                issues.push(issue(
                    language,
                    "S2344",
                    format!("Rename this enumeration to remove the '{suffix}' suffix."),
                    range_of(name, source),
                ));
                break;
            }
        }
    }
    issues
}
