use super::support::TYPE_DECLARATION_KINDS;
use super::support::has_explicit_interface_specifier;
use super::support::type_members;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4261 — async methods take the `Async` suffix and no others.
/// Overridden methods keep whatever name they override.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let non_interface_types: Vec<Node> = collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_node| type_node.kind() != "interface_declaration")
        .collect();
    for type_node in non_interface_types {
        for member in type_members(type_node) {
            if member.kind() != "method_declaration" || has_explicit_interface_specifier(member) {
                continue;
            }
            let Some(name) = member.child_by_field_name("name") else {
                continue;
            };
            let mut modifier_cursor = member.walk();
            let modifiers: Vec<&str> = member
                .children(&mut modifier_cursor)
                .filter(|child| child.kind() == "modifier")
                .map(|modifier| node_text(modifier, source))
                .collect();
            if modifiers.contains(&"override") {
                continue;
            }
            let is_async = modifiers.contains(&"async");
            let method_name = node_text(name, source);
            let message = (is_async && !method_name.ends_with("Async"))
                .then_some("Add the 'Async' suffix to the name of this method.");
            if let Some(message) = message {
                issues.push(issue(language, "S4261", message, range_of(name, source)));
            }
        }
    }
    issues
}
