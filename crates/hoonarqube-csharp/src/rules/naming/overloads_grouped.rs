use super::support::TYPE_DECLARATION_KINDS;
use super::support::has_explicit_interface_specifier;
use super::support::type_members;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4136 — overloads of a method sit together within their type:
/// a reoccurrence after differently named members is flagged.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let mut last_index_by_name: Vec<(String, usize)> = Vec::new();
        for (index, member) in type_members(type_node).into_iter().enumerate() {
            if member.kind() != "method_declaration" || has_explicit_interface_specifier(member) {
                continue;
            }
            let Some(name) = member.child_by_field_name("name") else {
                continue;
            };
            let method_name = node_text(name, source);
            let lowered = method_name.to_ascii_lowercase();
            if let Some(entry) = last_index_by_name
                .iter_mut()
                .find(|(seen, _)| *seen == lowered)
            {
                if entry.1 + 1 != index {
                    issues.push(issue(
                        language,
                        "S4136",
                        format!("Move this overload next to the other \"{method_name}\" methods."),
                        range_of(name),
                    ));
                }
                entry.1 = index;
            } else {
                last_index_by_name.push((lowered, index));
            }
        }
    }
    issues
}
