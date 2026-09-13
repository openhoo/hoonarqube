use super::support::TYPE_DECLARATION_KINDS;
use super::support::has_explicit_interface_specifier;
use super::support::type_members;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4136 — overloads of a method sit together within their type:
/// a reoccurrence after a differently named method declaration is flagged.
/// Adjacency is computed over method declarations only; comments, attribute
/// lists, and other non-method members never split a group.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let methods: Vec<(String, String, Node<'_>)> = type_members(type_node)
            .into_iter()
            .filter(|member| {
                member.kind() == "method_declaration" && !has_explicit_interface_specifier(*member)
            })
            .filter_map(|member| {
                let name = member.child_by_field_name("name")?;
                let method_name = node_text(name, source);
                Some((
                    method_name.to_ascii_lowercase(),
                    method_name.to_string(),
                    name,
                ))
            })
            .collect();
        let mut last_index_by_name: Vec<(String, usize, Node<'_>)> = Vec::new();
        for (index, (lowered, method_name, name)) in methods.iter().enumerate() {
            if let Some(entry) = last_index_by_name
                .iter_mut()
                .find(|(seen, _, _)| seen == lowered)
            {
                if entry.1 + 1 != index {
                    issues.push(issue(
                        language,
                        "S4136",
                        format!("All '{method_name}' method overloads should be adjacent."),
                        range_of(entry.2, source),
                    ));
                }
                entry.1 = index;
            } else {
                last_index_by_name.push((lowered.clone(), index, *name));
            }
        }
    }
    issues
}
