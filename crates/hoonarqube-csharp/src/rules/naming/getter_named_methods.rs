use super::support::TYPE_DECLARATION_KINDS;
use super::support::has_explicit_interface_specifier;
use super::support::type_members;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4059 — accessor methods (`GetFoo`) do not duplicate property
/// names (`Foo`, case-insensitively).
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let properties: Vec<(&str, String)> = type_members(type_node)
            .into_iter()
            .filter(|member| member.kind() == "property_declaration")
            .filter_map(|property| property.child_by_field_name("name"))
            .map(|name| {
                let text = node_text(name, source);
                (text, text.to_ascii_lowercase())
            })
            .collect();
        for member in type_members(type_node) {
            if member.kind() != "method_declaration" || has_explicit_interface_specifier(member) {
                continue;
            }
            let Some(name) = member.child_by_field_name("name") else {
                continue;
            };
            let method_name = node_text(name, source);
            let lowered = method_name.to_ascii_lowercase();
            let Some(candidate) = lowered.strip_prefix("get").filter(|rest| !rest.is_empty())
            else {
                continue;
            };
            if let Some((original, _)) = properties
                .iter()
                .find(|(_, property_lower)| *property_lower == candidate)
            {
                issues.push(issue(
                    language,
                    "S4059",
                    format!("Rename this accessor method; it duplicates property \"{original}\"."),
                    range_of(name, source),
                ));
            }
        }
    }
    issues
}
