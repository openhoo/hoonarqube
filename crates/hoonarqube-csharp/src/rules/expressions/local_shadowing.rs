use super::support::field_and_property_names;
use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1117 — locals do not shadow fields or properties of their
/// enclosing type.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_declaration in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_declaration) {
            continue;
        }
        let member_names = field_and_property_names(type_declaration, source);
        if member_names.is_empty() {
            continue;
        }
        for local in collect_kinds(type_declaration, &["local_declaration_statement"]) {
            for declarator in collect_kinds(local, &["variable_declarator"]) {
                let Some(identifier) = first_named_child(declarator) else {
                    continue;
                };
                if identifier.kind() != "identifier" {
                    continue;
                }
                let name = node_text(identifier, source);
                if member_names.contains(name) {
                    issues.push(issue(
                        language,
                        "S1117",
                        format!("Rename '{name}'; it shadows a member of its enclosing type."),
                        range_of(declarator),
                    ));
                }
            }
        }
    }
    issues
}
