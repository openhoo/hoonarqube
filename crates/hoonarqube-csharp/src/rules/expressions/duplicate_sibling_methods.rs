use super::support::member_declarations_of_kind;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::{body_of, is_attributed};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4144 — sibling methods sharing one verbatim body; later
/// duplicates are flagged against the first carrier.
pub(crate) fn check<'s>(root: Node<'_>, source: &'s str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let mut seen: Vec<(&'s str, &'s str)> = Vec::new();
        for method in member_declarations_of_kind(type_node, "method_declaration") {
            if is_error_tainted(method) || is_attributed(method, source) {
                continue;
            }
            let Some(body) = body_of(method) else {
                continue;
            };
            let text = node_text(body, source);
            if text.is_empty() {
                continue;
            }
            let name = method
                .child_by_field_name("name")
                .map_or("", |name| node_text(name, source));
            if let Some((carrier, _)) = seen.iter().find(|(_, earlier)| *earlier == text) {
                issues.push(issue(
                    language,
                    "S4144",
                    format!("Update this method so it no longer duplicates '{carrier}'."),
                    range_of(method, source),
                ));
            } else {
                seen.push((name, text));
            }
        }
    }
    issues
}
