use super::support::TYPE_DECLARATION_KINDS;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4041 — type names do not match namespace segments
/// (case-insensitively).
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut namespace_segments: Vec<(&str, String)> = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "namespace_declaration" {
            return;
        }
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let full_name = node_text(name, source);
        for segment in full_name.split(['.', ':']).filter(|part| !part.is_empty()) {
            namespace_segments.push((segment, segment.to_ascii_lowercase()));
        }
    });
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let Some(name) = type_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        let lowered = name_text.to_ascii_lowercase();
        if let Some((original, _)) = namespace_segments
            .iter()
            .find(|(_, segment_lower)| *segment_lower == lowered)
        {
            issues.push(issue(
                language,
                "S4041",
                format!("Rename this type; its name matches namespace segment \"{original}\"."),
                range_of(name, source),
            ));
        }
    }
    issues
}
