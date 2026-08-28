use super::support::EMBEDDED_HEADER_KINDS;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_from_byte_offsets};
use crate::rules::structure::embedded_bodies;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2681 — multi-line embedded bodies wear braces so no later
/// line can masquerade as part of the body.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &EMBEDDED_HEADER_KINDS) {
        if is_error_tainted(header) {
            continue;
        }
        let Some(body) = embedded_bodies(header)
            .into_iter()
            .find(|body| body.kind() != "block")
        else {
            continue;
        };
        let Some(parent) = header.parent() else {
            continue;
        };
        let mut cursor = parent.walk();
        let siblings: Vec<Node<'_>> = parent
            .children(&mut cursor)
            .filter(tree_sitter::Node::is_named)
            .collect();
        let Some(index) = siblings.iter().position(|node| node.id() == header.id()) else {
            continue;
        };
        let Some(next) = siblings.get(index + 1).copied() else {
            continue;
        };
        if next.start_position().column == body.start_position().column {
            let line_start = next.start_byte();
            let line_end = source[line_start..]
                .find(['\r', '\n'])
                .map_or(source.len(), |offset| line_start + offset);
            let line_count = next.start_position().row - body.start_position().row + 1;
            issues.push(issue(
                language,
                "S2681",
                format!(
                    "This line will not be executed conditionally; only the first line of this {line_count}-line block will be. The rest will execute unconditionally."
                ),
                range_from_byte_offsets(line_start, line_end, source),
            ));
        }
    }
    issues
}
