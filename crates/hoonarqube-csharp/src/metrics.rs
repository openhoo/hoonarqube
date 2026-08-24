//! File-level metric computation: LOC classification via a full CST walk.

use crate::cst::to_u32;
use tree_sitter::Node;

pub(crate) fn file_metrics(root: Node<'_>, source: &str) -> hoonarqube_ir::FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        to_u32(source.lines().count())
    };

    let mut code_lines = std::collections::BTreeSet::new();
    let mut comment_lines = std::collections::BTreeSet::new();
    collect_line_kinds(root, &mut code_lines, &mut comment_lines);
    // A line holding both code and a comment counts as code only.
    let comment_only: Vec<u32> = comment_lines.difference(&code_lines).copied().collect();

    hoonarqube_ir::FileMetrics {
        lines,
        code_lines: to_u32(code_lines.len()),
        comment_lines: to_u32(comment_only.len()),
    }
}

/// Classifies every covered row as code or comment by walking the whole CST;
/// `comment` nodes mark comment rows, everything else marks code rows.
pub(crate) fn collect_line_kinds(
    node: Node<'_>,
    code_lines: &mut std::collections::BTreeSet<u32>,
    comment_lines: &mut std::collections::BTreeSet<u32>,
) {
    if node.kind() == "comment" {
        for row in node.start_position().row..=node.end_position().row {
            comment_lines.insert(to_u32(row));
        }
        return;
    }
    if node.child_count() == 0 && node.kind() != "ERROR" {
        for row in node.start_position().row..=node.end_position().row {
            code_lines.insert(to_u32(row));
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_line_kinds(child, code_lines, comment_lines);
    }
}
