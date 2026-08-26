//! File-level metric computation: LOC classification via a full CST walk.

use crate::cst::to_u32;
use tree_sitter::Node;

/// Whole-file CST walks stay stack-bounded during `analyze`: legitimate
/// files nest nowhere near this deep, while runaway machine-generated
/// nesting stops descending past [`MAX_CST_DEPTH`] instead of exhausting
/// the stack. Rows of stopped subtrees stay classified because every
/// descendant span is covered by its already-marked ancestors.
const MAX_CST_DEPTH: u32 = 256;

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
    collect_line_kinds_bounded(node, code_lines, comment_lines, 0);
}

/// Bounded descent: marking happens before the depth check, so a subtree
/// cut at [`MAX_CST_DEPTH`] keeps its own rows classified.
fn collect_line_kinds_bounded(
    node: Node<'_>,
    code_lines: &mut std::collections::BTreeSet<u32>,
    comment_lines: &mut std::collections::BTreeSet<u32>,
    depth: u32,
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
    if depth >= MAX_CST_DEPTH {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_line_kinds_bounded(child, code_lines, comment_lines, depth + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::collect_line_kinds;
    use crate::tests::analyze_default;

    #[test]
    fn file_metrics_classifies_shallow_files_exactly() {
        let report = analyze_default("// lead\nclass A\n{\n}\n");
        assert_eq!(report.metrics.lines, 4);
        assert_eq!(report.metrics.code_lines, 3);
        assert_eq!(report.metrics.comment_lines, 1);
    }

    #[test]
    fn deeply_nested_cst_walk_stays_within_the_stack_budget() {
        // ~10k chained `&&` levels: far past MAX_CST_DEPTH and exactly the
        // runaway shape that previously recursed once per level unbounded.
        let deep = format!(
            "class A {{ void M(bool a) {{ var x = {}a; }} }}\n",
            "a && ".repeat(10_000)
        );
        let tree = crate::parse(&deep);
        let mut code_lines = std::collections::BTreeSet::new();
        let mut comment_lines = std::collections::BTreeSet::new();
        collect_line_kinds(tree.root_node(), &mut code_lines, &mut comment_lines);
        // The single physical line stays classified; the walk stops at
        // MAX_CST_DEPTH instead of recursing once per `&&` level.
        assert_eq!(code_lines.len(), 1);
        assert!(comment_lines.is_empty());
    }
}
