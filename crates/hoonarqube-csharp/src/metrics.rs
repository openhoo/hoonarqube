//! File-level metric computation: LOC classification via a full CST walk.

use crate::cst::{to_u32, walk_all};
use tree_sitter::Node;

pub(crate) fn file_metrics(root: Node<'_>, source: &str) -> (hoonarqube_ir::FileMetrics, usize) {
    let lines = if source.is_empty() {
        0
    } else {
        to_u32(source.lines().count())
    };

    let mut code_lines = std::collections::BTreeSet::new();
    let mut comment_lines = std::collections::BTreeSet::new();
    collect_line_kinds(root, &mut code_lines, &mut comment_lines);
    // A line holding both code and a comment counts as code only.
    let code_line_count = code_lines.len();
    (
        hoonarqube_ir::FileMetrics {
            lines,
            code_lines: to_u32(code_line_count),
            comment_lines: to_u32(comment_lines.difference(&code_lines).count()),
        },
        code_line_count,
    )
}

/// Classifies every covered row as code or comment by walking the whole CST;
/// `comment` nodes mark comment rows, everything else marks code rows.
pub(crate) fn collect_line_kinds(
    node: Node<'_>,
    code_lines: &mut std::collections::BTreeSet<u32>,
    comment_lines: &mut std::collections::BTreeSet<u32>,
) {
    walk_all(node, &mut |node| {
        let rows = node.start_position().row..=node.end_position().row;
        if node.kind() == "comment" {
            comment_lines.extend(rows.map(to_u32));
        } else if node.child_count() == 0 && node.kind() != "ERROR" {
            code_lines.extend(rows.map(to_u32));
        }
    });
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
    fn deeply_nested_cst_walk_is_iterative_and_exact() {
        // Chained `&&` nodes form a CST far deeper than the old descent cap.
        // Every physical line must still be classified.
        let deep = format!(
            "class A {{ void M(bool a) {{ var x =\n{}a;\n}} }}\n",
            "a &&\n".repeat(2_000)
        );
        let tree = crate::parse(&deep);
        let mut code_lines = std::collections::BTreeSet::new();
        let mut comment_lines = std::collections::BTreeSet::new();
        collect_line_kinds(tree.root_node(), &mut code_lines, &mut comment_lines);
        assert_eq!(code_lines.len(), deep.lines().count());
        assert!(comment_lines.is_empty());
    }
}
