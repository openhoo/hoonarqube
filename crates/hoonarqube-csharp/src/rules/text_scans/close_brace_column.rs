use crate::CsLanguage;
use crate::cst::{issue, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1109 — closing braces sit at the start of their line.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() == "}" && node.start_position().column != 0 {
            issues.push(issue(
                language,
                "S1109",
                "Move this closing curly brace to the beginning of its line.",
                range_of(node, source),
            ));
        }
    });
    issues
}
