use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4663 — comments should not be empty.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "comment" {
            return;
        }
        let text = node_text(node, source);
        let is_empty = if let Some(inner) = text.strip_prefix("/*") {
            let inner = inner.strip_suffix("*/").unwrap_or(inner);
            inner.chars().all(|c| c.is_whitespace() || c == '*')
        } else {
            false
        };
        if is_empty {
            issues.push(issue(
                language,
                "S4663",
                "Remove this empty comment",
                range_of(node, source),
            ));
        }
    });
    issues
}
