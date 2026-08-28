use crate::CsLanguage;
use crate::cst::{issue, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1109 — closing braces sit at the start of their line.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() == "}"
            && source[..node.start_byte()]
                .rsplit('\n')
                .next()
                .is_some_and(|prefix| {
                    !prefix.contains('{')
                        && prefix.chars().any(|character| !character.is_whitespace())
                })
        {
            issues.push(issue(
                language,
                "S1109",
                "Move this closing curly brace to the next line.",
                range_of(node, source),
            ));
        }
    });
    issues
}
