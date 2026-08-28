use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1199 — plain code blocks nest only through control flow.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        if is_error_tainted(block) {
            continue;
        }
        if block
            .parent()
            .is_some_and(|parent| parent.kind() == "block")
        {
            let opening = collect_kinds(block, &["{"])
                .into_iter()
                .next()
                .unwrap_or(block);
            issues.push(issue(
                language,
                "S1199",
                "Extract this nested code block into a separate method.",
                range_of(opening, source),
            ));
        }
    }
    issues
}
