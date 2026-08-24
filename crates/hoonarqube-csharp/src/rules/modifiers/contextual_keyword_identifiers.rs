use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2306 — `async` and `await` are contextual keywords, never
/// identifiers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for identifier in collect_kinds(root, &["identifier"]) {
        let text = node_text(identifier, source);
        if matches!(text, "async" | "await") {
            issues.push(issue(
                language,
                "S2306",
                format!("Rename \"{text}\"; it collides with a contextual keyword."),
                range_of(identifier),
            ));
        }
    }
    issues
}
