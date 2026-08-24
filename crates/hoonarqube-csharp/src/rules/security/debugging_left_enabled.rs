use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, range_of};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4507 — shipping with debugging enabled hands attackers a
/// detailed map of the application.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        let debug_on = (lowered.contains("customerrors") && lowered.contains("off"))
            || (lowered.contains("debug=") && lowered.contains("true"));
        if debug_on {
            issues.push(issue(
                language,
                "S4507",
                "Disable debugging features in production.",
                range_of(literal),
            ));
        }
    }
    issues
}
