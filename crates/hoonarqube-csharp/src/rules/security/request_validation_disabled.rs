use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{invocation_arguments, invocation_targets};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5753 — disabling request validation reopens the XSS door.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        if lowered.contains("validaterequest") && lowered.contains("false") {
            issues.push(issue(
                language,
                "S5753",
                "Keep ASP.NET request validation enabled.",
                range_of(literal, source),
            ));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation)
            || !invocation_targets(invocation, source, None, &["ValidateInput"])
        {
            continue;
        }
        let disables = invocation_arguments(invocation)
            .iter()
            .any(|argument| node_text(*argument, source) == "false");
        if disables {
            issues.push(issue(
                language,
                "S5753",
                "Keep ASP.NET request validation enabled.",
                range_of(invocation, source),
            ));
        }
    }
    issues
}
