use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1449 — searches and comparisons need an explicit culture or
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let count = invocation_arguments(call).len();
        let flagged = matches!(callee_name(call, source), Some("CompareTo") if count == 1)
            || matches!(callee_name(call, source), Some("IndexOf" | "LastIndexOf") if count <= 1);
        if flagged {
            issues.push(issue(
                language,
                "S1449",
                "Pass the culture or comparison type to this operation.",
                range_of(call),
            ));
        }
    }
    issues
}
