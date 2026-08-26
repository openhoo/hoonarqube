use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3443 — `GetType()` on a `System.Type` instance is noise.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for outer in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(outer) || callee_name(outer, source) != Some("GetType") {
            continue;
        }
        let receiver = invocation_receiver(outer);
        let redundant = receiver.is_some_and(|receiver| {
            receiver.kind() == "invocation_expression"
                && callee_name(receiver, source) == Some("GetType")
        });
        if redundant {
            issues.push(issue(
                language,
                "S3443",
                "Remove this redundant 'GetType' call; it already returns a System.Type.",
                range_of(outer, source),
            ));
        }
    }
    issues
}
