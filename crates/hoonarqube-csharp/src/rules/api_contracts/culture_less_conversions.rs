use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4056 — culture-less `ToString`/`Parse` calls pick the
/// machine's locale instead of a stated one.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let arguments = invocation_arguments(call);
        let flagged = match callee_name(call, source) {
            Some("ToString") => arguments.is_empty(),
            Some("Parse") => arguments.len() == 1,
            _ => false,
        };
        if flagged {
            issues.push(issue(
                language,
                "S4056",
                "Call the overload that takes an 'IFormatProvider'.",
                range_of(call),
            ));
        }
    }
    issues
}
