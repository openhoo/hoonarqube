use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::invocation_targets;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3884 — mutating process-wide COM security from managed code
/// corrupts the whole apartment.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const BANNED: [&str; 2] = ["CoSetProxyBlanket", "CoInitializeSecurity"];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| invocation_targets(*invocation, source, None, &BANNED))
        .map(|invocation| {
            issue(
                language,
                "S3884",
                "Do not mutate COM security settings here.",
                range_of(invocation),
            )
        })
        .collect()
}
