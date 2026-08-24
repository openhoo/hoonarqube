use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::invocation_targets;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5445 — predictable temporary file names let attackers pre-
/// create the path and hijack the write.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            invocation_targets(*invocation, source, Some("Path"), &["GetTempFileName"])
        })
        .map(|invocation| {
            issue(
                language,
                "S5445",
                "Create temporary files with unpredictable names in a private directory.",
                range_of(invocation),
            )
        })
        .collect()
}
