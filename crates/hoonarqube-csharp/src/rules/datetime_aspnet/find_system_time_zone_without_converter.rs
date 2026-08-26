use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::invocation_targets;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6575 — Windows time-zone ids vanish on other platforms;
/// `TimeZoneConverter` translates them safely.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    if source.contains("TimeZoneConverter") {
        return Vec::new();
    }
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            invocation_targets(
                *invocation,
                source,
                Some("TimeZoneInfo"),
                &["FindSystemTimeZoneById"],
            )
        })
        .map(|invocation| {
            issue(
                language,
                "S6575",
                "Resolve time zones through 'TimeZoneConverter' for portability.",
                range_of(invocation, source),
            )
        })
        .collect()
}
