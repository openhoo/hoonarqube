use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6354 — the system clock is untestable; inject a time
/// provider instead of reading `DateTime` statics.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "DateTime", &["Now", "UtcNow", "Today"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S6354",
                "Inject a testable time provider instead of reading the system clock.",
                range_of(access),
            )
        })
        .collect()
}
