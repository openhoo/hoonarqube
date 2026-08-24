use super::support::local_now_stores;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::dataflow::callable_blocks;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6563 — recorded instants belong in UTC so timelines
/// stay comparable across zones and daylight-saving changes. Bound:
/// targets whose name reads like an instant (`*Time`, `Created`,
/// `Modified`, …) stored from `DateTime.Now`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for (name, store) in local_now_stores(body, source) {
            if records_instant(name) {
                issues.push(issue(
                    language,
                    "S6563",
                    format!("Record '{name}' in UTC with 'DateTime.UtcNow'."),
                    range_of(store),
                ));
            }
        }
    }
    issues
}

/// Whether this target name suggests recording a point in time.
fn records_instant(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    [
        "time", "date", "stamp", "created", "modified", "updated", "expires", "seen",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}
