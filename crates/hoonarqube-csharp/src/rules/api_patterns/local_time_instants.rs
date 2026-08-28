use super::support::local_now_stores;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::dataflow::callable_blocks;
use crate::rules::literals::declarator_initializer;
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
                let anchor = match store.kind() {
                    "assignment_expression" => store.child_by_field_name("right"),
                    "variable_declarator" => store
                        .child_by_field_name("name")
                        .and_then(|declared| declarator_initializer(store, declared)),
                    _ => None,
                }
                .unwrap_or(store);
                issues.push(issue(
                    language,
                    "S6563",
                    "Use UTC when recording DateTime instants",
                    range_of(anchor, source),
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
