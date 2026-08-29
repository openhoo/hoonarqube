use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::dataflow::{callable_blocks, monitor_operations};
use hoonarqube_ir::Issue;
use std::collections::BTreeMap;
use tree_sitter::Node;

/// csharpsquid:S7133 — locks acquired in one method and released in
/// another hide their pairing from every reader. Bound: Monitor
/// enter/exit pairs resolved inside one member body.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let operations = monitor_operations(body, source);
        let mut held: BTreeMap<&str, Vec<Node<'_>>> = BTreeMap::new();
        for (method, object, node) in operations {
            if method == "Exit" {
                if let Some(acquisitions) = held.get_mut(object) {
                    acquisitions.pop();
                }
            } else {
                held.entry(object).or_default().push(node);
            }
        }
        issues.extend(held.into_values().flatten().map(|node| {
            issue(
                language,
                "S7133",
                "Release this lock in the same method that acquired it.",
                range_of(node, source),
            )
        }));
    }
    issues
}
