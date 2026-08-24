use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::dataflow::{callable_blocks, monitor_operations};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S7133 — locks acquired in one method and released in
/// another hide their pairing from every reader. Bound: Monitor
/// enter/exit pairs resolved inside one member body.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let operations = monitor_operations(body, source);
        for (index, (method, object, node)) in operations.iter().enumerate() {
            if *method == "Exit" {
                continue;
            }
            let released =
                operations[index + 1..]
                    .iter()
                    .any(|(exit_method, exit_object, exit_call)| {
                        *exit_method == "Exit"
                            && exit_object == object
                            && exit_call.start_byte() > node.end_byte()
                    });
            if !released {
                issues.push(issue(
                    language,
                    "S7133",
                    "Release this lock in the same method that acquired it.",
                    range_of(*node),
                ));
            }
        }
    }
    issues
}
