use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::dataflow::callable_blocks;
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S7131 — reader/writer lock scopes must nest: releasing
/// the wrong mode deadlocks or corrupts the protection.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const ACQUIRE: [&str; 2] = ["AcquireReaderLock", "AcquireWriterLock"];
    const RELEASE: [&str; 2] = ["ReleaseReaderLock", "ReleaseWriterLock"];
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let operations = lock_operations(body, source, &ACQUIRE, &RELEASE);
        for (index, (method, object, node)) in operations.iter().enumerate() {
            if RELEASE.contains(method) {
                continue;
            }
            let wanted_release = if *method == ACQUIRE[0] {
                RELEASE[0]
            } else {
                RELEASE[1]
            };
            let matched = operations[index + 1..]
                .iter()
                .any(|(later_method, later_object, _)| {
                    later_method == &wanted_release && later_object == object
                });
            if !matched {
                issues.push(issue(
                    language,
                    "S7131",
                    format!("Call '{wanted_release}' for this lock before returning."),
                    range_of(*node, source),
                ));
            }
        }
    }
    issues
}

/// Acquire/release invocations by lock-object text, document order:
/// `(method, object text, node)`.
fn lock_operations<'a, 't>(
    body: Node<'t>,
    source: &'a str,
    acquire_names: &[&str],
    release_names: &[&str],
) -> Vec<(&'a str, &'a str, Node<'t>)> {
    collect_kinds(body, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter_map(|call| {
            let method = callee_name(call, source)?;
            let is_acquire = acquire_names.contains(&method);
            let is_release = release_names.contains(&method);
            if !is_acquire && !is_release {
                return None;
            }
            // Reader/writer releases take no argument, so prefer the
            // receiver as the pairing key and fall back to the argument.
            let key = invocation_receiver(call)
                .map(|receiver| node_text(receiver, source))
                .or_else(|| {
                    invocation_arguments(call)
                        .into_iter()
                        .next()
                        .map(|argument| node_text(argument, source))
                })?;
            Some((method, key, call))
        })
        .collect()
}
