use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, node_text, range_of};
use crate::rules::dataflow::{callable_blocks, collect_owned_kinds};
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
        let mut stack: Vec<(&str, &str, Node<'_>, bool)> = Vec::new();
        for (method, object, node) in operations {
            if ACQUIRE.contains(&method) {
                stack.push((method, object, node, false));
                continue;
            }
            let Some(top) = stack.last_mut() else {
                continue;
            };
            let wanted_release = release_for(top.0);
            if top.1 == object && wanted_release == method {
                let (_, _, acquire, mismatched) = stack.pop().expect("stack is not empty");
                if mismatched {
                    issues.push(lock_issue(language, source, acquire, wanted_release));
                }
            } else {
                top.3 = true;
            }
        }
        issues.extend(
            stack.into_iter().map(|(method, _, node, _)| {
                lock_issue(language, source, node, release_for(method))
            }),
        );
    }
    issues
}

fn release_for(acquire: &str) -> &'static str {
    if acquire == "AcquireReaderLock" {
        "ReleaseReaderLock"
    } else {
        "ReleaseWriterLock"
    }
}

fn lock_issue(language: CsLanguage, source: &str, node: Node<'_>, wanted_release: &str) -> Issue {
    issue(
        language,
        "S7131",
        format!("Call '{wanted_release}' for this lock before returning."),
        range_of(node, source),
    )
}

/// Acquire/release invocations by lock-object text, document order:
/// `(method, object text, node)`.
fn lock_operations<'a, 't>(
    body: Node<'t>,
    source: &'a str,
    acquire_names: &[&str],
    release_names: &[&str],
) -> Vec<(&'a str, &'a str, Node<'t>)> {
    collect_owned_kinds(body, &["invocation_expression"])
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
