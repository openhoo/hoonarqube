use super::support::callable_blocks;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use crate::rules::modifiers::has_ancestor_with_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2222 — every `Monitor.Enter` needs its `Exit` on all
/// paths: an exit that is not wrapped in a `finally` leaves the lock
/// held when exceptions unwind. Bound: pairing resolved within one
/// member body, by lock-object text.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let operations = monitor_operations(body, source);
        for (index, (method, object, enter)) in operations.iter().enumerate() {
            if *method == "Exit" {
                continue;
            }
            let later_exits = operations[index + 1..]
                .iter()
                .filter(|(exit_method, exit_object, exit_call)| {
                    *exit_method == "Exit"
                        && exit_object == object
                        && exit_call.start_byte() > enter.end_byte()
                })
                .collect::<Vec<_>>();
            let released_on_all_paths = later_exits.is_empty()
                || later_exits.iter().any(|(_, _, exit_call)| {
                    has_ancestor_with_kind(*exit_call, &["finally_clause"])
                });
            if released_on_all_paths {
                continue;
            }
            issues.push(issue(
                language,
                "S2222",
                "Release this lock on every path through the code.",
                range_of(*enter),
            ));
        }
    }
    issues
}

/// `Monitor.Enter`/`TryEnter`/`Exit` invocations paired with their lock
/// object text, in document order.
pub(crate) fn monitor_operations<'a, 't>(
    body: Node<'t>,
    source: &'a str,
) -> Vec<(&'a str, &'a str, Node<'t>)> {
    collect_kinds(body, &["invocation_expression"])
        .into_iter()
        .filter_map(|call| {
            let method = callee_name(call, source)?;
            matches!(method, "Enter" | "TryEnter" | "Exit").then_some(())?;
            let receiver = invocation_receiver(call)?;
            (node_text(receiver, source) == "Monitor").then_some(())?;
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
