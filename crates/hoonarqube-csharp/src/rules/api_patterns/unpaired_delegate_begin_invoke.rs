use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::dataflow::callable_blocks;
use crate::rules::expressions::{callee_name, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4583 — every delegate `BeginInvoke` needs a matching
/// `EndInvoke` on the same receiver or the async machinery leaks.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let end_invokes: Vec<&str> = collect_kinds(body, &["invocation_expression"])
            .into_iter()
            .filter(|call| callee_name(*call, source) == Some("EndInvoke"))
            .filter_map(|call| invocation_receiver(call))
            .map(|receiver| node_text(receiver, source))
            .collect();
        for call in collect_kinds(body, &["invocation_expression"]) {
            if callee_name(call, source) != Some("BeginInvoke") || is_error_tainted(call) {
                continue;
            }
            let paired = invocation_receiver(call)
                .is_some_and(|receiver| end_invokes.contains(&node_text(receiver, source)));
            if !paired {
                issues.push(issue(
                    language,
                    "S4583",
                    "Call 'EndInvoke' for this 'BeginInvoke'.",
                    range_of(call, source),
                ));
            }
        }
    }
    issues
}
