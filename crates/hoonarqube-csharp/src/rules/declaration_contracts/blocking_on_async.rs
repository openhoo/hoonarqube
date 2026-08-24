use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{
    callee_name, expression_name, invocation_arguments, invocation_function, invocation_receiver,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4462 — `.Result`, `.Wait()`, and `GetAwaiter().GetResult()`
/// deadlock thread-pool-synchronized contexts.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for access in collect_kinds(root, &["member_access_expression"]) {
        if is_error_tainted(access) || expression_name(access, source) != Some("Result") {
            continue;
        }
        let called_like_a_method = access.parent().is_some_and(|parent| {
            parent.kind() == "invocation_expression" && invocation_function(parent) == Some(access)
        });
        if !called_like_a_method {
            issues.push(issue(
                language,
                "S4462",
                "Do not block on async code here.",
                range_of(access),
            ));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) {
            continue;
        }
        let zero_arg_wait = callee_name(invocation, source) == Some("Wait")
            && invocation_arguments(invocation).is_empty();
        let get_result_chain = callee_name(invocation, source) == Some("GetResult")
            && invocation_receiver(invocation).and_then(|receiver| callee_name(receiver, source))
                == Some("GetAwaiter");
        if zero_arg_wait || get_result_chain {
            issues.push(issue(
                language,
                "S4462",
                "Do not block on async code here.",
                range_of(invocation),
            ));
        }
    }
    issues
}
