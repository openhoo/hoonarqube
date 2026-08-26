use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, expression_name, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3011 — reflecting over non-public members escalates
/// accessibility beyond what the type author exposed.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            REFLECTION_MEMBER_LOOKUPS.contains(&callee_name(*call, source).unwrap_or(""))
        })
        .filter(|call| {
            uses_binding_flags(*call, source, &["NonPublic"])
                && uses_binding_flags(*call, source, &["Instance", "Static"])
        })
        .map(|call| {
            issue(
                language,
                "S3011",
                "Reflecting over non-public members bypasses accessibility checks.",
                range_of(call, source),
            )
        })
        .collect()
}

/// Reflection lookups that reach non-public state.
const REFLECTION_MEMBER_LOOKUPS: [&str; 8] = [
    "GetMethod",
    "GetField",
    "GetProperty",
    "GetEvent",
    "GetConstructor",
    "GetMember",
    "InvokeMember",
    "SetValue",
];

/// Binding flags mentioned anywhere in an invocation's arguments.
fn uses_binding_flags(invocation: Node<'_>, source: &str, wanted: &[&str]) -> bool {
    invocation_arguments(invocation).iter().any(|argument| {
        collect_kinds(*argument, &["member_access_expression"])
            .into_iter()
            .any(|access| wanted.contains(&expression_name(access, source).unwrap_or("")))
    })
}
