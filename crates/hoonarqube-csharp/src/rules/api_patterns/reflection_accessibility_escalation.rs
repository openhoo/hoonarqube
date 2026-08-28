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
        .filter_map(|call| binding_flags_argument(call, source))
        .map(|flags| {
            issue(
                language,
                "S3011",
                "Make sure that this accessibility bypass is safe here.",
                range_of(flags, source),
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
fn binding_flags_argument<'t>(invocation: Node<'t>, source: &str) -> Option<Node<'t>> {
    invocation_arguments(invocation)
        .into_iter()
        .find_map(|argument| {
            let accesses = collect_kinds(argument, &["member_access_expression"]);
            let names: Vec<&str> = accesses
                .iter()
                .copied()
                .filter_map(|access| expression_name(access, source))
                .collect();
            if names.contains(&"NonPublic")
                && (names.contains(&"Instance") || names.contains(&"Static"))
            {
                accesses
                    .into_iter()
                    .find(|access| expression_name(*access, source) == Some("NonPublic"))
            } else {
                None
            }
        })
}
