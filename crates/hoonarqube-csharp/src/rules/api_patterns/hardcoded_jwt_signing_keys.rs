use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{callee_name, first_named_child, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6781 — signing keys built from literal byte arrays live
/// forever in source control and leak with the repo.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "SymmetricSecurityKey"
                })
        })
        .filter(|creation| {
            collect_kinds(*creation, &["invocation_expression"])
                .into_iter()
                .any(|call| {
                    callee_name(call, source) == Some("GetBytes")
                        && invocation_arguments(call).iter().any(|argument| {
                            first_named_child(*argument)
                                .is_some_and(|value| value.kind() == "string_literal")
                        })
                })
                || invocation_arguments(*creation).iter().any(|argument| {
                    first_named_child(*argument)
                        .is_some_and(|value| value.kind() == "string_literal")
                })
        })
        .map(|creation| {
            issue(
                language,
                "S6781",
                "Load this signing key from configuration instead of hard-coding it.",
                range_of(creation, source),
            )
        })
        .collect()
}
