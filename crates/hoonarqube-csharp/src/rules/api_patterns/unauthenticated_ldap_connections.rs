use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::invocation_arguments;
use crate::rules::literals::literal_inner_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4433 — anonymous LDAP binds leak directory data to
/// anyone who can reach the server.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "DirectoryEntry"
                })
        })
        .filter(|creation| {
            let arguments = invocation_arguments(*creation);
            arguments.len() == 1
                && arguments[0]
                    .children(&mut arguments[0].walk())
                    .find(tree_sitter::Node::is_named)
                    .is_some_and(|value| {
                        value.kind() == "string_literal"
                            && literal_inner_text(value, source)
                                .to_ascii_uppercase()
                                .starts_with("LDAP")
                    })
        })
        .map(|creation| {
            issue(
                language,
                "S4433",
                "Set credentials or a secure authentication type on this LDAP connection.",
                range_of(creation),
            )
        })
        .collect()
}
