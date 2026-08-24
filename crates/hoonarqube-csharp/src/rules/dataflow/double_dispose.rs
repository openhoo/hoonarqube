use super::support::WriteKind;
use super::support::callable_blocks;
use super::support::identifier_write;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, walk_all};
use crate::rules::expressions::{callee_name, expression_name, invocation_receiver};
use crate::symbol_table::nearest_ancestor_of_kinds;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3966 — disposing an object twice either throws or hides
/// a lifecycle bug. Bound: document order across the member body —
/// branches that each dispose the same object are indistinguishable, so
/// a second dispose after an intervening store is clean but two bare
/// disposes are not. The enclosing `using` counts as a dispose too.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let mut disposed: std::collections::HashSet<String> = std::collections::HashSet::new();
        walk_all(body, &mut |node| match node.kind() {
            "invocation_expression" => {
                if callee_name(node, source) != Some("Dispose") {
                    return;
                }
                let Some(receiver) = invocation_receiver(node) else {
                    return;
                };
                let name = expression_name(receiver, source).unwrap_or("");
                let under_using = nearest_ancestor_of_kinds(node, &["using_statement"])
                    .is_some_and(|using| {
                        collect_kinds(using, &["variable_declarator"])
                            .iter()
                            .any(|declarator| {
                                declarator
                                    .child_by_field_name("name")
                                    .is_some_and(|declared| node_text(declared, source) == name)
                            })
                    });
                if under_using || disposed.contains(name) {
                    issues.push(issue(
                        language,
                        "S3966",
                        format!("'{name}' is disposed more than once."),
                        range_of(node),
                    ));
                } else {
                    disposed.insert(name.to_owned());
                }
            }
            "identifier" if identifier_write(node) == Some(WriteKind::Store) => {
                disposed.remove(node_text(node, source));
            }
            _ => {}
        });
    }
    issues
}
