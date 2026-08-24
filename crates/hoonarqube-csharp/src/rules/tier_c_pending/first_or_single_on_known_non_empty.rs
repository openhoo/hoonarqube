use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, walk_all};
use crate::rules::dataflow::{WriteKind, callable_blocks, identifier_write};
use crate::rules::expressions::{callee_name, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S7130 — First/Single on collections proven non-empty.
/// Subset: same-callable proof in document order — the receiver identifier
/// was populated by `.Add`/`.AddRange`/`.Insert` or a non-empty collection
/// initializer and never reassigned or cleared before the call; other
/// receiver shapes and cross-method flow stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for body in callable_blocks(root) {
        let mut populated: std::collections::HashSet<String> = std::collections::HashSet::new();
        walk_all(body, &mut |node| {
            if !visited.insert(node.id()) {
                return;
            }
            match node.kind() {
                "invocation_expression" => {
                    let Some(receiver) = invocation_receiver(node) else {
                        return;
                    };
                    if receiver.kind() != "identifier" {
                        return;
                    }
                    let name = node_text(receiver, source);
                    match callee_name(node, source) {
                        Some("Add" | "AddRange" | "Insert") => {
                            populated.insert(name.to_owned());
                        }
                        Some("Clear") => {
                            populated.remove(name);
                        }
                        Some("FirstOrDefault" | "SingleOrDefault") if populated.contains(name) => {
                            issues.push(issue(
                                    language,
                                    "S7130",
                                    "Use 'First' or 'Single' here; this collection is known to be non-empty.",
                                    range_of(node),
                                ));
                        }
                        _ => {}
                    }
                }
                "variable_declaration" => {
                    for declarator in collect_kinds(node, &["variable_declarator"]) {
                        let Some(initializer) =
                            collect_kinds(declarator, &["initializer_expression"])
                                .into_iter()
                                .next()
                        else {
                            continue;
                        };
                        let mut cursor = initializer.walk();
                        if !initializer
                            .children(&mut cursor)
                            .any(|child| child.is_named())
                        {
                            continue;
                        }
                        if let Some(name) = declarator.child_by_field_name("name") {
                            populated.insert(node_text(name, source).to_owned());
                        }
                    }
                }
                "identifier" if identifier_write(node) == Some(WriteKind::Store) => {
                    populated.remove(node_text(node, source));
                }
                _ => {}
            }
        });
    }
    issues
}
