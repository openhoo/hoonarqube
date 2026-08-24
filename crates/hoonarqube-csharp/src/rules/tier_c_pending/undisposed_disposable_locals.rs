use super::support::DISPOSABLE_TYPES;
use super::support::this_or_identifier_name;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name, walk_all,
};
use crate::rules::dataflow::callable_blocks;
use crate::rules::expressions::{callee_name, first_named_child, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2930 — `IDisposable` locals that are never disposed. Subset:
/// locals whose declared type is in the well-known disposable table, inside
/// one callable, with no `using` enclosure, no `.Dispose()` call, and no
/// `return` of the value in that callable; `var` declarations and fields
/// stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for body in callable_blocks(root) {
        let disposed = disposed_names(body, source);
        let enclosed = using_resource_names(body, source);
        let escaped = returned_names(body, source);
        for declaration in collect_kinds(body, &["variable_declaration"]) {
            if !visited.insert(declaration.id()) {
                continue;
            }
            if is_error_tainted(declaration)
                || declaration
                    .parent()
                    .is_none_or(|parent| parent.kind() != "local_declaration_statement")
            {
                continue;
            }
            let Some(type_node) = declaration.child_by_field_name("type") else {
                continue;
            };
            if !DISPOSABLE_TYPES.contains(&simple_name(node_text(type_node, source))) {
                continue;
            }
            for declarator in collect_kinds(declaration, &["variable_declarator"]) {
                let Some(name_node) = declarator.child_by_field_name("name") else {
                    continue;
                };
                let name = node_text(name_node, source);
                if disposed.contains(name) || enclosed.contains(name) || escaped.contains(name) {
                    continue;
                }
                issues.push(issue(
                    language,
                    "S2930",
                    format!("Dispose this '{name}' instance or wrap it in a 'using' statement."),
                    range_of(name_node),
                ));
            }
        }
    }
    issues
}

/// Names whose `.Dispose()` is invoked inside the block.
fn disposed_names(block: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    walk_all(block, &mut |node| {
        if node.kind() != "invocation_expression" || callee_name(node, source) != Some("Dispose") {
            return;
        }
        if let Some(receiver) = invocation_receiver(node)
            && let Some(name) = this_or_identifier_name(receiver, source)
        {
            names.insert(name.to_owned());
        }
    });
    names
}

/// Names bound as `using` resources inside the block, in both the
/// declaration and the expression form.
fn using_resource_names(block: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for statement in collect_kinds(block, &["using_statement"]) {
        let mut cursor = statement.walk();
        for child in statement.children(&mut cursor) {
            match child.kind() {
                "variable_declaration" => {
                    for declarator in collect_kinds(child, &["variable_declarator"]) {
                        if let Some(name) = declarator.child_by_field_name("name") {
                            names.insert(node_text(name, source).to_owned());
                        }
                    }
                }
                "identifier" => {
                    names.insert(node_text(child, source).to_owned());
                }
                _ => {}
            }
        }
    }
    names
}

/// Names returned by `return` statements inside the block.
fn returned_names(block: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    collect_kinds(block, &["return_statement"])
        .into_iter()
        .filter_map(first_named_child)
        .filter(|expression| expression.kind() == "identifier")
        .map(|expression| node_text(expression, source).to_owned())
        .collect()
}
