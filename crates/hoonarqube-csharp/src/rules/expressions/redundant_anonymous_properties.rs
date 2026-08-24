use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3441 — `new { x = x }` spells out a name the compiler
/// already infers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["anonymous_object_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        for (name, value) in anonymous_property_pairs(creation) {
            if !is_error_tainted(value) && node_text(name, source) == node_text(value, source) {
                issues.push(issue(
                    language,
                    "S3441",
                    "Use the shorthand property form; this assignment repeats the name.",
                    range_of(value),
                ));
            }
        }
    }
    issues
}

/// Initializer entries of an anonymous-object creation as `(name, value)`
/// pairs; shorthand entries yield no pair.
fn anonymous_property_pairs<'t>(creation: Node<'t>) -> Vec<(Node<'t>, Node<'t>)> {
    let mut cursor = creation.walk();
    let named: Vec<Node<'t>> = creation
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .collect();
    named
        .chunks(2)
        .filter_map(|pair| match pair {
            [name, value] => Some((*name, *value)),
            _ => None,
        })
        .collect()
}
