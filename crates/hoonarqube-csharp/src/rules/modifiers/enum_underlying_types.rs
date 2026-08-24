use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4022 — enums should stick to `int` storage.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for enum_node in collect_kinds(root, &["enum_declaration"]) {
        let mut cursor = enum_node.walk();
        let Some(base_list) = enum_node
            .children(&mut cursor)
            .find(|child| child.kind() == "base_list")
        else {
            continue;
        };
        let mut list_cursor = base_list.walk();
        let underlying = base_list
            .children(&mut list_cursor)
            .find(tree_sitter::Node::is_named)
            .map(|base| simple_name(node_text(base, source)));
        if underlying.is_none_or(|stored| matches!(stored, "int" | "Int32")) {
            continue;
        }
        let Some(name) = enum_node.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4022",
            "Use 'int' as the underlying type of this enum.",
            range_of(name),
        ));
    }
    issues
}
