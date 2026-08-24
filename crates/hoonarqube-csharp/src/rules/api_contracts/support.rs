use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, simple_name};
use crate::rules::expressions::member_declarations_of_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// The guarded expression of a `lock (...)` statement.
pub(crate) fn lock_guard_expression(lock_statement: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = lock_statement.walk();
    let mut after_paren = false;
    for child in lock_statement.children(&mut cursor) {
        if child.kind() == "(" {
            after_paren = true;
            continue;
        }
        if after_paren {
            return (!child.kind().is_empty()).then_some(child);
        }
    }
    None
}

/// Dispose-shaped methods declared directly by a type.
pub(crate) fn dispose_methods<'t>(type_node: Node<'t>, source: &str) -> Vec<Node<'t>> {
    member_declarations_of_kind(type_node, "method_declaration")
        .into_iter()
        .filter(|method| {
            method
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "Dispose")
        })
        .collect()
}

/// Comment markers that promise unfinished work.
pub(crate) fn comment_tag_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> (Vec<Issue>, Vec<Issue>) {
    let mut fixmes = Vec::new();
    let mut todos = Vec::new();
    for comment in collect_kinds(root, &["comment"]) {
        let upper = node_text(comment, source).to_ascii_uppercase();
        if upper.contains("FIXME") {
            fixmes.push(issue(
                language,
                "S1134",
                "Track the work promised by this FIXME tag.",
                range_of(comment),
            ));
        }
        if upper.contains("TODO") {
            todos.push(issue(
                language,
                "S1135",
                "Track the work promised by this TODO tag.",
                range_of(comment),
            ));
        }
    }
    (fixmes, todos)
}

/// The declared exception type name of a catch clause (`ex` of
/// `catch (Exception ex)`), when present.
pub(crate) fn catch_type_tail<'a>(clause: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut cursor = clause.walk();
    let declaration = clause
        .children(&mut cursor)
        .find(|child| child.kind() == "catch_declaration")?;
    let type_node = declaration.child_by_field_name("type")?;
    Some(simple_name(node_text(type_node, source)))
}
