use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3376 — classes extending `Attribute`, `EventArgs`, or
/// `Exception` end their names with that suffix.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        let mut base_cursor = class_node.walk();
        let offending_tail = class_node
            .children(&mut base_cursor)
            .find(|child| child.kind() == "base_list")
            .and_then(|base_list| {
                let mut base_list_cursor = base_list.walk();
                base_list
                    .children(&mut base_list_cursor)
                    .map(|base| simple_name(node_text(base, source)))
                    .find(|tail| {
                        matches!(*tail, "Attribute" | "EventArgs" | "Exception")
                            && !name_text.ends_with(tail)
                    })
            });
        if let Some(tail) = offending_tail {
            issues.push(issue(
                language,
                "S3376",
                format!("Rename this class so its name ends with \"{tail}\"."),
                range_of(name),
            ));
        }
    }
    issues
}
