use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3261 — namespaces group declarations.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for namespace in collect_kinds(root, &["namespace_declaration"]) {
        if is_error_tainted(namespace) {
            continue;
        }
        let mut cursor = namespace.walk();
        let has_members = namespace
            .children(&mut cursor)
            .find(|child| child.kind() == "declaration_list")
            .is_some_and(|list| {
                let mut list_cursor = list.walk();
                list.children(&mut list_cursor)
                    .any(|member| member.is_named())
            });
        if !has_members {
            issues.push(issue(
                language,
                "S3261",
                "Remove this empty namespace.",
                range_of(namespace, source),
            ));
        }
    }
    issues
}
