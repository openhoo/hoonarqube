use super::support::identifier_write;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S127 — a `for` stop condition stays invariant: nothing in
/// the body may assign a name the condition tests. Update-clause writes
/// drive the loop and are exempt by design.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let Some(condition) = for_statement.child_by_field_name("condition") else {
            continue;
        };
        let condition_names: std::collections::HashSet<&str> =
            collect_kinds(condition, &["identifier"])
                .into_iter()
                .map(|identifier| node_text(identifier, source))
                .collect();
        let Some(body) = for_statement.child_by_field_name("body") else {
            continue;
        };
        let body_writes = written_names(body, source);
        if condition_names
            .iter()
            .any(|name| body_writes.contains(name))
        {
            issues.push(issue(
                language,
                "S127",
                "This loop's stop condition is not invariant.",
                range_of(for_statement),
            ));
        }
    }
    issues
}

/// Names receiving a write anywhere in the subtree: assignment targets,
/// increment operands, and declared names alike.
fn written_names<'a>(node: Node<'_>, source: &'a str) -> std::collections::HashSet<&'a str> {
    let mut names = std::collections::HashSet::new();
    walk_all(node, &mut |current| {
        if current.kind() == "identifier" && identifier_write(current).is_some() {
            names.insert(node_text(current, source));
        }
    });
    names
}
