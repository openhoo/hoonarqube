use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::block_statements;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2327 — adjacent identical handlers merge into one `try`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        for pair in block_statements(block).windows(2) {
            if pair[0].kind() != "try_statement" || pair[1].kind() != "try_statement" {
                continue;
            }
            if try_handler_signature(pair[0], source) == try_handler_signature(pair[1], source) {
                issues.push(issue(
                    language,
                    "S2327",
                    "Merge these try statements sharing identical handlers.",
                    range_of(pair[1]),
                ));
            }
        }
    }
    issues
}

/// Catch and finally handler signature of a try statement, as written.
fn try_handler_signature(try_statement: Node<'_>, source: &str) -> (Vec<String>, Option<String>) {
    let mut cursor = try_statement.walk();
    let mut catches = Vec::new();
    let mut fin = None;
    for child in try_statement.children(&mut cursor) {
        match child.kind() {
            "catch_clause" => catches.push(node_text(child, source).trim().to_string()),
            "finally_clause" => fin = Some(node_text(child, source).trim().to_string()),
            _ => {}
        }
    }
    (catches, fin)
}
