use super::support::else_alternative;
use super::support::is_else_alternative;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_from_byte_offsets};
use hoonarqube_ir::{Issue, Range};
use tree_sitter::Node;

/// csharpsquid:S126 — `else if` chains end with a terminal `else`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for head in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(head) || is_else_alternative(head) {
            continue;
        }
        if let Some(range) = missing_else_range(head, source) {
            issues.push(issue(
                language,
                "S126",
                "Add the missing 'else' clause with either the appropriate action or a suitable comment as to why no action is taken.",
                range,
            ));
        }
    }
    issues
}

fn missing_else_range(head: Node<'_>, source: &str) -> Option<Range> {
    let mut current = head;
    loop {
        match else_alternative(current) {
            Some(alternative) if alternative.kind() == "if_statement" => current = alternative,
            Some(_) => return None,
            None if current == head => return None,
            None => return Some(chain_tail_range(current, source)),
        }
    }
}

fn chain_tail_range(current: Node<'_>, source: &str) -> Range {
    let start = current.start_byte().saturating_sub(5);
    if source
        .get(start..current.start_byte())
        .is_some_and(|prefix| prefix == "else ")
    {
        range_from_byte_offsets(start, current.start_byte() + 2, source)
    } else {
        range_from_byte_offsets(current.start_byte(), current.start_byte() + 2, source)
    }
}
