use super::support::EMBEDDED_HEADER_KINDS;
use super::support::{embedded_bodies, is_else_alternative};
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S121 — control structures wrap their bodies in curly braces.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &EMBEDDED_HEADER_KINDS) {
        if is_error_tainted(header) {
            continue;
        }
        for body in embedded_bodies(header) {
            if let Some(issue) = body_issue(header, body, source, language) {
                issues.push(issue);
            }
        }
    }
    issues
}

/// The S121 finding for one brace-less embedded `body`, when it has one.
fn body_issue(
    header: Node<'_>,
    body: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Option<Issue> {
    if body.kind() == "block" {
        return None;
    }
    // An `else` alternative anchors on its own `else` keyword, never on the
    // `if` keyword; `else if` chains are exempt per reference semantics
    // because the nested `if_statement` is checked itself.
    if is_else_alternative(body) {
        return else_issue(header, body, source, language);
    }
    let keyword_name = header_keyword_name(header.kind());
    let keyword = collect_kinds(header, &[keyword_name])
        .into_iter()
        .next()
        .unwrap_or(header);
    Some(issue(
        language,
        "S121",
        format!("Add curly braces around the nested statement(s) in this '{keyword_name}' block."),
        range_of(keyword, source),
    ))
}

/// The S121 finding for an `else` alternative, anchored on the `else`
/// keyword; `None` for `else if` chains.
fn else_issue(
    header: Node<'_>,
    body: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Option<Issue> {
    if body.kind() == "if_statement" {
        return None;
    }
    let mut cursor = header.walk();
    let keyword = header
        .children(&mut cursor)
        .find(|child| child.kind() == "else")
        .unwrap_or(header);
    Some(issue(
        language,
        "S121",
        "Add curly braces around the nested statement(s) in this 'else' block.",
        range_of(keyword, source),
    ))
}

/// The keyword token naming a control header's brace-less body.
fn header_keyword_name(kind: &str) -> &'static str {
    match kind {
        "if_statement" => "if",
        "for_statement" => "for",
        "foreach_statement" => "foreach",
        "while_statement" => "while",
        "do_statement" => "do",
        "using_statement" => "using",
        "lock_statement" => "lock",
        "fixed_statement" => "fixed",
        _ => "control",
    }
}
