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
            if body.kind() == "block" {
                continue;
            }
            // An `else` alternative anchors on its own `else` keyword, never
            // on the `if` keyword; `else if` chains are exempt per reference
            // semantics because the nested `if_statement` is checked itself.
            if is_else_alternative(body) {
                if body.kind() == "if_statement" {
                    continue;
                }
                let mut cursor = header.walk();
                let keyword = header
                    .children(&mut cursor)
                    .find(|child| child.kind() == "else")
                    .unwrap_or(header);
                issues.push(issue(
                    language,
                    "S121",
                    "Add curly braces around the nested statement(s) in this 'else' block.",
                    range_of(keyword, source),
                ));
                continue;
            }
            let keyword_name = match header.kind() {
                "if_statement" => "if",
                "for_statement" => "for",
                "foreach_statement" => "foreach",
                "while_statement" => "while",
                "do_statement" => "do",
                "using_statement" => "using",
                "lock_statement" => "lock",
                "fixed_statement" => "fixed",
                _ => "control",
            };
            let keyword = collect_kinds(header, &[keyword_name])
                .into_iter()
                .next()
                .unwrap_or(header);
            issues.push(issue(
                language,
                "S121",
                format!(
                    "Add curly braces around the nested statement(s) in this '{keyword_name}' block."
                ),
                range_of(keyword, source),
            ));
        }
    }
    issues
}
