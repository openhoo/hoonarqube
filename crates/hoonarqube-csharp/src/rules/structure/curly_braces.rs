use super::support::EMBEDDED_HEADER_KINDS;
use super::support::embedded_bodies;
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
            if body.kind() != "block" {
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
    }
    issues
}
