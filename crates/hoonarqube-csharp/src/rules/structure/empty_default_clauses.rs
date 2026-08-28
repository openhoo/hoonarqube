use super::support::section_has_default;
use super::support::section_statements;
use super::support::switch_body_of;
use super::support::switch_sections_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3532 — empty `default` clauses are removed.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(body) = switch_body_of(switch_statement) else {
            continue;
        };
        for section in switch_sections_of(body) {
            let statements = section_statements(section);
            if section_has_default(section)
                && statements
                    .iter()
                    .all(|statement| statement.kind() == "break_statement")
            {
                issues.push(issue(
                    language,
                    "S3532",
                    "Remove this empty 'default' clause.",
                    range_of(section, source),
                ));
            }
        }
    }
    issues
}
