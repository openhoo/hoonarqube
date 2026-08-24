use super::support::section_statements;
use super::support::switch_body_of;
use super::support::switch_sections_of;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1479 — a switch section holds at most the tolerated number
/// of statements.
pub(crate) fn check(root: Node<'_>, language: CsLanguage, options: &AnalyzerOptions) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        for section in switch_body_of(switch_statement)
            .map(switch_sections_of)
            .unwrap_or_default()
        {
            let count = to_u32(section_statements(section).len());
            if count > options.maximum_switch_section_statements {
                issues.push(issue(
                    language,
                    "S1479",
                    format!("Split this 'case' block; it contains {count} statements."),
                    range_of(section),
                ));
            }
        }
    }
    issues
}
