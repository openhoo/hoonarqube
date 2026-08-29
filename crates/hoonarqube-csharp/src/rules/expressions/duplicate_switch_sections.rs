use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::{section_statements, switch_body_of, switch_sections_of};
use hoonarqube_ir::Issue;
use std::collections::HashMap;
use tree_sitter::Node;

/// csharpsquid:S1871 — switch sections repeating an earlier section's
/// implementation verbatim.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(switch_body) = switch_body_of(switch_statement) else {
            continue;
        };
        let mut first_lines = HashMap::new();
        for section in switch_sections_of(switch_body) {
            let text = section_text(section, source);
            if text.is_empty() {
                continue;
            }
            if let Some(earlier_line) = first_lines.get(&text) {
                issues.push(issue(
                    language,
                    "S1871",
                    format!(
                        "Either merge this case with the identical one on line {earlier_line} or change one of the implementations."
                    ),
                    range_of(section, source),
                ));
            } else {
                first_lines.insert(text, range_of(section, source).start.line);
            }
        }
    }
    issues
}

/// Statement-sequence spelling of a switch section, for duplicate checks.
fn section_text(section: Node<'_>, source: &str) -> String {
    let mut text = String::new();
    for statement in section_statements(section) {
        text.push_str(node_text(statement, source));
    }
    text
}
