use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::{section_statements, switch_body_of, switch_sections_of};
use hoonarqube_ir::Issue;
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
        let sections = switch_sections_of(switch_body);
        let texts: Vec<String> = sections
            .iter()
            .map(|section| section_text(*section, source))
            .collect();
        for (index, section) in sections.iter().enumerate() {
            let text = &texts[index];
            if text.is_empty() {
                continue;
            }
            if let Some(earlier_index) = texts[..index].iter().position(|earlier| earlier == text) {
                let earlier_line = range_of(sections[earlier_index], source).start.line;
                issues.push(issue(
                    language,
                    "S1871",
                    format!(
                        "Either merge this case with the identical one on line {earlier_line} or change one of the implementations."
                    ),
                    range_of(*section, source),
                ));
            }
        }
    }
    issues
}

/// Statement-sequence spelling of a switch section, for duplicate checks.
fn section_text(section: Node<'_>, source: &str) -> String {
    section_statements(section)
        .iter()
        .map(|statement| node_text(*statement, source))
        .collect::<Vec<_>>()
        .concat()
}
