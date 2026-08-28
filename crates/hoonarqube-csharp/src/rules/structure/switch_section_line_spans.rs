use super::support::{section_statements, switch_body_of, switch_sections_of};
use crate::cst::{collect_kinds, is_error_tainted, issue, range_from_byte_offsets, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1151 — a switch section fits within the tolerated span.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        for section in switch_body_of(switch_statement)
            .map(switch_sections_of)
            .unwrap_or_default()
        {
            let statement_count = to_u32(section_statements(section).len());
            if statement_count > options.maximum_switch_section_lines {
                let label_end = source[section.start_byte()..section.end_byte()]
                    .find(':')
                    .map_or(section.end_byte(), |offset| {
                        section.start_byte() + offset + 1
                    });
                issues.push(issue(
                    language,
                    "S1151",
                    format!(
                        "Reduce this switch section number of statements from {statement_count} to at most {}, for example by extracting code into a method.",
                        options.maximum_switch_section_lines
                    ),
                    range_from_byte_offsets(section.start_byte(), label_end, source),
                ));
            }
        }
    }
    issues
}
