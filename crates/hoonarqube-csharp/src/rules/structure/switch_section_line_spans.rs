use super::support::switch_body_of;
use super::support::switch_sections_of;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1151 — a switch section fits within the tolerated span.
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
            let height = to_u32(section.end_position().row - section.start_position().row + 1);
            if height > options.maximum_switch_section_lines {
                issues.push(issue(
                    language,
                    "S1151",
                    format!("Reduce this 'case' block; it spans {height} lines."),
                    range_of(section),
                ));
            }
        }
    }
    issues
}
