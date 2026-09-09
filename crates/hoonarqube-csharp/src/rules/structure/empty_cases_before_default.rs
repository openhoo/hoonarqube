use super::support::section_has_default;
use super::support::section_statements;
use super::support::switch_body_of;
use super::support::switch_sections_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_from_byte_offsets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3458 — an empty `case` stack falling straight into
/// `default` drops its labels.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(body) = switch_body_of(switch_statement) else {
            continue;
        };
        for pair in switch_sections_of(body).windows(2) {
            if !section_statements(pair[0]).is_empty() || !section_has_default(pair[1]) {
                continue;
            }
            for (start, end) in case_label_spans(pair[0]) {
                issues.push(issue(
                    language,
                    "S3458",
                    "Remove this empty 'case' clause.",
                    range_from_byte_offsets(start, end, source),
                ));
            }
        }
    }
    issues
}

/// Return each `case ...:` label span in a section.
///
/// The labels are anonymous grammar tokens, so the section's direct children
/// are used to stop at the label colon without confusing a nested expression
/// colon with the switch-label delimiter.
fn case_label_spans(section: Node<'_>) -> Vec<(usize, usize)> {
    let mut cursor = section.walk();
    let children: Vec<_> = section.children(&mut cursor).collect();
    let mut spans = Vec::new();
    for (index, child) in children.iter().enumerate() {
        if child.kind() != "case" {
            continue;
        }
        let Some(colon) = children[index + 1..]
            .iter()
            .take_while(|candidate| !matches!(candidate.kind(), "case" | "default"))
            .find(|candidate| candidate.kind() == ":")
        else {
            continue;
        };
        spans.push((child.start_byte(), colon.end_byte()));
    }
    spans
}
