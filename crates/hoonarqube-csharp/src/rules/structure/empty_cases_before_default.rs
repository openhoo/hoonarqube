use super::support::section_has_default;
use super::support::section_statements;
use super::support::switch_body_of;
use super::support::switch_sections_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3458 — an empty `case` stack falling straight into
/// `default` drops its labels.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(body) = switch_body_of(switch_statement) else {
            continue;
        };
        for pair in switch_sections_of(body).windows(2) {
            if section_statements(pair[0]).is_empty() && section_has_default(pair[1]) {
                issues.push(issue(
                    language,
                    "S3458",
                    "Remove this empty 'case'; it falls through to 'default'.",
                    range_of(pair[0]),
                ));
            }
        }
    }
    issues
}
