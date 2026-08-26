use super::support::section_has_default;
use super::support::switch_body_of;
use super::support::switch_sections_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4524 — the `default` clause leads or trails the sections.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(body) = switch_body_of(switch_statement) else {
            continue;
        };
        let sections = switch_sections_of(body);
        let Some(index) = sections.iter().position(|s| section_has_default(*s)) else {
            continue;
        };
        if index > 0 && index != sections.len() - 1 {
            issues.push(issue(
                language,
                "S4524",
                "Move this 'default' clause first or last among the sections.",
                range_of(sections[index], source),
            ));
        }
    }
    issues
}
