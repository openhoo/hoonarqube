use super::support::section_statements;
use super::support::switch_body_of;
use super::support::switch_sections_of;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1479 — a switch section holds at most the tolerated number
/// of statements.
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
        let sections = switch_body_of(switch_statement)
            .map(switch_sections_of)
            .unwrap_or_default();
        if to_u32(sections.len()) <= options.maximum_switch_section_statements {
            continue;
        }
        let has_multi_statement_case = sections.into_iter().any(|section| {
            let count = section_statements(section)
                .into_iter()
                .filter(|statement| {
                    !matches!(
                        statement.kind(),
                        "break_statement" | "return_statement" | "throw_statement"
                    )
                })
                .count();
            count > 1
        });
        if !has_multi_statement_case {
            continue;
        }
        let mut cursor = switch_statement.walk();
        let anchor = switch_statement
            .children(&mut cursor)
            .find(|child| child.kind() == "switch")
            .unwrap_or(switch_statement);
        issues.push(issue(
            language,
            "S1479",
            format!(
                "Consider reworking this 'switch' to reduce the number of 'case' clauses to at most {} or have only one statement per 'case'.",
                options.maximum_switch_section_statements
            ),
            range_of(anchor, source),
        ));
    }
    issues
}
