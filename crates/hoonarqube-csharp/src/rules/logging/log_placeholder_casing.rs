use super::support::logging_calls;
use super::support::template_argument;
use super::support::template_placeholders;
use crate::CsLanguage;
use crate::cst::{is_pascal_case, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6678 — placeholders read as property names and must be
/// `PascalCase`; positional numeric slots are exempt.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        if template_placeholders(template).into_iter().any(|name| {
            !name.chars().all(|character| character.is_ascii_digit()) && !is_pascal_case(name)
        }) {
            issues.push(issue(
                language,
                "S6678",
                "Use PascalCase for named placeholders.",
                range_of(literal, source),
            ));
        }
    }
    issues
}
