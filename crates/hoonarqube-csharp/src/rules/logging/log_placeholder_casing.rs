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
        for name in template_placeholders(template) {
            let positional = name.chars().all(|character| character.is_ascii_digit());
            if positional || is_pascal_case(name) {
                continue;
            }
            let shown = format!("{{{name}}}");
            issues.push(issue(
                language,
                "S6678",
                format!("Rename the placeholder {shown} to PascalCase."),
                range_of(literal),
            ));
        }
    }
    issues
}
