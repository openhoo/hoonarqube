use super::support::logging_calls;
use super::support::template_argument;
use super::support::template_placeholders;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for name in template_placeholders(template) {
            if !seen.insert(name.to_ascii_lowercase()) {
                let shown = format!("{{{name}}}");
                issues.push(issue(
                    language,
                    "S6677",
                    format!("Rename the duplicate placeholder {shown}."),
                    range_of(literal, source),
                ));
            }
        }
    }
    issues
}
