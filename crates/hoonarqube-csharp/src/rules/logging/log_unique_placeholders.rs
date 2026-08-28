use super::support::logging_calls;
use super::support::template_argument;
use super::support::template_placeholders;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_from_byte_offsets, range_of};
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
                let token = format!("{{{name}}}");
                let range = node_text(literal, source).find(&token).map_or_else(
                    || range_of(literal, source),
                    |offset| {
                        let start = literal.start_byte() + offset + 1;
                        range_from_byte_offsets(start, start + name.len(), source)
                    },
                );
                issues.push(issue(
                    language,
                    "S6677",
                    format!("Message template placeholder '{name}' is not unique."),
                    range,
                ));
            }
        }
    }
    issues
}
