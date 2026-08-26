use super::support::logging_calls;
use super::support::template_argument;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6674 — malformed message templates fail at logging time.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        if !template_is_valid(template) {
            issues.push(issue(
                language,
                "S6674",
                "Fix this malformed message template.",
                range_of(literal, source),
            ));
        }
    }
    issues
}

/// Whether a message template parses: balanced braces, no empty or nested
/// placeholders, and no stray closing brace.
fn template_is_valid(template: &str) -> bool {
    let bytes = template.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                let Some(close) = bytes[index + 1..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|relative| index + 1 + relative)
                else {
                    return false;
                };
                if close == index + 1 || bytes[index + 1..close].contains(&b'{') {
                    return false;
                }
                index = close + 1;
            }
            b'}' => return false,
            _ => index += 1,
        }
    }
    true
}
