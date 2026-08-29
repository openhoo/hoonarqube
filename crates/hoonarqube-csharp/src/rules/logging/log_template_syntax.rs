use super::support::logging_calls;
use super::support::template_argument;
use crate::CsLanguage;
use crate::cst::{issue, range_from_byte_offsets, range_of};
use crate::rules::literals::literal_inner_offset;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6674 — malformed message templates fail at logging time.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        match template_error(template) {
            Some(TemplateError::Syntax) => issues.push(issue(
                language,
                "S6674",
                "Log message template should be syntactically correct.",
                range_of(literal, source),
            )),
            Some(TemplateError::EmptyPlaceholder(offset)) => {
                let start = literal.start_byte() + literal_inner_offset(literal, source) + offset;
                issues.push(issue(
                    language,
                    "S6674",
                    "Log message template should not contain empty placeholder.",
                    range_from_byte_offsets(start, start + 2, source),
                ));
            }
            None => {}
        }
    }
    issues
}

enum TemplateError {
    Syntax,
    EmptyPlaceholder(usize),
}

/// First Sonar-compatible template error. A lone closing brace is left to the
/// logging framework and does not trigger this rule in the pinned analyzer.
fn template_error(template: &str) -> Option<TemplateError> {
    let bytes = template.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                if bytes.get(index + 1) == Some(&b'{') {
                    index += 2;
                    continue;
                }
                let Some(close) = bytes[index + 1..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|relative| index + 1 + relative)
                else {
                    return Some(TemplateError::Syntax);
                };
                if close == index + 1 {
                    return Some(TemplateError::EmptyPlaceholder(index));
                }
                if bytes[index + 1..close].contains(&b'{') {
                    return Some(TemplateError::Syntax);
                }
                index = close + 1;
            }
            _ => index += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6674_accepts_escaped_opening_braces() {
        let report = analyze_default(
            "class C { void M() { logger.LogInformation(\"{{literal}} {Value}\", value); } }\n",
        );
        assert!(with_key(&report, "csharpsquid:S6674").is_empty());
    }
}
