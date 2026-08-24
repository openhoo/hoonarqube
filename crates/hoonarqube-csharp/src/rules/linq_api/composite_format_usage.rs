use super::support::composite_template;
use super::support::is_composite_format_call;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3457 — composite formats need valid slots, and pointless
/// format strings hide plain output.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) || !is_composite_format_call(call, source) {
            continue;
        }
        let Some((literal, template, budget)) = composite_template(call, source) else {
            continue;
        };
        if !composite_template_is_valid(template) {
            issues.push(issue(
                language,
                "S3457",
                "Fix this malformed composite format string.",
                range_of(literal),
            ));
        } else if !template.contains('{') && budget > 0 {
            issues.push(issue(
                language,
                "S3457",
                "Pass the arguments directly instead of using this format string.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// Composite-format brace scan honoring doubled-brace escapes.
fn composite_template_is_valid(template: &str) -> bool {
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
                    return false;
                };
                if close == index + 1 || bytes[index + 1..close].contains(&b'{') {
                    return false;
                }
                index = close + 1;
            }
            b'}' => {
                if bytes.get(index + 1) != Some(&b'}') {
                    return false;
                }
                index += 2;
            }
            _ => index += 1,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3457_treats_doubled_braces_as_escapes() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"{{0}}\", one);\n        text = string.Format(\"Plain text\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3457").is_empty());
    }

    #[test]
    fn s3457_flags_lone_closing_and_empty_slots() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"Lone }\");\n        text = string.Format(\"{}\", one);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3457");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5); // document line 4
        assert_eq!(flagged[1].range.start.line, 6); // document line 5
    }
}
