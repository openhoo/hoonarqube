use super::support::composite_template;
use super::support::is_composite_format_call;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::invocation_arguments;
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
        let Some((literal, template, _)) = composite_template(call, source) else {
            continue;
        };
        let highest_slot = composite_slots(template).into_iter().max();
        let arguments = invocation_arguments(call);
        let format_index = arguments
            .iter()
            .position(|argument| collect_kinds(*argument, &["string_literal"]).contains(&literal))
            .unwrap_or(0);
        let values = &arguments[format_index.saturating_add(1)..];
        let used = highest_slot.map_or(0, |slot| slot + 1);
        if values.len() > used {
            let names = values[used..]
                .iter()
                .map(|argument| format!("'{}'", node_text(*argument, source)))
                .collect::<Vec<_>>()
                .join(", ");
            issues.push(issue(
                language,
                "S3457",
                format!(
                    "The format string might be wrong, the following arguments are unused: {names}."
                ),
                call.child_by_field_name("function").map_or_else(
                    || range_of(literal, source),
                    |callee| range_of(callee, source),
                ),
            ));
        }
    }
    issues
}

/// Issue worth raising for one invocation: malformed slots, or a
/// slot-less format string that still receives arguments.
fn composite_slots(template: &str) -> Vec<usize> {
    let mut slots = Vec::new();
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
                    break;
                };
                if let Some(slot) = template[index + 1..close]
                    .split([',', ':'])
                    .next()
                    .and_then(|value| value.trim().parse().ok())
                {
                    slots.push(slot);
                }
                index = close + 1;
            }
            b'}' => {
                if bytes.get(index + 1) != Some(&b'}') {
                    break;
                }
                index += 2;
            }
            _ => index += 1,
        }
    }
    slots
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3457_treats_doubled_braces_as_escapes() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"{{0}}\", one);\n        text = string.Format(\"Plain text\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3457").len(), 1);
    }

    #[test]
    fn s3457_flags_lone_closing_and_empty_slots() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"Lone }\");\n        text = string.Format(\"{}\", one);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3457");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }
}
