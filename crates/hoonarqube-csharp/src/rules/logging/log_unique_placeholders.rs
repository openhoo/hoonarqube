use super::support::TemplatePlaceholder;
use super::support::logging_calls;
use super::support::template_argument;
use super::support::template_placeholder_spans;
use crate::CsLanguage;
use crate::cst::{issue, range_from_byte_offsets};
use crate::rules::literals::literal_inner_offset;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        let mut first: std::collections::HashMap<String, TemplatePlaceholder<'_>> =
            std::collections::HashMap::new();
        let mut reported = std::collections::HashSet::new();
        let content_start = literal.start_byte() + literal_inner_offset(literal, source);
        for placeholder in template_placeholder_spans(template) {
            let name = placeholder.name;
            let normalized = name.to_ascii_lowercase();
            if let Some(first_placeholder) = first.get(&normalized) {
                if reported.insert(normalized) {
                    let start = content_start + first_placeholder.start;
                    issues.push(issue(
                        language,
                        "S6677",
                        format!("Message template placeholder '{name}' is not unique."),
                        range_from_byte_offsets(
                            start,
                            start + first_placeholder.name.len(),
                            source,
                        ),
                    ));
                }
            } else {
                first.insert(normalized, placeholder);
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6677_anchors_the_first_duplicate_placeholder_with_each_literal_kind() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        logger.LogInformation(@\"{Id} then {Id}\", id, id);\n        logger.LogInformation(\"\"\"{Name} then {Name}\"\"\", name, name);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6677");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.column, 33);
        assert_eq!(flagged[1].range.start.column, 34);
    }
}
