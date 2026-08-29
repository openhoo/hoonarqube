use super::support::{section_statements, switch_body_of, switch_sections_of};
use crate::cst::{collect_kinds, is_error_tainted, issue, range_from_byte_offsets, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1151 — a switch section fits within the tolerated span.
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
        for section in switch_body_of(switch_statement)
            .map(switch_sections_of)
            .unwrap_or_default()
        {
            let statements = section_statements(section);
            let statement_count = to_u32(statements.len());
            if statement_count > options.maximum_switch_section_lines {
                let mut cursor = section.walk();
                let label_end = section
                    .children(&mut cursor)
                    .find(|child| child.kind() == ":")
                    .map_or(section.end_byte(), |colon| colon.end_byte());
                issues.push(issue(
                    language,
                    "S1151",
                    format!(
                        "Reduce this switch section number of statements from {statement_count} to at most {}, for example by extracting code into a method.",
                        options.maximum_switch_section_lines
                    ),
                    range_from_byte_offsets(section.start_byte(), label_end, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::AnalyzerOptions;
    use crate::tests::{analyze_options, with_key};

    #[test]
    fn s1151_counts_statements_not_physical_lines() {
        let source = "class C\n{\n    void M(int value)\n    {\n        switch (value)\n        {\n            case 1:\n                Call(\n                    value);\n                break;\n        }\n    }\n}\n";
        let options = AnalyzerOptions {
            maximum_switch_section_lines: 2,
            ..Default::default()
        };
        let report = analyze_options(source, &options);
        let flagged = with_key(&report, "csharpsquid:S1151");
        assert!(flagged.is_empty());
    }

    #[test]
    fn s1151_label_range_uses_label_colon_not_colon_inside_string() {
        let source = "class C\n{\n    void M(string value)\n    {\n        switch (value)\n        {\n            case \"http://\":\n                First();\n                Second();\n        }\n    }\n}\n";
        let options = AnalyzerOptions {
            maximum_switch_section_lines: 1,
            ..Default::default()
        };
        let report = analyze_options(source, &options);
        let flagged = with_key(&report, "csharpsquid:S1151");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.end.column, 27);
    }
}
