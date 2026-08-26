use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::{accessor_keyword, accessors_of, getter_field, setter_field};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4275 — accessors of one property must agree on the backing
/// field they touch.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let Some(property_name) = property.child_by_field_name("name") else {
            continue;
        };
        let mut getter_field_name: Option<&str> = None;
        let mut setter_field_name: Option<&str> = None;
        for accessor in accessors_of(property) {
            match accessor_keyword(accessor, source) {
                "get" => getter_field_name = getter_field(accessor, source),
                "set" => setter_field_name = setter_field(accessor, source),
                _ => {}
            }
        }
        match (getter_field_name, setter_field_name) {
            (Some(read), Some(written)) if read != written => issues.push(issue(
                language,
                "S4275",
                format!(
                    "'get' and 'set' accessors of '{}' touch different fields ('{read}' vs '{written}').",
                    node_text(property_name, source)
                ),
                range_of(property_name, source),
            )),
            _ => {}
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4275_ignores_auto_properties() {
        let report = analyze_default(
            "class A\n{\n    public string Name\n    {\n        get;\n        set;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4275").is_empty());
    }

    #[test]
    fn s4275_requires_both_accessors_to_touch_fields() {
        let report = analyze_default(
            "class A\n{\n    private string first;\n\n    public string Value\n    {\n        get { return first; }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4275").is_empty());
    }

    #[test]
    fn s4275_accepts_matching_backing_fields() {
        let report = analyze_default(
            "class A\n{\n    private string first;\n\n    public string Value\n    {\n        get { return first; }\n        set { first = value; }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4275").is_empty());
    }

    #[test]
    fn s4275_reports_each_mismatched_property_distinctly() {
        let report = analyze_default(
            "class A\n{\n    private string first;\n    private string second;\n\n    public string Alpha\n    {\n        get { return first; }\n        set { second = value; }\n    }\n\n    public string Beta\n    {\n        get { return second; }\n        set { first = value; }\n    }\n}\n",
        );
        let mut lines: Vec<u32> = with_key(&report, "csharpsquid:S4275")
            .iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![6, 12]);
    }
}
