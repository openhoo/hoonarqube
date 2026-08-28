use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
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
        let expected = normalized_member_name(node_text(property_name, source));
        if !owner_declares_field(property, &expected, source) {
            continue;
        }
        for accessor in accessors_of(property) {
            let actual = match accessor_keyword(accessor, source) {
                "get" => getter_field(accessor, source),
                "set" => setter_field(accessor, source),
                _ => None,
            };
            let Some(actual) = actual else {
                continue;
            };
            if normalized_member_name(actual) == expected {
                continue;
            }
            let anchor = collect_kinds(accessor, &["identifier"])
                .into_iter()
                .find(|identifier| node_text(*identifier, source) == actual)
                .unwrap_or(property_name);
            let accessor_kind = accessor_keyword(accessor, source);
            issues.push(issue(
                language,
                "S4275",
                format!(
                    "Refactor this {accessor_kind}ter so that it actually refers to the field '{}'.",
                    node_text(property_name, source).to_lowercase()
                ),
                range_of(anchor, source),
            ));
        }
    }
    issues
}

fn owner_declares_field(property: Node<'_>, expected: &str, source: &str) -> bool {
    let Some(owner) =
        ancestors_of(property).find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
    else {
        return false;
    };
    collect_kinds(owner, &["field_declaration"])
        .into_iter()
        .filter(|field| {
            ancestors_of(*field).find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
                == Some(owner)
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .any(|name| normalized_member_name(node_text(name, source)) == expected)
}

fn normalized_member_name(name: &str) -> String {
    name.chars()
        .filter(|character| *character != '_')
        .flat_map(char::to_lowercase)
        .collect()
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
    fn s4275_checks_a_getter_against_its_property_name() {
        let report = analyze_default(
            "class A\n{\n    private string first;\n    private string value;\n\n    public string Value\n    {\n        get { return first; }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4275").len(), 1);
    }

    #[test]
    fn s4275_accepts_matching_backing_fields() {
        let report = analyze_default(
            "class A\n{\n    private string first;\n\n    public string First\n    {\n        get { return first; }\n        set { first = value; }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4275").is_empty());
    }

    #[test]
    fn s4275_reports_each_mismatched_property_distinctly() {
        let report = analyze_default(
            "class A\n{\n    private string first;\n    private string second;\n    private string alpha;\n    private string beta;\n\n    public string Alpha\n    {\n        get { return first; }\n        set { second = value; }\n    }\n\n    public string Beta\n    {\n        get { return second; }\n        set { first = value; }\n    }\n}\n",
        );
        let mut lines: Vec<u32> = with_key(&report, "csharpsquid:S4275")
            .iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![10, 11, 16, 17]);
    }
}
