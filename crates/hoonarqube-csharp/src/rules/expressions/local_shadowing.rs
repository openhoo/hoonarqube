use super::support::field_and_property_names;
use super::support::first_named_child;
use super::support::member_declarations_of_kind;
use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1117 — locals do not shadow fields or properties of their
/// enclosing type.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_declaration in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_declaration) {
            continue;
        }
        let member_names = field_and_property_names(type_declaration, source);
        if member_names.is_empty() {
            continue;
        }
        let property_names: std::collections::HashSet<String> =
            member_declarations_of_kind(type_declaration, "property_declaration")
                .into_iter()
                .filter_map(|property| property.child_by_field_name("name"))
                .map(|name| node_text(name, source).to_owned())
                .collect();
        issues.extend(shadowing_local_issues(
            type_declaration,
            source,
            language,
            &member_names,
            &property_names,
        ));
    }
    issues
}

fn shadowing_local_issues(
    type_declaration: Node<'_>,
    source: &str,
    language: CsLanguage,
    member_names: &std::collections::HashSet<String>,
    property_names: &std::collections::HashSet<String>,
) -> Vec<Issue> {
    collect_kinds(type_declaration, &["local_declaration_statement"])
        .into_iter()
        .filter(|local| {
            super::support::enclosing_type(*local)
                .is_some_and(|owner| owner.id() == type_declaration.id())
        })
        .flat_map(local_declarators)
        .filter_map(|declarator| {
            let identifier = first_named_child(declarator)?;
            (identifier.kind() == "identifier").then_some(identifier)
        })
        .filter_map(|identifier| {
            let name = node_text(identifier, source);
            member_names.contains(name).then(|| {
                let member_kind = if property_names.contains(name) {
                    "property"
                } else {
                    "field"
                };
                issue(
                    language,
                    "S1117",
                    format!("Rename '{name}' which hides the {member_kind} with the same name."),
                    range_of(identifier, source),
                )
            })
        })
        .collect()
}

fn local_declarators(local: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(local, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| {
            ancestors_of(*declarator)
                .find(|ancestor| ancestor.kind() == "local_declaration_statement")
                .is_some_and(|owner| owner.id() == local.id())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1117_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1117").is_empty());
    }

    #[test]
    fn s1117_flags_local_shadowing_field() {
        let report = analyze_default(
            "class C\n{\n    private int value;\n\n    int M()\n    {\n        int value = 1;\n        return value;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1117");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
        assert!(flagged[0].message.contains("'value'"));
    }

    #[test]
    fn s1117_flags_var_local_shadowing_property() {
        let report = analyze_default(
            "class C\n{\n    public string Name { get; set; }\n\n    void M()\n    {\n        var Name = \"x\";\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1117");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s1117_ignores_assignments_method_names_and_unrelated_locals() {
        let report = analyze_default(
            "class C\n{\n    private int value;\n\n    void M()\n    {\n        int other = 1;\n        value = 2;\n    }\n\n    void N()\n    {\n        int M = 1;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1117").is_empty());
    }

    #[test]
    fn s1117_reports_each_shadowing_local_at_its_line() {
        let report = analyze_default(
            "class C\n{\n    private int a;\n    private int b;\n\n    void M()\n    {\n        int a = 1;\n        int b = 2;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1117");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 8);
        assert_eq!(flagged[1].range.start.line, 9);
    }

    #[test]
    fn s1117_applies_to_struct_members() {
        let report = analyze_default(
            "struct S\n{\n    public int Count;\n\n    void M()\n    {\n        var Count = 3;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1117");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s1117_does_not_apply_outer_members_to_nested_type_locals() {
        let report = analyze_default(
            "class Outer\n{\n    int value;\n    class Inner\n    {\n        void M()\n        {\n            int value = 1;\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1117").is_empty());
    }

    #[test]
    fn s1117_reports_nested_and_outer_members_once_with_correct_kind() {
        let report = analyze_default(
            "class Outer\n{\n    int value;\n    void M() { int value = 1; }\n    class Inner\n    {\n        int value { get; }\n        void M() { int value = 1; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1117");
        assert_eq!(flagged.len(), 2);
        assert!(flagged[0].message.contains("the field"));
        assert!(flagged[1].message.contains("the property"));
    }

    #[test]
    fn s1117_nested_lambda_local_is_not_traversed_twice() {
        let report = analyze_default(
            "class C { int value; void M() { System.Action action = () => { int value = 1; }; } }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1117").len(), 1);
    }

    #[test]
    fn s1117_does_not_treat_lambda_initializer_locals_as_fields() {
        let report = analyze_default(
            "class C { System.Action action = () => { int value = 1; }; void M() { int value = 2; } }",
        );
        assert!(with_key(&report, "csharpsquid:S1117").is_empty());
    }
}
