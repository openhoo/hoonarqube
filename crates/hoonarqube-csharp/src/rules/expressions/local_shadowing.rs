use super::support::field_and_property_names;
use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
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
        for local in collect_kinds(type_declaration, &["local_declaration_statement"]) {
            for declarator in collect_kinds(local, &["variable_declarator"]) {
                let Some(identifier) = first_named_child(declarator) else {
                    continue;
                };
                if identifier.kind() != "identifier" {
                    continue;
                }
                let name = node_text(identifier, source);
                if member_names.contains(name) {
                    issues.push(issue(
                        language,
                        "S1117",
                        format!("Rename '{name}'; it shadows a member of its enclosing type."),
                        range_of(declarator),
                    ));
                }
            }
        }
    }
    issues
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
}
