use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::{creation_type_text, first_named_child};
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3257 — when the initializer spells out the type again, `var`
/// keeps the declaration honest without repeating it.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["local_declaration_statement"]) {
        if is_error_tainted(statement) || modifiers_of(statement, source).contains(&"const") {
            continue;
        }
        let Some(declaration) = first_named_child(statement) else {
            continue;
        };
        let Some(type_node) = declaration.child_by_field_name("type") else {
            continue;
        };
        if type_node.kind() == "implicit_type" {
            continue;
        }
        let declared = node_text(type_node, source)
            .split_whitespace()
            .collect::<String>();
        for declarator in collect_kinds(declaration, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(initializer) = declarator_initializer(declarator, name) else {
                continue;
            };
            if initializer.kind() != "object_creation_expression" {
                continue;
            }
            let created = creation_type_text(initializer, source)
                .split_whitespace()
                .collect::<String>();
            if created == declared {
                issues.push(issue(
                    language,
                    "S3257",
                    "Use 'var' for this declaration.",
                    range_of(declarator, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3257_interface_typed_declarations_stay_clean() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        System.Collections.Generic.IEnumerable<int> wide = new System.Collections.Generic.List<int>();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3257").is_empty());
    }

    #[test]
    fn s3257_flags_every_redundant_declarator_in_a_statement() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        List<int> left = new List<int>(), right = new List<int>();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3257");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5); // document line 4
        assert_eq!(flagged[1].range.start.line, 5);
    }

    #[test]
    fn s3257_normalizes_generic_whitespace_before_comparing() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Dictionary<string, int> map = new Dictionary<string, int>();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3257");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5); // document line 4
    }
}
