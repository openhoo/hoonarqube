use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3217 — a typed `foreach` over a generic collection must not
/// silently downcast each element.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for each in collect_kinds(root, &["foreach_statement"]) {
        if is_error_tainted(each) {
            continue;
        }
        let Some(loop_variable) = each.child_by_field_name("left") else {
            continue;
        };
        let Some(loop_type) = each.child_by_field_name("type") else {
            continue;
        };
        let Some(collection) = each.child_by_field_name("right") else {
            continue;
        };
        if collection.kind() != "identifier" {
            continue;
        }
        let collection_name = node_text(collection, source);
        let Some(element_type) = generic_element_type(root, collection_name, source) else {
            continue;
        };
        let loop_type_text = node_text(loop_type, source);
        if element_type == "object" || element_type == loop_type_text {
            continue;
        }
        issues.push(issue(
            language,
            "S3217",
            format!(
                "Either change the type of '{}' to '{}' or iterate on a generic collection of type '{}'.",
                node_text(loop_variable, source),
                element_type,
                loop_type_text
            ),
            range_of(loop_type, source),
        ));
    }
    issues
}

fn generic_element_type<'a>(root: Node<'_>, name: &str, source: &'a str) -> Option<&'a str> {
    for declaration in collect_kinds(root, &["parameter", "variable_declarator"]) {
        let declared_name = declaration.child_by_field_name("name")?;
        if node_text(declared_name, source) != name {
            continue;
        }
        let type_node = if declaration.kind() == "parameter" {
            declaration.child_by_field_name("type")
        } else {
            declaration
                .parent()
                .and_then(|parent| parent.child_by_field_name("type"))
        }?;
        let type_text = node_text(type_node, source);
        let start = type_text.rfind('<')? + 1;
        let end = type_text[start..].find([',', '>'])? + start;
        return Some(type_text[start..end].trim());
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3217_flags_typed_iteration_downcasts() {
        let report = analyze_default(
            "class Fruit { }\nclass Orange : Fruit { }\nclass A\n{\n    void M(System.Collections.Generic.List<Fruit> rows)\n    {\n        foreach (Orange row in rows)\n            Log(row);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3217").len(), 1);
    }

    #[test]
    fn s3217_matching_iteration_types_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(System.Collections.Generic.List<string> values)\n    {\n        foreach (string raw in values)\n            Log(raw.Length);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3217").is_empty());
    }
}
