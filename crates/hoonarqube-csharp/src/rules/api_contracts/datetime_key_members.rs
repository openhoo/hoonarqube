use crate::CsLanguage;
use crate::cst::{
    attributes_of, collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::expressions::first_named_child;
use crate::rules::logging::field_declarator_names;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3363 — date/time values make unstable, ambiguous keys.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const DATETIME_TYPES: [&str; 2] = ["DateTime", "DateTimeOffset"];
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let primary_key = property
            .child_by_field_name("name")
            .is_some_and(|name| key_shaped(node_text(name, source)))
            || attributes_of(property, source).contains(&"Key");
        let Some(type_node) = property.child_by_field_name("type") else {
            continue;
        };
        let type_name = simple_name(node_text(type_node, source));
        if primary_key && DATETIME_TYPES.contains(&type_name) {
            issues.push(issue(
                language,
                "S3363",
                format!("'{type_name}' should not be used as a type for primary keys"),
                range_of(type_node, source),
            ));
        }
    }
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let named_key = field_declarator_names(field, source)
            .into_iter()
            .any(key_shaped);
        let typed_datetime = collect_kinds(field, &["variable_declaration"])
            .first()
            .and_then(|declaration| first_named_child(*declaration))
            .is_some_and(|type_node| {
                DATETIME_TYPES.contains(&simple_name(node_text(type_node, source)))
            });
        if named_key && typed_datetime {
            issues.push(issue(
                language,
                "S3363",
                "'DateTime' should not be used as a type for primary keys",
                range_of(field, source),
            ));
        }
    }
    issues
}

/// Key-shaped member names (`Id`, `OrderKey`, ...).
fn key_shaped(name: &str) -> bool {
    name == "Id"
        || name == "Key"
        || (name.ends_with("Id") && name.len() > 2)
        || (name.ends_with("Key") && name.len() > 3)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3363_flags_key_shaped_datetime_fields() {
        let report = analyze_default(
            "class R\n{\n    private DateTime OrderKey;\n    public DateTimeOffset MyId;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3363").len(), 2);
    }

    #[test]
    fn s3363_lowercase_names_are_not_key_shaped() {
        let report = analyze_default(
            "class R\n{\n    public DateTime id { get; set; }\n    public DateTimeOffset stamp;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3363").is_empty());
    }
}
