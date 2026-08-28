use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3996 — URI-named properties should carry real URIs.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let property_name = property.child_by_field_name("name");
        let named_uri = property_name
            .and_then(|name| node_text(name, source).strip_suffix("Uri"))
            .is_some_and(|prefix| !prefix.is_empty());
        let string_type = property
            .child_by_field_name("type")
            .filter(|type_node| simple_name(node_text(*type_node, source)) == "string");
        if let (true, Some(string_type)) = (named_uri, string_type) {
            let name = property_name.map_or("property", |name| node_text(name, source));
            issues.push(issue(
                language,
                "S3996",
                format!("Change the '{name}' property type to 'System.Uri'."),
                range_of(string_type, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3996_respects_suffix_and_type_boundaries() {
        let report = analyze_default(
            "class C\n{\n    public System.Uri HomeUri { get; set; }\n    public string Uri { get; set; }\n    public string XUri { get; set; }\n    public string homeuri { get; set; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3996");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5); // document line 4
    }

    #[test]
    fn s3996_empty_class_is_clean() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3996").is_empty());
    }
}
