use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, simple_name};
use crate::rules::security::return_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3995 — URI-shaped method names should return `System.Uri`, not
/// a string.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let method_name = node_text(name, source).to_lowercase();
        if simple_name(return_type_text(method, source)) != "string"
            || !(method_name.contains("uri")
                || method_name.contains("urn")
                || method_name.contains("url"))
        {
            continue;
        }
        let Some(return_type) = method.child_by_field_name("returns") else {
            continue;
        };
        issues.push(issue(
            language,
            "S3995",
            "Change this return type to 'System.Uri'.",
            range_of(return_type, source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3995_parameter_overloads_without_uri_returns_are_clean() {
        let report = analyze_default(
            "class C\n{\n    public string Load(string path) { return path; }\n    public string Load(Uri path) { return \"\"; }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3995").is_empty());
    }

    #[test]
    fn s3995_flags_uri_named_string_return() {
        let report = analyze_default(
            "class C\n{\n    public string GetParentUri() { return \"\"; }\n    public string Save() { return \"\"; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3995");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3995_uri_return_type_is_clean() {
        let report =
            analyze_default("class C\n{\n    public System.Uri GetUri() { return null!; }\n}\n");
        assert!(with_key(&report, "csharpsquid:S3995").is_empty());
    }

    #[test]
    fn s3995_empty_class_is_clean() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3995").is_empty());
    }
}
