use super::support::methods_grouped_by_name;
use crate::CsLanguage;
use crate::cst::{issue, node_text, parameters_of, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3994 — string parameters duplicating a sibling `System.Uri`
/// overload push conversion work onto callers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
        if methods.len() < 2 {
            continue;
        }
        let shapes: Vec<Vec<String>> = methods
            .iter()
            .map(|method| {
                parameters_of(*method)
                    .iter()
                    .filter_map(|parameter| parameter.child_by_field_name("type"))
                    .map(|type_node| simple_name(node_text(type_node, source)).to_string())
                    .collect()
            })
            .collect();
        for index in 0..shapes.iter().map(Vec::len).max().unwrap_or(0) {
            let has_uri = shapes
                .iter()
                .any(|shape| shape.get(index).is_some_and(|name| name == "Uri"));
            if !has_uri {
                continue;
            }
            for (method, shape) in methods.iter().zip(&shapes) {
                if shape.get(index).is_some_and(|name| name == "string") {
                    issues.push(issue(
                        language,
                        "S3994",
                        "Accept a 'System.Uri' instead of a string here.",
                        range_of(*method, source),
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
    fn s3994_single_overload_without_sibling_is_clean() {
        let report = analyze_default("class C\n{\n    public void Load(string path) { }\n}\n");
        assert!(with_key(&report, "csharpsquid:S3994").is_empty());
    }

    #[test]
    fn s3994_flags_every_string_overload_of_the_group() {
        let report = analyze_default(
            "class C\n{\n    public void Load(Uri u) { }\n    public void Load(string s) { }\n    public void Save(Uri u) { }\n    public void Save(string s) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3994");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 4); // document line 3
        assert_eq!(flagged[1].range.start.line, 6); // document line 5
    }

    #[test]
    fn s3994_requires_positional_alignment_with_the_uri_parameter() {
        let report = analyze_default(
            "class C\n{\n    public void Load(Uri u, int mode) { }\n    public void Load(int mode, string s) { }\n    public void Save(Uri u, int mode) { }\n    public void Save(string s, int mode) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3994");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6); // document line 5
    }

    #[test]
    fn s3994_accepts_namespace_qualified_uri_siblings() {
        let report = analyze_default(
            "class C\n{\n    public void Load(System.Uri u) { }\n    public void Load(string s) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3994");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4); // document line 3
    }
}
