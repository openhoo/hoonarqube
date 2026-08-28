use super::support::methods_grouped_by_name;
use crate::CsLanguage;
use crate::cst::{issue, node_text, parameters_of, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3994 — URI-shaped string parameters require a corresponding
/// `System.Uri` overload.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
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
        for (method_index, method) in methods.iter().enumerate() {
            let parameters = parameters_of(*method);
            for (parameter_index, parameter) in parameters.iter().enumerate() {
                let Some(name) = parameter.child_by_field_name("name") else {
                    continue;
                };
                if shapes[method_index]
                    .get(parameter_index)
                    .is_none_or(|parameter_type| parameter_type != "string")
                    || !looks_like_uri_name(node_text(name, source))
                {
                    continue;
                }
                let has_uri_overload = shapes.iter().enumerate().any(|(other_index, shape)| {
                    other_index != method_index
                        && shape.len() == shapes[method_index].len()
                        && shape.iter().enumerate().all(|(index, parameter_type)| {
                            if index == parameter_index {
                                parameter_type == "Uri"
                            } else {
                                shapes[method_index].get(index) == Some(parameter_type)
                            }
                        })
                });
                if !has_uri_overload {
                    let anchor = parameter.child_by_field_name("type").unwrap_or(name);
                    issues.push(issue(
                        language,
                        "S3994",
                        "Either change this parameter type to 'System.Uri' or provide an overload which takes a 'System.Uri' parameter.",
                        range_of(anchor, source),
                    ));
                }
            }
        }
    }
    issues
}

fn looks_like_uri_name(name: &str) -> bool {
    let lowercase = name.to_lowercase();
    lowercase.contains("uri") || lowercase.contains("urn") || lowercase.contains("url")
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3994_single_uri_named_string_without_sibling_flags() {
        let report = analyze_default("class C\n{\n    public void Load(string uriPath) { }\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S3994").len(), 1);
    }

    #[test]
    fn s3994_corresponding_uri_overloads_are_clean() {
        let report = analyze_default(
            "class C\n{\n    public void Load(Uri u) { }\n    public void Load(string s) { }\n    public void Save(Uri u) { }\n    public void Save(string s) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3994").is_empty());
    }

    #[test]
    fn s3994_non_uri_parameter_names_are_ignored() {
        let report = analyze_default(
            "class C\n{\n    public void Load(Uri u, int mode) { }\n    public void Load(int mode, string s) { }\n    public void Save(Uri u, int mode) { }\n    public void Save(string s, int mode) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3994").is_empty());
    }

    #[test]
    fn s3994_accepts_namespace_qualified_uri_siblings() {
        let report = analyze_default(
            "class C\n{\n    public void Load(System.Uri uri) { }\n    public void Load(string uri) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3994").is_empty());
    }
}
