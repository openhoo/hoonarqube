use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4005 — pass parsed `System.Uri` values instead of raw
/// strings at dual-overload call sites.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut overloads = std::collections::HashMap::<&str, Vec<Vec<String>>>::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        overloads.entry(node_text(name, source)).or_default().push(
            parameters_of(method)
                .into_iter()
                .filter_map(|parameter| parameter.child_by_field_name("type"))
                .map(|parameter_type| simple_name(node_text(parameter_type, source)).to_string())
                .collect(),
        );
    }
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let Some(name) = callee_name(call, source) else {
            continue;
        };
        let Some(shapes) = overloads.get(name) else {
            continue;
        };
        let arguments = invocation_arguments(call);
        let has_string_uri_pair = shapes.iter().any(|string_shape| {
            shapes.iter().any(|uri_shape| {
                string_shape.len() == uri_shape.len()
                    && string_shape.iter().zip(uri_shape).enumerate().any(
                        |(index, (string_type, uri_type))| {
                            string_type == "string"
                                && uri_type == "Uri"
                                && arguments.get(index).is_some_and(|argument| {
                                    argument_expression(*argument).kind() == "string_literal"
                                })
                                && string_shape.iter().zip(uri_shape).enumerate().all(
                                    |(other_index, (left, right))| {
                                        other_index == index || left == right
                                    },
                                )
                        },
                    )
            })
        });
        if has_string_uri_pair {
            issues.push(issue(
                language,
                "S4005",
                "Call the overload that takes a 'System.Uri' as an argument instead.",
                range_of(call, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4005_checks_string_calls_when_local_uri_overload_exists() {
        let report = analyze_default(
            "class A\n{\n    void Load(string uri) { }\n    void Load(System.Uri uri) { }\n    void M()\n    {\n        Load(\"http://example.com\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4005");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s4005_ignores_unknown_members_and_nonliteral_first_arguments() {
        let report = analyze_default(
            "class A\n{\n    void M(System.Net.WebClient client)\n    {\n        other = client.UnknownMethod(\"http://example.com\");\n        none = client.DownloadString();\n        stream = client.OpenRead(address);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4005").is_empty());
    }
}
