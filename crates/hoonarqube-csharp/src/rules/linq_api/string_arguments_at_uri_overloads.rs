use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::expressions::{
    callee_name, enclosing_type, invocation_arguments, invocation_receiver,
};
use crate::rules::literals::{argument_expression, is_string_literal};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4005 — pass parsed `System.Uri` values instead of raw
/// strings at dual-overload call sites.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut overloads = std::collections::HashMap::<(usize, &str), Vec<Vec<String>>>::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let Some(owner) = enclosing_type(method) else {
            continue;
        };
        overloads
            .entry((owner.id(), node_text(name, source)))
            .or_default()
            .push(
                parameters_of(method)
                    .into_iter()
                    .filter_map(|parameter| parameter.child_by_field_name("type"))
                    .map(|parameter_type| {
                        simple_name(node_text(parameter_type, source)).to_string()
                    })
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
        let Some(owner) = enclosing_type(call) else {
            continue;
        };
        if !targets_enclosing_type(call, owner, source) {
            continue;
        }
        let Some(shapes) = overloads.get(&(owner.id(), name)) else {
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
                                    is_string_literal(argument_expression(*argument))
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

/// Without semantic type resolution, only unqualified, `this`, and explicit
/// enclosing-type calls can safely use locally declared overloads.
fn targets_enclosing_type(call: Node<'_>, owner: Node<'_>, source: &str) -> bool {
    let Some(receiver) = invocation_receiver(call) else {
        return true;
    };
    let receiver = node_text(receiver, source);
    if receiver == "this" {
        return true;
    }
    owner
        .child_by_field_name("name")
        .is_some_and(|name| simple_name(receiver) == node_text(name, source))
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

    #[test]
    fn s4005_does_not_borrow_overloads_from_other_types_or_receivers() {
        let report = analyze_default(
            "class Overloaded\n{\n    public void Load(string uri) { }\n    public void Load(System.Uri uri) { }\n}\nclass Plain\n{\n    void Load(string uri) { }\n    void M(dynamic unknown)\n    {\n        Load(\"relative\");\n        unknown.Load(\"relative\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4005").is_empty());
    }
}
