use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, issue, modifiers_of, node_text, parameters_of, range_of,
};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3251 — a `partial` method without any implementing part in
/// this file never runs. Partial types span files, so implementations living
/// elsewhere are out of reach for this analyzer.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let partials: Vec<(Node<'_>, String, bool)> = collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| has_modifier(&modifiers_of(*method, source), "partial"))
        .filter_map(|method| {
            Some((
                method,
                partial_method_key(method, source)?,
                has_body_block(method),
            ))
        })
        .collect();
    let implemented: std::collections::HashSet<String> = partials
        .iter()
        .filter_map(|(_, key, has_body)| has_body.then_some(key.clone()))
        .collect();
    partials
        .into_iter()
        .filter(|(_, key, has_body)| !has_body && !implemented.contains(key))
        .map(|(method, _, _)| {
            let modifier = collect_kinds(method, &["modifier"])
                .into_iter()
                .find(|node| node_text(*node, source) == "partial")
                .unwrap_or(method);
            issue(
                language,
                "S3251",
                "Supply an implementation for this partial method.",
                range_of(modifier, source),
            )
        })
        .collect()
}

/// Namespace/type path plus method signature. Method names alone collide
/// across types and overloads and must never pair unrelated partial methods.
fn partial_method_key(method: Node<'_>, source: &str) -> Option<String> {
    let mut owners = ancestors_of(method)
        .filter(|ancestor| {
            matches!(
                ancestor.kind(),
                "class_declaration"
                    | "struct_declaration"
                    | "record_declaration"
                    | "interface_declaration"
                    | "namespace_declaration"
                    | "file_scoped_namespace_declaration"
            )
        })
        .filter_map(|owner| {
            let name = node_text(owner.child_by_field_name("name")?, source);
            let type_parameters = owner
                .child_by_field_name("type_parameters")
                .map_or("", |parameters| node_text(parameters, source));
            Some(format!("{name}{type_parameters}"))
        })
        .collect::<Vec<_>>();
    owners.reverse();

    let name = node_text(method.child_by_field_name("name")?, source);
    let return_type = method
        .child_by_field_name("returns")
        .or_else(|| method.child_by_field_name("type"))
        .map_or("", |node| node_text(node, source));
    let type_parameters = method
        .child_by_field_name("type_parameters")
        .map_or("", |node| node_text(node, source));
    let parameters = parameters_of(method)
        .into_iter()
        .map(|parameter| {
            let modifiers = modifiers_of(parameter, source).join(" ");
            let ty = parameter
                .child_by_field_name("type")
                .map_or("", |node| node_text(node, source));
            format!("{modifiers}:{ty}")
        })
        .collect::<Vec<_>>()
        .join(",");
    Some(format!(
        "{}::{return_type}:{name}{type_parameters}({parameters})",
        owners.join(".")
    ))
}

/// Whether a callable declares an implementation body (not just `;`).
fn has_body_block(callable: Node<'_>) -> bool {
    callable.child_by_field_name("body").is_some()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3251_same_method_name_in_another_type_does_not_pair() {
        let report = analyze_default(
            "partial class A { partial void Run(); }\npartial class B { partial void Run() { } }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3251").len(), 1);
    }

    #[test]
    fn s3251_different_overload_does_not_pair() {
        let report = analyze_default(
            "partial class A { partial void Run(int value); partial void Run(string value) { } }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3251").len(), 1);
    }

    #[test]
    fn s3251_matching_parts_across_type_declarations_pair() {
        let report = analyze_default(
            "partial class A { partial void Run(int first); }\npartial class A { partial void Run(int second) { } }",
        );
        assert!(with_key(&report, "csharpsquid:S3251").is_empty());
    }

    #[test]
    fn s3251_same_type_name_in_another_namespace_does_not_pair() {
        let report = analyze_default(
            "namespace One { partial class A { partial void Run(); } }\nnamespace Two { partial class A { partial void Run() { } } }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3251").len(), 1);
    }
}
