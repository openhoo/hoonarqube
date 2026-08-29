use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
};
use crate::rules::expressions::first_named_child;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3956 — concrete `List<T>` leaks implementation details from
/// public signatures.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    check_public_methods(root, source, language, &mut issues);
    check_public_members(root, source, language, &mut issues);
    issues
}

const MESSAGE: &str = "use a generic collection designed for inheritance";

fn check_public_methods(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "public") {
            continue;
        }
        if let Some(return_type) = method
            .child_by_field_name("returns")
            .or_else(|| method.child_by_field_name("type"))
            .filter(|type_node| contains_list_type(*type_node, source))
        {
            push_issue(return_type, "method", source, language, issues);
        }
        for parameter_type in parameters_of(method)
            .iter()
            .filter_map(|parameter| parameter.child_by_field_name("type"))
            .filter(|type_node| contains_list_type(*type_node, source))
        {
            push_issue(parameter_type, "method", source, language, issues);
        }
    }
}

fn check_public_members(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    for member_kind in ["property_declaration", "field_declaration"] {
        for member in collect_kinds(root, &[member_kind]) {
            if is_error_tainted(member) || !has_modifier(&modifiers_of(member, source), "public") {
                continue;
            }
            if let Some(type_node) = exposed_list_type(member, source) {
                let surface = match member.kind() {
                    "property_declaration" => "property",
                    _ => "field",
                };
                push_issue(type_node, surface, source, language, issues);
            }
        }
    }
}

fn exposed_list_type<'tree>(member: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    match member.kind() {
        "property_declaration" => member.child_by_field_name("type"),
        _ => collect_kinds(member, &["variable_declaration"])
            .into_iter()
            .find_map(first_named_child),
    }
    .filter(|type_node| contains_list_type(*type_node, source))
}

fn contains_list_type(type_node: Node<'_>, source: &str) -> bool {
    collect_kinds(type_node, &["generic_name"])
        .into_iter()
        .any(|generic| {
            first_named_child(generic)
                .is_some_and(|identifier| node_text(identifier, source) == "List")
        })
}

fn push_issue(
    type_node: Node<'_>,
    surface: &str,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    issues.push(issue(
        language,
        "S3956",
        format!("Refactor this {surface} to {MESSAGE}."),
        range_of(type_node, source),
    ));
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3956_flags_public_list_properties_but_not_protected_surface() {
        let report = analyze_default(
            "class A\n{\n    public List<int> Items { get; set; }\n\n    protected List<int> Peek() => null;\n\n    internal List<int> Grab() => null;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3956");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3956_ignores_non_public_methods_and_locals() {
        let report = analyze_default(
            "class A\n{\n    int Total(List<int> xs)\n    {\n        List<int> copy = xs;\n        return copy.Count;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3956").is_empty());
    }

    #[test]
    fn s3956_matches_list_identifiers_not_substrings() {
        let report = analyze_default(
            "class A\n{\n    public MyList<int> Custom() => null;\n    public IList<int> Interface() => null;\n    public System.Collections.Generic.List < int > Concrete() => null;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3956");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }
}
