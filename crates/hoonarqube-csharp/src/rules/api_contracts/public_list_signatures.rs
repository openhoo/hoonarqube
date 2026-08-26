use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
};
use crate::rules::expressions::first_named_child;
use crate::rules::modifiers::has_modifier;
use crate::rules::security::return_type_text;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3956 — concrete `List<T>` leaks implementation details from
/// public signatures.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const LIST_MARKER: &str = "List<";
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "public") {
            continue;
        }
        let exposes_list = return_type_text(method, source).contains(LIST_MARKER)
            || parameters_of(method).iter().any(|parameter| {
                parameter
                    .child_by_field_name("type")
                    .is_some_and(|type_node| node_text(type_node, source).contains(LIST_MARKER))
            });
        if exposes_list {
            issues.push(issue(
                language,
                "S3956",
                "Expose 'IEnumerable<T>' or 'IList<T>' instead of 'List<T>'.",
                range_of(name_anchor(method), source),
            ));
        }
    }
    for member_kind in ["property_declaration", "field_declaration"] {
        for member in collect_kinds(root, &[member_kind]) {
            if is_error_tainted(member) || !has_modifier(&modifiers_of(member, source), "public") {
                continue;
            }
            let typed_list = match member.kind() {
                "property_declaration" => member
                    .child_by_field_name("type")
                    .is_some_and(|type_node| node_text(type_node, source).contains(LIST_MARKER)),
                _ => collect_kinds(member, &["variable_declaration"])
                    .iter()
                    .any(|declaration| {
                        first_named_child(*declaration).is_some_and(|type_node| {
                            node_text(type_node, source).contains(LIST_MARKER)
                        })
                    }),
            };
            if typed_list {
                issues.push(issue(
                    language,
                    "S3956",
                    "Expose 'IEnumerable<T>' or 'IList<T>' instead of 'List<T>'.",
                    range_of(member, source),
                ));
            }
        }
    }
    issues
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
}
