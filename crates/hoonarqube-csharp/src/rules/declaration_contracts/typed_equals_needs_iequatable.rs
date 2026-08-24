use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text,
    parameters_of, range_of,
};
use crate::rules::expressions::{enclosing_type, first_named_child};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3897 — declaring a typed `Equals(T)` overload promises
/// `IEquatable<T>`; spell it out on the type.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || has_modifier(&modifiers_of(method, source), "override")
            || method
                .child_by_field_name("name")
                .is_none_or(|name| node_text(name, source) != "Equals")
        {
            continue;
        }
        let parameters = parameters_of(method);
        if parameters.len() != 1 {
            continue;
        }
        let parameter_type =
            first_named_child(parameters[0]).map_or("", |type_node| node_text(type_node, source));
        if parameter_type.is_empty() || parameter_type == "object" {
            continue;
        }
        let implements = enclosing_type(method).is_none_or(|type_node| {
            base_simple_names(type_node, source)
                .iter()
                .any(|base| base.starts_with("IEquatable"))
        });
        if !implements {
            issues.push(issue(
                language,
                "S3897",
                "Declare 'IEquatable<T>' on this type.",
                range_of(method),
            ));
        }
    }
    issues
}
