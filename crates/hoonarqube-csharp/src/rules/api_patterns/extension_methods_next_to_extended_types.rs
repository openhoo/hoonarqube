use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4226 — extension methods living next to the extended
/// type couple every importer of that type to the extensions. Bound:
/// extended types declared in the same file count as "same namespace".
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let declared_types: std::collections::HashSet<String> =
        collect_kinds(root, &TYPE_DECLARATION_KINDS)
            .into_iter()
            .filter_map(|type_node| type_node.child_by_field_name("name"))
            .map(|name| node_text(name, source).to_owned())
            .collect();
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_this_modifier(method, source) || is_error_tainted(method) {
            continue;
        }
        let extends_declared = parameters_of(method)
            .first()
            .and_then(|first| first.child_by_field_name("type"))
            .is_some_and(|type_node| {
                declared_types.contains(simple_name(node_text(type_node, source)))
            });
        if extends_declared {
            issues.push(issue(
                language,
                "S4226",
                "Either move this extension to another namespace or move the method inside the class itself.",
                range_of(name_anchor(method), source),
            ));
        }
    }
    issues
}

/// Whether the method's first parameter carries the `this` modifier.
fn has_this_modifier(method: Node<'_>, source: &str) -> bool {
    parameters_of(method)
        .first()
        .is_some_and(|first| node_text(*first, source).trim_start().starts_with("this"))
}
