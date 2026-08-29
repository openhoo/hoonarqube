use crate::CsLanguage;
use crate::cst::{
    collect_kinds, containing_namespace, is_error_tainted, issue, modifiers_of, node_text,
    parameters_of, range_of, simple_name,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4226 — extension methods living next to the extended
/// type couple every importer of that type to the extensions.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let declared_types: Vec<(&str, String)> = collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter_map(|type_node| {
            let name = type_node.child_by_field_name("name")?;
            Some((
                simple_name(node_text(name, source)),
                containing_namespace(type_node, source),
            ))
        })
        .collect();
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let method_modifiers = modifiers_of(method, source);
        if !has_modifier(&method_modifiers, "static")
            || !has_this_modifier(method, source)
            || is_error_tainted(method)
        {
            continue;
        }
        let method_namespace = containing_namespace(method, source);
        let extends_declared = parameters_of(method)
            .first()
            .and_then(|first| first.child_by_field_name("type"))
            .is_some_and(|type_node| {
                let written = node_text(type_node, source)
                    .replace("global::", "")
                    .replace('@', "");
                let simple = simple_name(&written);
                declared_types.iter().any(|(name, namespace)| {
                    *name == simple
                        && *namespace == method_namespace
                        && (!written.contains('.')
                            || format!("{namespace}.{name}").trim_start_matches('.') == written)
                })
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
        .is_some_and(|first| has_modifier(&modifiers_of(*first, source), "this"))
}
