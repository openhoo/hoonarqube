use super::support::local_type_declarations;
use super::support::local_type_table;
use crate::CsLanguage;
use crate::cst::{base_simple_names, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    matched_method_pairs(root, source, |modifiers| {
        !has_modifier(modifiers, "override") && !has_modifier(modifiers, "new")
    })
    .into_iter()
    .filter_map(|(hiding, _)| hiding.child_by_field_name("name"))
    .map(|name| {
        issue(
            language,
            "S4019",
            "Declare this method 'new' or rename it; it hides an inherited member.",
            range_of(name),
        )
    })
    .collect()
}

/// Same-name method pairs across a type's first file-local base, selected by
/// a predicate over the derived method's modifiers.
fn matched_method_pairs<'t>(
    root: Node<'t>,
    source: &'t str,
    select: impl Fn(&[&str]) -> bool,
) -> Vec<(Node<'t>, Node<'t>)> {
    let types = local_type_table(root, source);
    let mut pairs = Vec::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(base_name) = base_simple_names(declaration, source).first().copied() else {
            continue;
        };
        let Some(base) = types.get(base_name).copied() else {
            continue;
        };
        let base_methods: std::collections::HashMap<&str, Node<'t>> =
            member_declarations_of_kind(base, "method_declaration")
                .into_iter()
                .filter_map(|method| {
                    method
                        .child_by_field_name("name")
                        .map(|name| (node_text(name, source), method))
                })
                .collect();
        for method in member_declarations_of_kind(declaration, "method_declaration") {
            if !select(&modifiers_of(method, source)) {
                continue;
            }
            if let Some(name) = method.child_by_field_name("name")
                && let Some(base_method) = base_methods.get(node_text(name, source))
            {
                pairs.push((method, *base_method));
            }
        }
    }
    pairs
}
