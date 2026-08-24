use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text,
    parameters_of, range_of,
};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6424 — durable entity interface restrictions. Subset:
/// interfaces named `I…Entity` or deriving an `IDurableEntity…` interface
/// whose methods declare `ref`/`out` parameters; the remaining signature
/// restrictions (return shapes, generics) stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["interface_declaration"])
        .into_iter()
        .filter(|interface| !is_error_tainted(*interface))
        .filter(|interface| {
            let named_entity = interface.child_by_field_name("name").is_some_and(|name| {
                let text = node_text(name, source);
                text.starts_with('I') && text.ends_with("Entity")
            });
            named_entity
                || base_simple_names(*interface, source)
                    .iter()
                    .any(|base| base.starts_with("IDurableEntity"))
        })
        .flat_map(|interface| member_declarations_of_kind(interface, "method_declaration"))
        .filter(|method| {
            parameters_of(*method).iter().any(|parameter| {
                let modifiers = modifiers_of(*parameter, source);
                has_modifier(&modifiers, "ref") || has_modifier(&modifiers, "out")
            })
        })
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S6424",
                "Durable entity interface methods cannot use 'ref' or 'out' parameters.",
                range_of(name),
            )
        })
        .collect()
}
