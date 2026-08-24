use super::support::DISPOSABLE_TYPES;
use super::support::member_declared_type;
use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of,
    simple_name,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2931 — classes declaring disposable members without
/// implementing `IDisposable`. Subset: fields/properties typed by the
/// well-known disposable table (or `IDisposable` itself) on non-partial
/// classes whose base list lacks the interface textually; disposable bases
/// outside the file stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class| !is_error_tainted(*class))
        .filter(|class| !has_modifier(&modifiers_of(*class, source), "partial"))
        .filter(|class| {
            !base_simple_names(*class, source)
                .iter()
                .any(|name| *name == "IDisposable" || DISPOSABLE_TYPES.contains(name))
        })
        .filter(|class| {
            type_members(*class).into_iter().any(|member| {
                matches!(member.kind(), "field_declaration" | "property_declaration")
                    && member_declared_type(member).is_some_and(|type_node| {
                        let declared = simple_name(node_text(type_node, source));
                        declared == "IDisposable" || DISPOSABLE_TYPES.contains(&declared)
                    })
            })
        })
        .filter_map(|class| class.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S2931",
                "Implement 'IDisposable' on this class; it declares disposable members.",
                range_of(name),
            )
        })
        .collect()
}
