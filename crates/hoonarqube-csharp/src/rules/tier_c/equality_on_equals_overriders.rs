use super::support::declared_type_names;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of, simple_name,
};
use crate::rules::expressions::{binary_operands, member_declarations_of_kind};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1698 — `==`/`!=` on operands typed to a file-local class that
/// overrides `Equals`, where reference identity almost certainly is not the
/// intended comparison. Subset: identifier operands resolved through the
/// file-local declaration table.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const EQUALITY_OPERATORS: [&str; 2] = ["==", "!="];
    let types = declared_type_names(root, source);
    let overriders = equals_overriding_class_names(root, source);
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|comparison| !is_error_tainted(*comparison))
        .filter(|comparison| EQUALITY_OPERATORS.contains(&binary_operator(*comparison, source)))
        .filter(|comparison| {
            binary_operands(*comparison).is_some_and(|(left, right)| {
                [left, right].iter().any(|operand| {
                    operand.kind() == "identifier"
                        && types
                            .get(node_text(*operand, source))
                            .is_some_and(|declared| overriders.contains(simple_name(declared)))
                })
            })
        })
        .map(|comparison| {
            issue(
                language,
                "S1698",
                "Use 'Equals' instead of '=='; this type overrides equality semantics.",
                range_of(comparison),
            )
        })
        .collect()
}

/// File-local classes declaring an `Equals` override.
fn equals_overriding_class_names<'a>(
    root: Node<'a>,
    source: &'a str,
) -> std::collections::HashSet<&'a str> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class| {
            member_declarations_of_kind(*class, "method_declaration")
                .into_iter()
                .any(|method| {
                    has_modifier(&modifiers_of(method, source), "override")
                        && method
                            .child_by_field_name("name")
                            .is_some_and(|name| node_text(name, source) == "Equals")
                })
        })
        .filter_map(|class| class.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect()
}
