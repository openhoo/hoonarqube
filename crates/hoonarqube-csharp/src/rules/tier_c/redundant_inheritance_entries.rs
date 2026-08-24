use super::support::local_type_declarations;
use crate::CsLanguage;
use crate::cst::{base_simple_names, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1939 — inheritance lists repeating an entry or repeating the
/// declared type's own name.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    local_type_declarations(root)
        .into_iter()
        .filter(|declaration| !is_error_tainted(*declaration))
        .filter(|declaration| {
            let bases = base_simple_names(*declaration, source);
            let duplicated =
                (0..bases.len()).any(|index| bases[index + 1..].contains(&bases[index]));
            let self_named = declaration
                .child_by_field_name("name")
                .is_some_and(|name| bases.contains(&node_text(name, source)));
            duplicated || self_named
        })
        .map(|declaration| {
            issue(
                language,
                "S1939",
                "Remove the redundant entry from this inheritance list.",
                range_of(name_anchor(declaration)),
            )
        })
        .collect()
}
