use super::support::dispose_methods;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2953 — a hand-rolled `Dispose` without `IDisposable` is
/// never called by `using`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_node| !is_error_tainted(*type_node))
        .filter(|type_node| !dispose_methods(*type_node, source).is_empty())
        .filter(|type_node| !base_simple_names(*type_node, source).contains(&"IDisposable"))
        .map(|type_node| {
            issue(
                language,
                "S2953",
                "Implement 'IDisposable' on this type.",
                range_of(name_anchor(type_node)),
            )
        })
        .collect()
}
