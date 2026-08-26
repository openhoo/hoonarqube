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
                range_of(name_anchor(type_node), source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2953_flags_structs_with_hand_rolled_dispose() {
        let report = analyze_default("struct Bag\n{\n    public void Dispose() { }\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S2953").len(), 1);
    }

    #[test]
    fn s2953_interface_without_dispose_method_is_not_flagged() {
        let report = analyze_default("class Odd : IDisposable\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2953").is_empty());
    }
}
