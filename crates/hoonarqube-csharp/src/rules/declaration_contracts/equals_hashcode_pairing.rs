use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{member_named, overridden_names};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1206 — overriding only one of `Equals`/`GetHashCode` breaks
/// hash-based collections.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let overrides = overridden_names(type_node, source);
        for lone in ["Equals", "GetHashCode"] {
            let partner = if lone == "Equals" {
                "GetHashCode"
            } else {
                "Equals"
            };
            if overrides.contains(lone)
                && !overrides.contains(partner)
                && let Some(method) = member_named(type_node, "method_declaration", lone, source)
            {
                issues.push(issue(
                    language,
                    "S1206",
                    format!("Override 'Equals' and 'GetHashCode' together; '{lone}' is alone."),
                    range_of(method),
                ));
            }
        }
    }
    issues
}
