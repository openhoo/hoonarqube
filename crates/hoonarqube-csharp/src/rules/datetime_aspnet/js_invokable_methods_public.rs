use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6798 — Blazor can only reach public methods through JS
/// interop.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| has_any_attribute(*method, source, &["JSInvokable"]))
        .filter(|method| !has_modifier(&modifiers_of(*method, source), "public"))
        .map(|method| {
            issue(
                language,
                "S6798",
                "Methods marked as 'JSInvokable' should be 'public'.",
                range_of(name_anchor(method), source),
            )
        })
        .collect()
}
