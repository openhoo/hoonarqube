use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3005 — `ThreadStatic` only affects static fields; on an
/// instance field it silently does nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .filter(|field| {
            has_any_attribute(*field, source, &["ThreadStatic", "ThreadStaticAttribute"])
                && !has_modifier(&modifiers_of(*field, source), "static")
        })
        .filter_map(|field| {
            collect_kinds(field, &["attribute"])
                .into_iter()
                .find(|attribute| node_text(*attribute, source).starts_with("ThreadStatic"))
        })
        .map(|attribute| {
            issue(
                language,
                "S3005",
                "Remove the 'ThreadStatic' attribute from this definition.",
                range_of(attribute, source),
            )
        })
        .collect()
}
