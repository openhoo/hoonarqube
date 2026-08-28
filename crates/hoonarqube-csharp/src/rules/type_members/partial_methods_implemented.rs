use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3251 — a `partial` method without any implementing part in
/// this file never runs. Partial types span files, so implementations living
/// elsewhere are out of reach for this analyzer.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let partials: Vec<(Node<'_>, &str, bool)> = collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| has_modifier(&modifiers_of(*method, source), "partial"))
        .filter_map(|method| {
            let name = node_text(method.child_by_field_name("name")?, source);
            Some((method, name, has_body_block(method)))
        })
        .collect();
    let mut implemented: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (_, name, has_body) in &partials {
        if *has_body {
            implemented.insert(name);
        }
    }
    partials
        .into_iter()
        .filter_map(move |(method, name, _)| {
            (!implemented.contains(name)).then_some((method, name))
        })
        .map(|(method, _name)| {
            let modifier = collect_kinds(method, &["modifier"])
                .into_iter()
                .find(|node| node_text(*node, source) == "partial")
                .unwrap_or(method);
            issue(
                language,
                "S3251",
                "Supply an implementation for this partial method.",
                range_of(modifier, source),
            )
        })
        .collect()
}

/// Whether a callable declares an implementation body (not just `;`).
fn has_body_block(callable: Node<'_>) -> bool {
    callable.child_by_field_name("body").is_some()
}
