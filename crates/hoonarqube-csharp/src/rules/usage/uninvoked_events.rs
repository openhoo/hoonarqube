use super::support::count_word_occurrences;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3264 — events nobody raises can never inform anybody.
/// Subscriptions alone do not raise; this in-file heuristic only certifies
/// events whose name appears nowhere beyond its declaration.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let declared: Vec<(Node<'_>, &str)> = collect_kinds(root, &["event_field_declaration"])
        .into_iter()
        .flat_map(|declaration| collect_kinds(declaration, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            Some((declarator, node_text(name, source)))
        })
        .collect();
    if declared.is_empty() {
        return Vec::new();
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (_, name) in &declared {
        *counts.entry(name).or_insert(0) += 1;
    }
    declared
        .into_iter()
        .filter(|(_, name)| count_word_occurrences(source, name) <= counts[name])
        .map(|(declarator, name)| {
            issue(
                language,
                "S3264",
                format!("Invoke the event '{name}' or remove it."),
                range_of(declarator),
            )
        })
        .collect()
}
