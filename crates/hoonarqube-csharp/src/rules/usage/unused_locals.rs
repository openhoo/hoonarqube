use super::support::count_word_occurrences;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1481 — local variables nobody reads are noise. Discard
/// declarations (`_`) are exempt by convention.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["local_declaration_statement"])
        .into_iter()
        .filter(|statement| !has_modifier(&modifiers_of(*statement, source), "const"))
        .flat_map(|statement| collect_kinds(statement, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let text = node_text(name, source);
            (text != "_").then_some((declarator, text))
        })
        .filter(|(_, text)| count_word_occurrences(source, text) <= 1)
        .map(|(declarator, _)| {
            issue(
                language,
                "S1481",
                "Remove this unused local variable.",
                range_of(declarator),
            )
        })
        .collect()
}
