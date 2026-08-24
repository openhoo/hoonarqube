use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, parameters_of, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4225 — extension methods on 'object' match everything and
/// hide real members.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter_map(|method| {
            let first = parameters_of(method).first().copied()?;
            Some((method, first))
        })
        .filter(|(_, first)| node_text(*first, source).trim_start().starts_with("this"))
        .filter_map(|(method, first)| {
            // Receiver type: the token between `this` and the parameter name.
            let text = node_text(first, source)
                .trim_start()
                .strip_prefix("this")?
                .trim();
            let type_name = simple_name(text.split_whitespace().next()?);
            (type_name == "object").then_some(method)
        })
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S4225",
                "Refactor this extension method on 'object' to extend a more specific type.",
                range_of(name_node),
            )
        })
        .collect()
}
