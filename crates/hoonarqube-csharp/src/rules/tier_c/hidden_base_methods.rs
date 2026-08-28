use super::support::matched_method_pairs;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, parameters_of, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    matched_method_pairs(root, source, |modifiers| {
        !has_modifier(modifiers, "override") && !has_modifier(modifiers, "new")
    })
    .into_iter()
    .filter(|(hiding, _)| collect_kinds(*hiding, &["explicit_interface_specifier"]).is_empty())
    .filter_map(|(hiding, hidden)| {
        let name = hiding.child_by_field_name("name")?;
        let hidden_name = hidden.child_by_field_name("name")?;
        let owner = enclosing_type(hidden)?.child_by_field_name("name")?;
        let parameter_types = parameters_of(hidden)
            .into_iter()
            .filter_map(|parameter| parameter.child_by_field_name("type"))
            .map(|parameter_type| node_text(parameter_type, source))
            .collect::<Vec<_>>()
            .join(", ");
        Some((name, owner, hidden_name, parameter_types))
    })
    .map(|(name, owner, hidden_name, parameter_types)| {
        issue(
            language,
            "S4019",
            format!(
                "Remove or rename that method because it hides '{}.{}({parameter_types})'.",
                node_text(owner, source),
                node_text(hidden_name, source)
            ),
            range_of(name, source),
        )
    })
    .collect()
}
