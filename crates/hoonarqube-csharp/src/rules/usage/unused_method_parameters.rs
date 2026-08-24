use super::support::mentions_identifier_outside_parameter_list;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, parameters_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1172 — parameters no body ever reads mislead callers.
/// Visible, virtual, abstract, partial, and extern callables keep their
/// signatures; discard names (`_`) are exempt by convention.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration", "constructor_declaration"])
        .into_iter()
        .filter(|callable| {
            !modifiers_of(*callable, source)
                .iter()
                .any(|modifier| SIGNATURE_KEEPING_MODIFIERS.contains(modifier))
        })
        .flat_map(|callable| {
            parameters_of(callable)
                .into_iter()
                .map(move |parameter| (callable, parameter))
        })
        .filter_map(|(callable, parameter)| {
            let name = parameter.child_by_field_name("name")?;
            let text = node_text(name, source);
            (text != "_").then_some((callable, parameter, text))
        })
        .filter(|(callable, _, name)| {
            !mentions_identifier_outside_parameter_list(*callable, name, source)
        })
        .map(|(_, parameter, name)| {
            issue(
                language,
                "S1172",
                format!("Remove this unused method parameter '{name}'."),
                range_of(parameter),
            )
        })
        .collect()
}

/// Modifiers whose callables keep their signatures regardless of usage.
const SIGNATURE_KEEPING_MODIFIERS: [&str; 8] = [
    "public",
    "protected",
    "internal",
    "virtual",
    "override",
    "abstract",
    "partial",
    "extern",
];
