use super::support::override_base_pairs;
use crate::CsLanguage;
use crate::cst::{issue, node_text, parameters_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S927 — overrides renaming parameters relative to the base
/// declaration. Subset: proper (non-flattened) positional parameters on
/// direct file-local bases; cross-file partial declarations stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let parameter_name = |parameter: &Node<'_>| -> Option<&str> {
        parameter
            .child_by_field_name("name")
            .map(|name| node_text(name, source))
    };
    override_base_pairs(root, source)
        .into_iter()
        .filter_map(|(overriding, base)| {
            let overriding_parameters = parameters_of(overriding);
            let base_parameters = parameters_of(base);
            if overriding_parameters.len() != base_parameters.len() {
                return None;
            }
            for (index, base_parameter) in base_parameters.iter().enumerate() {
                match (
                    parameter_name(&overriding_parameters[index]),
                    parameter_name(base_parameter),
                ) {
                    (Some(derived), Some(base)) if derived != base => {
                        return overriding.child_by_field_name("name");
                    }
                    _ => {}
                }
            }
            None
        })
        .map(|name| {
            issue(
                language,
                "S927",
                "Rename this parameter to match the base declaration.",
                range_of(name),
            )
        })
        .collect()
}
