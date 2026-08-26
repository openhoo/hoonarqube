use super::support::attribute_argument_texts;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4159 — an `[Export(typeof(I))]` part must actually
/// implement the exported contract `I`. Bound: same-file classes;
/// contracts declared elsewhere are assumed satisfied.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration) {
            continue;
        }
        for attribute in collect_kinds(class_declaration, &["attribute"]) {
            let exports = attribute
                .children(&mut attribute.walk())
                .find(tree_sitter::Node::is_named)
                .is_some_and(|name| node_text(name, source).ends_with("Export"));
            if !exports {
                continue;
            }
            let contract = attribute_argument_texts(attribute, source)
                .into_iter()
                .find_map(simple_name_of_typeof);
            let implemented = contract.as_ref().is_some_and(|contract| {
                base_simple_names(class_declaration, source).contains(&contract.as_str())
            });
            if let Some(contract) = contract
                && !implemented
            {
                issues.push(issue(
                    language,
                    "S4159",
                    format!("This class exports '{contract}' without implementing it."),
                    range_of(name_anchor(class_declaration), source),
                ));
            }
        }
    }
    issues
}

/// The contract type of a `typeof(T)` argument, if one is present.
fn simple_name_of_typeof(argument_text: &str) -> Option<String> {
    let trimmed = argument_text.trim();
    let inner = trimmed
        .strip_prefix("typeof(")
        .and_then(|rest| rest.strip_suffix(')'))?
        .trim();
    inner.rsplit('.').next().map(str::to_owned)
}
