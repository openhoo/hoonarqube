use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::declaration_contracts::enclosing_method;
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2302 — strings that mirror an enclosing parameter name
/// should travel through `nameof`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let inner = literal_inner_text(literal, source);
        if !is_identifier_text(inner) {
            continue;
        }
        let mirrors_parameter = enclosing_method(literal).is_some_and(|method| {
            parameters_of(method).iter().any(|parameter| {
                parameter
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == inner)
            })
        });
        if mirrors_parameter {
            issues.push(issue(
                language,
                "S2302",
                format!("Replace this string with 'nameof({inner})'."),
                range_of(literal),
            ));
        }
    }
    issues
}

/// Whether the text parses as a plain identifier usable with `nameof`.
fn is_identifier_text(text: &str) -> bool {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) if first.is_alphabetic() || first == '_' => {}
        _ => return false,
    }
    characters.all(|rest| rest.is_alphanumeric() || rest == '_')
}
