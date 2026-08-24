use super::support::operator_declaration_for;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{declared_method_names, overloaded_operators};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4069 — operator overloads deserve named method equivalents.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let names = declared_method_names(type_node, source);
        for token in overloaded_operators(type_node) {
            let alternative = match OPERATOR_ALTERNATIVES
                .iter()
                .find(|(operator, _)| *operator == token)
            {
                Some((_, method)) => Some(*method),
                None => matches!(token, "<" | "<=" | ">" | ">=").then_some("CompareTo"),
            };
            if let Some(alternative) = alternative
                && !names.contains(alternative)
                && let Some(declaration) = operator_declaration_for(type_node, token)
            {
                issues.push(issue(
                    language,
                    "S4069",
                    format!("Provide a named '{alternative}' method alongside this operator."),
                    range_of(declaration),
                ));
            }
        }
    }
    issues
}

/// Named methods that serve as operator alternatives.
const OPERATOR_ALTERNATIVES: [(&str, &str); 4] = [
    ("+", "Add"),
    ("-", "Subtract"),
    ("*", "Multiply"),
    ("/", "Divide"),
];
