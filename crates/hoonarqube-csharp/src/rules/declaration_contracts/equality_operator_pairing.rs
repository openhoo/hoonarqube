use super::support::operator_declaration_for;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{overloaded_operators, overridden_names};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4050 — a `==` overload must come with `!=` and an `Equals`
/// override or equality semantics fall apart.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let operators = overloaded_operators(type_node);
        if operators.contains(&"==")
            && (!operators.contains(&"!=")
                || !overridden_names(type_node, source).contains("Equals"))
            && let Some(declaration) = operator_declaration_for(type_node, "==")
        {
            issues.push(issue(
                language,
                "S4050",
                "Pair this equality operator with '!=' and an 'Equals' override.",
                range_of(declaration),
            ));
        }
    }
    issues
}
