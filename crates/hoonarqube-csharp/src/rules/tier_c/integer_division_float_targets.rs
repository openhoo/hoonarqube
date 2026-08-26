use super::support::FLOATING_TYPES;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::binary_operands;
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2184 — integer-literal divisions stored straight into
/// float/double/decimal declarations. Subset: declarations with literal
/// operands; assignments to previously declared variables and mixed-typed
/// divisions stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(root, &["variable_declaration"]) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(type_node) = declaration.child_by_field_name("type") else {
            continue;
        };
        let type_text = node_text(type_node, source);
        if type_text.contains('?') || !FLOATING_TYPES.contains(&simple_name(type_text)) {
            continue;
        }
        for declarator in collect_kinds(declaration, &["variable_declarator"]) {
            let mut cursor = declarator.walk();
            let Some(value) = declarator
                .children(&mut cursor)
                .find(|child| child.kind() == "binary_expression")
            else {
                continue;
            };
            if binary_operator(value, source) != "/" {
                continue;
            }
            let divides_integers = binary_operands(value).is_some_and(|(left, right)| {
                left.kind() == "integer_literal" && right.kind() == "integer_literal"
            });
            if !divides_integers {
                continue;
            }
            if let Some(name) = declarator.child_by_field_name("name") {
                issues.push(issue(
                    language,
                    "S2184",
                    "Assign this integer division to an integer target, or make one operand floating-point.",
                    range_of(name, source),
                ));
            }
        }
    }
    issues
}
