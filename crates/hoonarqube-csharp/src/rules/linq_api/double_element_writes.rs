use super::support::child_operator;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, block_statements, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4143 — consecutive writes to the same element leave the
/// first one dead.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        let statements = block_statements(block);
        for pair in statements.windows(2) {
            let (Some(first), Some(second)) = (
                element_write_target(pair[0], source),
                element_write_target(pair[1], source),
            ) else {
                continue;
            };
            if first == second {
                issues.push(issue(
                    language,
                    "S4143",
                    "Remove this write; it is overwritten by the next statement.",
                    range_of(pair[0]),
                ));
            }
        }
    }
    issues
}

/// The element-access target of an assignment statement (`arr[i] = v`),
/// keyed by its full target text.
fn element_write_target<'a>(statement: Node<'_>, source: &'a str) -> Option<&'a str> {
    let inner = first_named_child(statement)?;
    if inner.kind() != "assignment_expression" || child_operator(inner, source) != Some("=") {
        return None;
    }
    let (target, _) = binary_operands(inner)?;
    (target.kind() == "element_access_expression").then(|| node_text(target, source))
}
