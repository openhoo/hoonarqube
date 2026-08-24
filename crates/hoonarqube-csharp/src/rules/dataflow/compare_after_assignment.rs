use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::{
    binary_operands, block_statements, first_named_child, operator_of,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3440 — comparing a variable with the very value it just
/// received cannot vary. Bound: consecutive statements within one block;
/// the assigned expression must be side-effect free so its two textual
/// appearances denote one value.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const CONDITION_KINDS: [&str; 4] = [
        "if_statement",
        "while_statement",
        "do_statement",
        "switch_statement",
    ];
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        let statements = block_statements(block);
        for window in statements.windows(2) {
            let (first, second) = (window[0], window[1]);
            if first.kind() != "expression_statement" || !CONDITION_KINDS.contains(&second.kind()) {
                continue;
            }
            let Some(assignment) = first_named_child(first) else {
                continue;
            };
            if assignment.kind() != "assignment_expression" || operator_of(assignment) != Some("=")
            {
                continue;
            }
            let Some((target, value)) = binary_operands(assignment) else {
                continue;
            };
            if target.kind() != "identifier" || !side_effect_free(value) {
                continue;
            }
            let target_name = node_text(target, source);
            let value_text = node_text(value, source);
            let condition = second
                .child_by_field_name("condition")
                .or_else(|| second.child_by_field_name("value"));
            let Some(condition) = condition else { continue };
            for comparison in collect_kinds(condition, &["binary_expression"]) {
                let matches_pair = binary_operands(comparison).is_some_and(|(left, right)| {
                    (node_text(left, source) == target_name
                        && node_text(right, source) == value_text)
                        || (node_text(left, source) == value_text
                            && node_text(right, source) == target_name)
                });
                if matches_pair
                    && matches!(
                        operator_of(comparison),
                        Some("==" | "!=" | "<" | "<=" | ">" | ">=")
                    )
                {
                    issues.push(issue(
                        language,
                        "S3440",
                        format!("'{target_name}' was just assigned this exact value; this comparison cannot vary."),
                        range_of(comparison),
                    ));
                }
            }
        }
    }
    issues
}

/// Whether an expression computes a value without observable effects.
fn side_effect_free(expression: Node<'_>) -> bool {
    collect_kinds(
        expression,
        &[
            "invocation_expression",
            "object_creation_expression",
            "assignment_expression",
            "prefix_unary_expression",
            "postfix_unary_expression",
            "await_expression",
        ],
    )
    .is_empty()
}
