use super::support::unary_operator;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, first_named_child, operator_of};
use crate::rules::structure::{binary_operator, counter_name, for_clauses};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2251 — a `for` counter must move toward its bound:
/// ascending against `<`/`<=`, or descending against `>`/`>=`, strands
/// the loop.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let (initializer, condition, update) = for_clauses(for_statement);
        let (Some(initializer), Some(condition), Some(update)) = (initializer, condition, update)
        else {
            continue;
        };
        let Some(counter) = counter_name(initializer, source) else {
            continue;
        };
        let Some(direction) = update_direction(update, counter, source) else {
            continue;
        };
        let operator = binary_operator(condition, source);
        let references_counter = collect_kinds(condition, &["identifier"])
            .into_iter()
            .any(|identifier| node_text(identifier, source) == counter);
        let strands = references_counter
            && matches!(
                (operator, direction),
                ("<" | "<=", CounterDirection::Decreasing)
                    | (">" | ">=", CounterDirection::Increasing)
            );
        if strands {
            issues.push(issue(
                language,
                "S2251",
                format!("The counter '{counter}' moves away from this loop's bound."),
                range_of(for_statement),
            ));
        }
    }
    issues
}

/// Direction a `for` update clause drives its counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CounterDirection {
    Increasing,
    Decreasing,
}

/// Direction of the first counter movement in an update clause:
/// `++`/`--`, `+=`/`-=`, or a re-assignment folding the counter with a
/// signed literal step.
fn update_direction(update: Node<'_>, counter: &str, source: &str) -> Option<CounterDirection> {
    for node in collect_kinds(
        update,
        &[
            "prefix_unary_expression",
            "postfix_unary_expression",
            "assignment_expression",
        ],
    ) {
        match node.kind() {
            "prefix_unary_expression" | "postfix_unary_expression" => {
                let touches_counter = first_named_child(node)
                    .is_some_and(|operand| node_text(operand, source) == counter);
                if touches_counter {
                    return match unary_operator(node) {
                        Some("++") => Some(CounterDirection::Increasing),
                        Some("--") => Some(CounterDirection::Decreasing),
                        _ => None,
                    };
                }
            }
            "assignment_expression" => {
                let Some(left) = node.child_by_field_name("left") else {
                    continue;
                };
                if node_text(left, source) != counter {
                    continue;
                }
                match operator_of(node) {
                    Some("+=") => return Some(CounterDirection::Increasing),
                    Some("-=") => return Some(CounterDirection::Decreasing),
                    Some("=") => {
                        let Some(right) = node.child_by_field_name("right") else {
                            continue;
                        };
                        if right.kind() == "binary_expression" {
                            let step = match binary_operator(right, source) {
                                "+" => CounterDirection::Increasing,
                                "-" => CounterDirection::Decreasing,
                                _ => continue,
                            };
                            let (lhs, rhs) = binary_operands(right)?;
                            let counter_side = [lhs, rhs]
                                .into_iter()
                                .any(|operand| node_text(operand, source) == counter);
                            if counter_side {
                                return Some(step);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    None
}
