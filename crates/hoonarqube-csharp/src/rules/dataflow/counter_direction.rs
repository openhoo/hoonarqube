use super::support::{constant_integer_value, unary_operator};
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
            let movement = match direction {
                CounterDirection::Increasing => "incremented",
                CounterDirection::Decreasing => "decremented",
            };
            issues.push(issue(
                language,
                "S2251",
                format!("'{counter}' is {movement} and will never reach 'stop condition'."),
                range_of(update, source),
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
        let direction = match node.kind() {
            "prefix_unary_expression" | "postfix_unary_expression" => {
                unary_update_direction(node, counter, source)
            }
            "assignment_expression" => assignment_update_direction(node, counter, source),
            _ => None,
        };
        if direction.is_some() {
            return direction;
        }
    }
    None
}

fn unary_update_direction(
    update: Node<'_>,
    counter: &str,
    source: &str,
) -> Option<CounterDirection> {
    let operand = first_named_child(update)?;
    if node_text(operand, source) != counter {
        return None;
    }
    match unary_operator(update) {
        Some("++") => Some(CounterDirection::Increasing),
        Some("--") => Some(CounterDirection::Decreasing),
        _ => None,
    }
}

fn assignment_update_direction(
    update: Node<'_>,
    counter: &str,
    source: &str,
) -> Option<CounterDirection> {
    let left = update.child_by_field_name("left")?;
    if node_text(left, source) != counter {
        return None;
    }
    let right = update.child_by_field_name("right")?;
    match operator_of(update) {
        Some("+=") => direction_from_delta(constant_integer_value(right, source)?),
        Some("-=") => direction_from_delta(-constant_integer_value(right, source)?),
        Some("=") if right.kind() == "binary_expression" => {
            binary_assignment_direction(right, counter, source)
        }
        _ => None,
    }
}

fn binary_assignment_direction(
    expression: Node<'_>,
    counter: &str,
    source: &str,
) -> Option<CounterDirection> {
    let (left, right) = binary_operands(expression)?;
    match binary_operator(expression, source) {
        "+" if node_text(left, source) == counter => {
            direction_from_delta(constant_integer_value(right, source)?)
        }
        "+" if node_text(right, source) == counter => {
            direction_from_delta(constant_integer_value(left, source)?)
        }
        "-" if node_text(left, source) == counter => {
            direction_from_delta(-constant_integer_value(right, source)?)
        }
        _ => None,
    }
}

fn direction_from_delta(delta: i128) -> Option<CounterDirection> {
    match delta.cmp(&0) {
        std::cmp::Ordering::Greater => Some(CounterDirection::Increasing),
        std::cmp::Ordering::Less => Some(CounterDirection::Decreasing),
        std::cmp::Ordering::Equal => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S2251";

    #[test]
    fn s2251_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2251_ascending_against_upper_bound_is_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        for (int i = 0; i < 9; i++) {\n            Tick(i);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2251_ascending_against_lower_bound_strands() {
        let report = analyze_default(
            "class C {\n    void M() {\n        for (int i = 0; i < 9; i--) {\n            Tick(i);\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s2251_descending_with_plus_equals_also_strands() {
        let report = analyze_default(
            "class C {\n    void M() {\n        for (int n = 9; n > 0; n += 2) {\n            Tick(n);\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s2251_signed_and_dynamic_steps_are_classified_conservatively() {
        let report = analyze_default(
            "class C {\n    void M(int step) {\n        for (int i = 9; i > 0; i += -2) {\n            Tick(i);\n        }\n        for (int j = 0; j < 9; j -= -2) {\n            Tock(j);\n        }\n        for (int k = 0; k < 9; k += step) {\n            Tock(k);\n        }\n        for (int n = 0; n < 9; n = 10 - n) {\n            Tock(n);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2251_condition_without_counter_is_out_of_scope() {
        let report = analyze_default(
            "class C {\n    void M(bool done) {\n        for (int i = 0; !done; i--) {\n            Tick(i);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2251_missing_update_clause_is_skipped() {
        let report = analyze_default(
            "class C {\n    void M() {\n        for (int i = 0; i < 9;) {\n            Tick(i);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2251_two_stranded_loops_at_distinct_lines() {
        let report = analyze_default(
            "class C {\n    void M() {\n        for (int i = 0; i < 4; i--) {\n            Tick(i);\n        }\n        for (int j = 4; j > 0; j++) {\n            Tock(j);\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].range.start.line, found[1].range.start.line);
    }
}
