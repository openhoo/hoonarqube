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
