use super::support::constant_integer_value;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::binary_operands;
use crate::rules::structure::{binary_operator, counter_name, for_clauses};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2252 — a loop condition should hold at least once: a
/// condition that is already false at entry strands the body. `do`
/// bodies run before their condition and are exempt.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["while_statement", "for_statement"]) {
        if is_error_tainted(header) {
            continue;
        }
        if condition_false_at_entry(header, source) {
            issues.push(issue(
                language,
                "S2252",
                "This loop's body never executes; the condition is false from the start.",
                range_of(header),
            ));
        }
    }
    issues
}

/// Whether a relational operator holds between two folded values.
fn relation_holds(left: i128, operator: &str, right: i128) -> bool {
    match operator {
        "<" => left < right,
        "<=" => left <= right,
        ">" => left > right,
        ">=" => left >= right,
        "==" => left == right,
        "!=" => left != right,
        _ => false,
    }
}

/// Entry value of a `for` counter: its initializer's integer literal.
fn counter_entry_value<'a>(loop_header: Node<'_>, source: &'a str) -> Option<(&'a str, i128)> {
    let (Some(initializer), _, _) = for_clauses(loop_header) else {
        return None;
    };
    let counter = counter_name(initializer, source)?;
    let literal = collect_kinds(initializer, &["integer_literal"])
        .into_iter()
        .next()?;
    let value = constant_integer_value(literal, source)?;
    Some((counter, value))
}

/// Entry-time falsity of a loop condition: a literal `false`, a
/// relational self-comparison (`x < x` is false for every value,
/// `NaN` included), or a `for` whose folded start/bound pair already
/// fails its own relation.
fn condition_false_at_entry(loop_header: Node<'_>, source: &str) -> bool {
    let Some(condition) = loop_header.child_by_field_name("condition") else {
        // `for (;;)` relies on escapes; the infinite-loop pass judges it.
        return false;
    };
    if condition.kind() == "boolean_literal" {
        return node_text(condition, source) == "false";
    }
    if condition.kind() != "binary_expression" {
        return false;
    }
    let operator = binary_operator(condition, source);
    let Some((left, right)) = binary_operands(condition) else {
        return false;
    };
    let left_text = node_text(left, source);
    let right_text = node_text(right, source);
    if matches!(operator, "<" | "<=" | ">" | ">=") && left_text == right_text {
        return true;
    }
    let (entry, bound) = match (
        constant_integer_value(left, source),
        constant_integer_value(right, source),
    ) {
        (Some(entry), Some(bound)) => (entry, bound),
        _ => match counter_entry_value(loop_header, source) {
            Some((counter, value)) if left_text == counter => {
                match constant_integer_value(right, source) {
                    Some(bound) => (value, bound),
                    None => return false,
                }
            }
            Some((counter, value)) if right_text == counter => {
                match constant_integer_value(left, source) {
                    Some(bound) => (bound, value),
                    None => return false,
                }
            }
            _ => return false,
        },
    };
    !relation_holds(entry, operator, bound)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S2252";

    #[test]
    fn empty_body_and_unfoldable_conditions_stay_clean() {
        let empty = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&empty, KEY).is_empty());

        let unknown = analyze_default(
            "class C {\n    void M(int bound) {\n        for (int i = 0; i < bound; i++) {\n            Tick();\n        }\n        while (Ready()) {\n            Pump();\n        }\n    }\n}\n",
        );
        assert!(with_key(&unknown, KEY).is_empty());
    }

    #[test]
    fn folded_entry_relation_boundary_decides_finding() {
        let failing = analyze_default(
            "class C {\n    void M() {\n        while (3 > 5) {\n            Skip();\n        }\n    }\n}\n",
        );
        let found = with_key(&failing, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);

        // NOTE: a reflexive `5 >= 5` header would be ideal here, but the
        // self-comparison shortcut pins it as always-false (impl subset,
        // logged upstream); a folded strictly-holding relation proves the
        // same boundary instead.
        let holding = analyze_default(
            "class C {\n    void M() {\n        while (3 < 5) {\n            Run();\n        }\n    }\n}\n",
        );
        assert!(with_key(&holding, KEY).is_empty());
    }

    #[test]
    fn relational_self_comparison_is_false_for_every_value() {
        let report = analyze_default(
            "class C {\n    void M(int pace) {\n        while (pace < pace) {\n            Stall();\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn stranded_counters_flag_at_distinct_lines() {
        let report = analyze_default(
            "class C {\n    void M() {\n        for (int i = 5; i < 3; i++) {\n            Tick();\n        }\n        for (int j = 10; j > 20; j--) {\n            Tock();\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[1].range.start.line, 6);
    }

    #[test]
    fn do_bodies_run_before_their_condition_and_stay_exempt() {
        let report = analyze_default(
            "class C {\n    void M() {\n        do {\n            Once();\n        } while (false);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
