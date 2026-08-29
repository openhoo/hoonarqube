use super::support::counter_name;
use super::support::for_clauses;
use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, expression_name, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1994 — the increment clause drives the loop counter.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let (Some(initializer), Some(condition), update) = for_clauses(for_statement) else {
            continue;
        };
        let Some(counter) = counter_name(initializer, source) else {
            continue;
        };
        let condition_tests_counter = collect_kinds(condition, &["identifier"])
            .into_iter()
            .any(|identifier| node_text(identifier, source) == counter);
        if !condition_tests_counter {
            continue;
        }
        let modifies_counter = update.is_some_and(|_| {
            let mut cursor = for_statement.walk();
            for_statement
                .children_by_field_name("update", &mut cursor)
                .any(|clause| clause_modifies_counter(clause, counter, source))
        });
        if !modifies_counter {
            let detail = incrementer_subject(for_statement, counter, source).map_or_else(
                || "does not update it".to_string(),
                |subject| format!("updates '{subject}'"),
            );
            issues.push(issue(
                language,
                "S1994",
                format!(
                    "This loop's stop condition tests '{counter}' but the incrementer {detail}."
                ),
                range_of(condition, source),
            ));
        }
    }
    issues
}

fn incrementer_subject(for_statement: Node<'_>, counter: &str, source: &str) -> Option<String> {
    let mut cursor = for_statement.walk();
    let target = for_statement
        .children_by_field_name("update", &mut cursor)
        .find_map(|clause| update_target(clause, source))?;
    if target == counter {
        return None;
    }
    let is_field = ancestors_of(for_statement)
        .find(|ancestor| {
            matches!(
                ancestor.kind(),
                "class_declaration" | "struct_declaration" | "record_declaration"
            )
        })
        .is_some_and(|owner| {
            collect_kinds(owner, &["field_declaration"])
                .into_iter()
                .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
                .filter_map(|declarator| declarator.child_by_field_name("name"))
                .any(|name| node_text(name, source) == target)
        });
    Some(if is_field { "this" } else { target }.to_string())
}

fn update_target<'a>(clause: Node<'_>, source: &'a str) -> Option<&'a str> {
    if clause.kind() == "assignment_expression" {
        return binary_operands(clause).and_then(|(left, _)| expression_name(left, source));
    }
    if matches!(
        clause.kind(),
        "prefix_unary_expression" | "postfix_unary_expression"
    ) {
        return first_named_child(clause).and_then(|operand| expression_name(operand, source));
    }
    collect_kinds(
        clause,
        &[
            "assignment_expression",
            "prefix_unary_expression",
            "postfix_unary_expression",
        ],
    )
    .into_iter()
    .find_map(|expression| update_target(expression, source))
}

fn clause_modifies_counter(clause: Node<'_>, counter: &str, source: &str) -> bool {
    let assigned = collect_kinds(clause, &["assignment_expression"])
        .into_iter()
        .filter_map(|assignment| assignment.child_by_field_name("left"))
        .any(|left| left.kind() == "identifier" && node_text(left, source) == counter);
    assigned
        || collect_kinds(
            clause,
            &["prefix_unary_expression", "postfix_unary_expression"],
        )
        .into_iter()
        .any(|unary| {
            let text = node_text(unary, source).trim();
            let is_update = text.starts_with("++")
                || text.starts_with("--")
                || text.ends_with("++")
                || text.ends_with("--");
            is_update
                && unary.named_child_count() == 1
                && unary.named_child(0).is_some_and(|operand| {
                    operand.kind() == "identifier" && node_text(operand, source) == counter
                })
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1994_requires_mutation_not_merely_counter_reference() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        for (int i = 0; i < 10; Log(i)) { }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1994").len(), 1);
    }

    #[test]
    fn s1994_ignores_initializer_not_used_as_stop_counter() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        for (int i = 0; KeepGoing(); Tick()) { }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1994").is_empty());
    }

    #[test]
    fn s1994_checks_all_update_expressions() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        for (int i = 0, j = 0; i < 10; i++, j++) { }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1994").is_empty());
    }

    #[test]
    fn s1994_names_instance_field_updates_as_this() {
        let report = analyze_default(
            "class C { int ticks; void M() { for (int i = 0; i < 10; ticks++) { } } }",
        );
        let issues = with_key(&report, "csharpsquid:S1994");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "This loop's stop condition tests 'i' but the incrementer updates 'this'."
        );
    }
}
