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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S3440";

    #[test]
    fn empty_body_and_declaration_first_window_stay_clean() {
        let empty = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&empty, KEY).is_empty());

        let declared = analyze_default(
            "class C {\n    void M() {\n        int limit = 10;\n        if (limit == 10) {\n            Mark();\n        }\n    }\n}\n",
        );
        assert!(with_key(&declared, KEY).is_empty());
    }

    #[test]
    fn side_effecting_value_breaks_the_window() {
        let report = analyze_default(
            "class C {\n    int Get() {\n        return 5;\n    }\n    void M() {\n        int x;\n        x = Get();\n        if (x == Get()) {\n            Mark();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn different_compared_value_does_not_fire() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int x;\n        x = 5;\n        if (x == 9) {\n            Mark();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn both_operand_orders_and_relational_operators_fire_distinctly() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int x;\n        x = 7;\n        if (7 < x) {\n            A();\n        }\n        int y;\n        y = 2;\n        while (y <= 2) {\n            B();\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found[0].range.start.line, 5);
        assert_eq!(found[1].range.start.line, 10);
    }

    #[test]
    fn intervening_write_displaces_the_comparison() {
        let report = analyze_default(
            "class C {\n    void M(int next) {\n        int x;\n        x = 5;\n        x = next;\n        if (x == 5) {\n            Mark();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn do_statement_condition_is_examined_too() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int n;\n        n = 1;\n        do {\n            Step();\n        } while (n != 1);\n        Step();\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found[0].range.start.line, 7);
    }
}
