use super::support::collect_owned_kinds;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3440 — checking that a variable differs from a value only to
/// assign that same value makes the condition useless.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for conditional in collect_kinds(root, &["if_statement"]) {
        let Some(condition) = conditional.child_by_field_name("condition") else {
            continue;
        };
        if operator_of(condition) != Some("!=") {
            continue;
        }
        let Some((left, right)) = binary_operands(condition) else {
            continue;
        };
        let Some(body) = conditional.child_by_field_name("consequence") else {
            continue;
        };
        let repeats_assignment = collect_owned_kinds(body, &["assignment_expression"])
            .into_iter()
            .any(|assignment| {
                operator_of(assignment) == Some("=")
                    && binary_operands(assignment).is_some_and(|(target, value)| {
                        node_text(target, source) == node_text(left, source)
                            && node_text(value, source) == node_text(right, source)
                    })
            });
        if repeats_assignment {
            issues.push(issue(
                language,
                "S3440",
                "Remove this useless conditional.",
                range_of(condition, source),
            ));
        }
    }
    issues
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
    fn repeated_assignments_inside_inequality_guards_fire_distinctly() {
        let report = analyze_default(
            "class C {\n    void M(int x, int y) {\n        if (x != 7) {\n            x = 7;\n        }\n        if (y != 2) {\n            y = 2;\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[1].range.start.line, 6);
    }

    #[test]
    fn intervening_write_displaces_the_comparison() {
        let report = analyze_default(
            "class C {\n    void M(int next) {\n        int x;\n        x = 5;\n        x = next;\n        if (x == 5) {\n            Mark();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn equality_guard_is_not_reported() {
        let report = analyze_default(
            "class C {\n    void M(int n) {\n        if (n == 1) {\n            n = 1;\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn local_function_assignment_does_not_satisfy_outer_guard() {
        let report = analyze_default(
            "class C {\n    void M(int n) {\n        if (n != 1) {\n            void Local() { n = 1; }\n            Local();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
