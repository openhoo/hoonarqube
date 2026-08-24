use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2583 — a condition that is literally `false` guards code
/// that can never run.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(
        root,
        &[
            "if_statement",
            "while_statement",
            "for_statement",
            "conditional_expression",
        ],
    ) {
        if is_error_tainted(header) {
            continue;
        }
        let Some(condition) = header.child_by_field_name("condition") else {
            continue;
        };
        if condition.kind() == "boolean_literal" && node_text(condition, source) == "false" {
            issues.push(issue(
                language,
                "S2583",
                "This condition is always false; the guarded code never runs.",
                range_of(condition),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S2583";

    #[test]
    fn empty_member_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn true_literal_and_runtime_condition_do_not_fire() {
        let report = analyze_default(
            "class C {\n    void M(bool ready) {\n        if (true) {\n            Run();\n        }\n        while (ready) {\n            Pump();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn conditional_expression_and_for_header_variants_fire() {
        let report = analyze_default(
            "class C {\n    int Pick() {\n        var choice = false ? 1 : 2;\n        return choice;\n    }\n    void Spin() {\n        for (; false; ) {\n            Turn();\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[1].range.start.line, 7);
    }

    #[test]
    fn do_while_false_is_out_of_scope_but_two_hits_stay_distinct() {
        let report = analyze_default(
            "class C {\n    void M() {\n        do {\n            Once();\n        } while (false);\n        if (false) {\n            Dead();\n        }\n        while (false) {\n            Never();\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].range.start.line, found[1].range.start.line);
    }
}
