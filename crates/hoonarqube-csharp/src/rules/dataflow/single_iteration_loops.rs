use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::block_statements;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1751 — loops that provably run at most once: the final
/// body statement leaves the loop unconditionally. Entry-false
/// conditions belong to S2252; `do`-while run-once idioms are exempt.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["while_statement", "for_statement"]) {
        if is_error_tainted(header) {
            continue;
        }
        let Some(body) = header.child_by_field_name("body") else {
            continue;
        };
        if trailing_statement_exits(body) {
            issues.push(issue(
                language,
                "S1751",
                "This loop will execute at most once.",
                range_of(header, source),
            ));
        }
    }
    issues
}

/// Whether a loop body's final statement leaves the loop unconditionally.
fn trailing_statement_exits(body: Node<'_>) -> bool {
    let statements = if body.kind() == "block" {
        block_statements(body)
    } else {
        vec![body]
    };
    statements.last().is_some_and(|last| {
        matches!(
            last.kind(),
            "break_statement" | "return_statement" | "throw_statement"
        )
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S1751";

    #[test]
    fn s1751_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1751_trailing_break_makes_loop_single_shot() {
        let report = analyze_default(
            "class C {\n    void M() {\n        while (Ready()) {\n            Step();\n            break;\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s1751_trailing_return_flags_too() {
        let report = analyze_default(
            "class C {\n    void M() {\n        for (int i = 0; i < 9; i++) {\n            Tick(i);\n            return;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s1751_mid_body_break_with_trailing_work_is_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        while (Ready()) {\n            if (Done()) {\n                break;\n            }\n            Step();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1751_plain_loop_without_jumps_stays_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        while (Ready()) {\n            Step();\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1751_do_while_run_once_idiom_is_exempt() {
        let report = analyze_default(
            "class C {\n    void M() {\n        do {\n            Step();\n        } while (Ready());\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1751_two_single_shot_loops_flag_at_their_headers() {
        let report = analyze_default(
            "class C {\n    void M() {\n        while (Ready()) {\n            break;\n        }\n        for (int i = 0; i < 9; i++) {\n            return;\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].range.start.line, found[1].range.start.line);
    }
}
