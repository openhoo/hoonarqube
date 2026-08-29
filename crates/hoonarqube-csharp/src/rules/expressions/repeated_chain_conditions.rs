use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::{else_alternative, is_else_alternative};
use hoonarqube_ir::Issue;
use std::collections::HashMap;
use tree_sitter::Node;

/// csharpsquid:S1862 — a condition repeats along its if/else-if chain. Each
/// chain reports from its own first `if`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(header) || is_else_alternative(header) {
            continue;
        }
        let mut seen = HashMap::new();
        let mut current = Some(header);
        while let Some(if_statement) = current {
            if let Some(condition) =
                first_named_child(if_statement).filter(|condition| !is_error_tainted(*condition))
            {
                let text = node_text(condition, source);
                if let Some(first_line) = seen.get(text) {
                    issues.push(issue(
                        language,
                        "S1862",
                        format!("This branch duplicates the one on line {first_line}."),
                        range_of(condition, source),
                    ));
                } else {
                    seen.insert(text, condition.start_position().row + 1);
                }
            }
            current = else_alternative(if_statement)
                .filter(|alternative| alternative.kind() == "if_statement");
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1862_single_if_chain_has_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1862").is_empty());
    }

    #[test]
    fn s1862_flags_third_condition_repeating_chain_head() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        else if (x < 0) { Less(); }\n        else if (x > 0) { Repeat(); }\n        else { Rest(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1862");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s1862_each_chain_reports_its_own_repeat() {
        let report = analyze_default(
            "class A\n{\n    void M(int x, int y)\n    {\n        if (x > 0) { Work(); }\n        else if (x > 0) { More(); }\n\n        if (y < 3) { Run(); }\n        else if (y < 3) { Walk(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1862");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 9);
    }

    #[test]
    fn s1862_nested_duplicate_condition_is_separate_chain() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n        {\n            if (x > 0) { Work(); }\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1862").is_empty());
    }
}
