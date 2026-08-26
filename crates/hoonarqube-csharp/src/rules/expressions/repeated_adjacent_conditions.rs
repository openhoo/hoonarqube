use super::support::block_statements;
use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2760 — adjacent if statements rechecking the same condition.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        let statements = block_statements(block);
        for pair in statements.windows(2) {
            let (first, second) = (pair[0], pair[1]);
            if first.kind() != "if_statement" || second.kind() != "if_statement" {
                continue;
            }
            let (Some(first_condition), Some(second_condition)) =
                (first_named_child(first), first_named_child(second))
            else {
                continue;
            };
            if !is_error_tainted(second_condition)
                && node_text(first_condition, source) == node_text(second_condition, source)
            {
                issues.push(issue(
                    language,
                    "S2760",
                    "This condition repeats the immediately preceding check.",
                    range_of(second_condition, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2760_minimal_class_has_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2760").is_empty());
    }

    #[test]
    fn s2760_flags_second_of_two_identical_adjacent_conditions() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        if (x > 0) { More(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2760");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s2760_intervening_statement_breaks_adjacency() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        Step();\n        if (x > 0) { More(); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2760").is_empty());
    }

    #[test]
    fn s2760_reports_every_repeat_in_a_run() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        if (x > 0) { More(); }\n        if (x > 0) { Extra(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2760");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 7);
    }
}
