use super::support::child_operator;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, block_statements, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4143 — consecutive writes to the same element leave the
/// first one dead.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        let statements = block_statements(block);
        for pair in statements.windows(2) {
            let (Some(first), Some(second)) = (
                element_write_target(pair[0], source),
                element_write_target(pair[1], source),
            ) else {
                continue;
            };
            if first == second {
                issues.push(issue(
                    language,
                    "S4143",
                    "Verify this is the index/key that was intended; a value has already been set for it.",
                    range_of(pair[1], source),
                ));
            }
        }
    }
    issues
}

/// The element-access target of an assignment statement (`arr[i] = v`),
/// keyed by its full target text.
fn element_write_target<'a>(statement: Node<'_>, source: &'a str) -> Option<&'a str> {
    let inner = first_named_child(statement)?;
    if inner.kind() != "assignment_expression" || child_operator(inner, source) != Some("=") {
        return None;
    }
    let (target, _) = binary_operands(inner)?;
    (target.kind() == "element_access_expression").then(|| node_text(target, source))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4143_reports_each_dead_write_in_a_run() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        data[0] = 1;\n        data[0] = 2;\n        data[0] = 3;\n        Log();\n        data[0] = 4;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4143");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s4143_matches_multi_dimensional_element_targets() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        grid[0, 1] = 1;\n        grid[0, 1] = 2;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4143");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s4143_minimal_block_without_element_writes_is_clean() {
        let report =
            analyze_default("class A\n{\n    void M()\n    {\n        data[0] = 1;\n    }\n}\n");
        assert!(with_key(&report, "csharpsquid:S4143").is_empty());
    }
}
