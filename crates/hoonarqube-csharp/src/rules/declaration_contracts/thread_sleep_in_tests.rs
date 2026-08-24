use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::expressions::{invocation_targets, is_test_attributed};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2925 — sleeping in tests slows suites and hides races.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !is_test_attributed(method, source) {
            continue;
        }
        for invocation in collect_kinds(method, &["invocation_expression"]) {
            if invocation_targets(invocation, source, Some("Thread"), &["Sleep"]) {
                issues.push(issue(
                    language,
                    "S2925",
                    "Remove this 'Thread.Sleep' from the test.",
                    range_of(invocation),
                ));
            }
        }
    }
    issues
}
