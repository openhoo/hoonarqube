use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{invocation_arguments, invocation_targets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2970 — a constraint-less `Assert.That` asserts nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| invocation_targets(*call, source, Some("Assert"), &["That"]))
        .filter(|call| invocation_arguments(*call).len() == 1)
        .map(|call| {
            issue(
                language,
                "S2970",
                "Complete this 'Assert.That' with a constraint.",
                range_of(call),
            )
        })
        .collect()
}
