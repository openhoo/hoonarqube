use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::callee_name;
use crate::rules::linq_api::first_child_token_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2291 — `unchecked` around `Sum` silently truncates.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["checked_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter(|statement| first_child_token_text(*statement, source) == "unchecked")
        .filter(|statement| {
            collect_kinds(*statement, &["invocation_expression"])
                .into_iter()
                .any(|call| callee_name(call, source) == Some("Sum"))
        })
        .map(|statement| {
            issue(
                language,
                "S2291",
                "Do not disable overflow checks around 'Sum'.",
                range_of(statement),
            )
        })
        .collect()
}
