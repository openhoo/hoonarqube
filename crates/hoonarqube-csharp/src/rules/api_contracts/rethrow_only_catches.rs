use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::block_statements;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2737 — a catch clause that only rethrows adds nothing.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| {
            clause.child_by_field_name("body").is_some_and(|body| {
                let statements = block_statements(body);
                statements.len() == 1 && statements[0].kind() == "throw_statement"
            })
        })
        .map(|clause| {
            issue(
                language,
                "S2737",
                "Handle this exception or remove this catch clause.",
                range_of(clause),
            )
        })
        .collect()
}
