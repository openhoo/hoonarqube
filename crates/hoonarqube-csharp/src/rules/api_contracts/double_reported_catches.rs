use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::logging::logging_calls;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2139 — logging and rethrowing reports the failure twice.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter_map(|clause| {
            let body = clause.child_by_field_name("body")?;
            Some((
                clause,
                !logging_calls(body, source).is_empty(),
                !collect_kinds(body, &["throw_statement"]).is_empty(),
            ))
        })
        .filter(|(_, logs, rethrows)| *logs && *rethrows)
        .map(|(clause, _, _)| {
            issue(
                language,
                "S2139",
                "Choose either logging or rethrowing in this catch clause.",
                range_of(clause),
            )
        })
        .collect()
}
