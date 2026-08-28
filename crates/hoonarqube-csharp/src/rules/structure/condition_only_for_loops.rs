use super::support::for_clauses;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1264 — a `for` with neither initializer nor update is a
/// `while`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let (initializer, _, update) = for_clauses(for_statement);
        if initializer.is_none() && update.is_none() {
            let keyword = collect_kinds(for_statement, &["for"])
                .into_iter()
                .next()
                .unwrap_or(for_statement);
            issues.push(issue(
                language,
                "S1264",
                "Replace this 'for' loop with a 'while' loop.",
                range_of(keyword, source),
            ));
        }
    }
    issues
}
