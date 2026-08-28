use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S907 — gotos destroy structured control flow.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["goto_statement"]) {
        let keyword = collect_kinds(statement, &["goto"])
            .into_iter()
            .next()
            .unwrap_or(statement);
        issues.push(issue(
            language,
            "S907",
            "Remove this use of 'goto'.",
            range_of(keyword, source),
        ));
    }
    issues
}
