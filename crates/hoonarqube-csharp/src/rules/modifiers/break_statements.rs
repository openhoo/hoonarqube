use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1227 — loop exits should be expressed in the loop condition;
/// `break` remains appropriate for switch sections.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["break_statement"]) {
        let target = ancestors_of(statement).find(|ancestor| {
            matches!(
                ancestor.kind(),
                "switch_section"
                    | "for_statement"
                    | "foreach_statement"
                    | "while_statement"
                    | "do_statement"
            )
        });
        if target.is_some_and(|target| target.kind() != "switch_section") {
            issues.push(issue(
                language,
                "S1227",
                "Refactor the code in order to remove this break statement.",
                range_of(statement, source),
            ));
        }
    }
    issues
}
