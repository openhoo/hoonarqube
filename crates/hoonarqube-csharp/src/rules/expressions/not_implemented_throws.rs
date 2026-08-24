use super::support::creation_type_text;
use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3717 — thrown `NotImplementedException`s are tracked so
/// unfinished work stays visible.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for throw_statement in collect_kinds(root, &["throw_statement"]) {
        if is_error_tainted(throw_statement) {
            continue;
        }
        let tracked = first_named_child(throw_statement).is_some_and(|thrown| {
            thrown.kind() == "object_creation_expression"
                && simple_name(creation_type_text(thrown, source)) == "NotImplementedException"
        });
        if tracked {
            issues.push(issue(
                language,
                "S3717",
                "Track uses of 'NotImplementedException'.",
                range_of(throw_statement),
            ));
        }
    }
    issues
}
