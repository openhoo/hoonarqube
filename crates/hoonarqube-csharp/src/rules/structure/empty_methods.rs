use super::support::body_of;
use super::support::is_attributed;
use super::support::name_anchor;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1186 — methods, constructors, and operators are not left
/// empty. Attributed members (framework hooks, externals, stubs under test
/// markers) stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["method_declaration", "operator_declaration"];
    let mut issues = Vec::new();
    for member in collect_kinds(root, &KINDS) {
        if is_error_tainted(member) || is_attributed(member, source) {
            continue;
        }
        let Some(body) = body_of(member) else {
            continue;
        };
        let mut cursor = body.walk();
        if body.children(&mut cursor).any(|child| child.is_named()) {
            continue;
        }
        let word = if member.kind() == "method_declaration" {
            "method"
        } else {
            "operator"
        };
        issues.push(issue(
            language,
            "S1186",
            format!("Add a nested comment explaining why this {word} is empty, throw a 'NotSupportedException' or complete the implementation."),
            range_of(name_anchor(member), source),
        ));
    }
    issues
}
