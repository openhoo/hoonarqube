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
    const KINDS: [&str; 3] = [
        "method_declaration",
        "constructor_declaration",
        "operator_declaration",
    ];
    const KIND_WORDS: [(&str, &str); 3] = [
        ("method_declaration", "method"),
        ("constructor_declaration", "constructor"),
        ("operator_declaration", "operator"),
    ];
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
        let word = KIND_WORDS
            .iter()
            .find(|(kind, _)| *kind == member.kind())
            .map_or("member", |(_, word)| word);
        issues.push(issue(
            language,
            "S1186",
            format!("Remove this empty {word} or add its implementation."),
            range_of(name_anchor(member), source),
        ));
    }
    issues
}
