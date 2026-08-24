use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2551 — locking on `this`, a `typeof(...)` object, or a
/// string literal, exactly the canonical RSPEC shapes. Locking on arbitrary
/// expressions needs aliasing analysis and stays uncovered.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    /// The lock target between the parentheses; the `this` keyword is an
    /// anonymous token, so the raw child sequence is scanned.
    fn lock_target(statement: Node<'_>) -> Option<Node<'_>> {
        let mut cursor = statement.walk();
        let mut after_open = false;
        for child in statement.children(&mut cursor) {
            match child.kind() {
                "(" => after_open = true,
                ")" => return None,
                "this" | "typeof_expression" | "string_literal" if after_open => {
                    return Some(child);
                }
                _ => {}
            }
        }
        None
    }
    collect_kinds(root, &["lock_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(lock_target)
        .map(|target| {
            issue(
                language,
                "S2551",
                "Do not lock on 'this', a type object, or a string; use a dedicated private lock object.",
                range_of(target),
            )
        })
        .collect()
}
