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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2551_ignores_local_object_targets() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        object gate = new object();\n        lock (gate)\n        {\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2551").is_empty());
    }

    #[test]
    fn s2551_flags_nested_shared_targets_at_each_line() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        lock (this)\n        {\n            lock (\"inner\")\n            {\n            }\n        }\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2551");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 5);
        assert_eq!(found[1].range.start.line, 7);
    }

    #[test]
    fn s2551_flags_qualified_typeof_targets() {
        let report = analyze_default("lock (typeof(System.String))\n{\n}\n");
        let found = with_key(&report, "csharpsquid:S2551");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
    }

    #[test]
    fn s2551_ignores_interpolated_and_parenthesized_targets() {
        let report = analyze_default(
            "class C\n{\n    object gate = new object();\n    void M(string name)\n    {\n        lock ($\"gate{name}\")\n        {\n        }\n        lock ((gate))\n        {\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2551").is_empty());
    }
}
