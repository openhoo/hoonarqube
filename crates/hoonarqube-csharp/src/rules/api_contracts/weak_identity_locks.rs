use super::support::lock_guard_expression;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["lock_statement"])
        .into_iter()
        .filter(|lock_statement| !is_error_tainted(*lock_statement))
        .filter(|lock_statement| {
            lock_guard_expression(*lock_statement).is_some_and(|expression| {
                matches!(
                    expression.kind(),
                    "this" | "string_literal" | "typeof_expression"
                )
            })
        })
        .map(|lock_statement| {
            issue(
                language,
                "S3998",
                "Lock on a dedicated private lock object.",
                range_of(lock_statement, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3998_flags_weak_locks_across_methods_but_spares_fields() {
        let report = analyze_default(
            "class A\n{\n    static readonly object gate = new();\n    readonly object padlock = new object();\n\n    void First()\n    {\n        lock (\"cache\") { }\n    }\n\n    void Second()\n    {\n        lock (this) { }\n        lock (gate) { }\n        lock (padlock) { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3998");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 8);
        assert_eq!(flagged[1].range.start.line, 13);
    }
}
