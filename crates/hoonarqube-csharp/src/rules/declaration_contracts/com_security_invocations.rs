use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::invocation_targets;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3884 — mutating process-wide COM security from managed code
/// corrupts the whole apartment.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const BANNED: [&str; 2] = ["CoSetProxyBlanket", "CoInitializeSecurity"];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| invocation_targets(*invocation, source, None, &BANNED))
        .map(|invocation| {
            issue(
                language,
                "S3884",
                "Do not mutate COM security settings here.",
                range_of(invocation, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3884_flags_co_initialize_security_too() {
        let report = analyze_default(
            "class C\n{\n    void Boot()\n    {\n        CoInitializeSecurity(IntPtr.Zero, -1, null, IntPtr.Zero, 0, 0, IntPtr.Zero, 0, 0);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3884").len(), 1);
    }

    #[test]
    fn s3884_unrelated_security_calls_stay_unflagged() {
        let report = analyze_default(
            "class C\n{\n    void Boot()\n    {\n        InitializeSecurity();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3884").is_empty());
    }
}
