use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3869 — raw handle leaks defeat `SafeHandle`'s release safety.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "SafeHandle", &["DangerousGetHandle"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S3869",
                "Remove this 'DangerousGetHandle' call.",
                range_of(access),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};
    #[test]
    fn s3869_counts_every_dangerous_handle_read() {
        let report = analyze_default(
            "class C\n{\n    void Leak(SafeHandle firstHandle, SafeHandle secondSafeHandle)\n    {\n        Use(firstSafeHandle.DangerousGetHandle());\n        Use(secondSafeHandle.DangerousGetHandle());\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3869").len(), 2);
    }
}
