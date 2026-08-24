use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3889 — suspended threads hold locks and never resume on
/// their own.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Thread", &["Suspend", "Resume"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S3889",
                "Do not suspend or resume threads.",
                range_of(access),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3889_flags_suspend_and_resume_accesses() {
        let report = analyze_default(
            "class C\n{\n    void Freeze()\n    {\n        Thread.CurrentThread.Suspend();\n        Thread.CurrentThread.Resume();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3889").len(), 2);
    }

    #[test]
    fn s3889_spares_other_members_and_lowercase_receivers() {
        let report = analyze_default(
            "class C\n{\n    void Run(Thread worker)\n    {\n        Thread.Sleep(1);\n        worker.Suspend();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3889").is_empty());
    }
}
