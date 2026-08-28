use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::expressions::expression_name;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3889 — suspended threads hold locks and never resume on
/// their own.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["member_access_expression"])
        .into_iter()
        .filter_map(|access| {
            let method = expression_name(access, source)?;
            matches!(method, "Suspend" | "Resume").then_some((access, method))
        })
        .map(|(access, method)| {
            let anchor = collect_kinds(access, &["identifier"])
                .into_iter()
                .last()
                .unwrap_or(access);
            issue(
                language,
                "S3889",
                format!("Refactor the code to remove this use of 'Thread.{method}'."),
                range_of(anchor, source),
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
    fn s3889_spares_other_members_but_tracks_thread_parameters() {
        let report = analyze_default(
            "class C\n{\n    void Run(Thread worker)\n    {\n        Thread.Sleep(1);\n        worker.Suspend();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3889").len(), 1);
    }
}
