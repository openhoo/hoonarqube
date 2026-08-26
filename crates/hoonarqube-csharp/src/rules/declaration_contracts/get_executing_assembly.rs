use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3902 — `GetExecutingAssembly` couples code to its physical
/// assembly and breaks when moved.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Assembly", &["GetExecutingAssembly"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S3902",
                "Remove this 'GetExecutingAssembly' call.",
                range_of(access, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3902_flags_qualified_executing_assembly_reads() {
        let report = analyze_default(
            "class C\n{\n    void Who()\n    {\n        System.Reflection.Assembly.GetExecutingAssembly();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3902").len(), 1);
    }

    #[test]
    fn s3902_counts_every_occurrence() {
        let report = analyze_default(
            "class C\n{\n    void Who()\n    {\n        Assembly.GetExecutingAssembly();\n        Assembly.GetExecutingAssembly();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3902").len(), 2);
    }
}
