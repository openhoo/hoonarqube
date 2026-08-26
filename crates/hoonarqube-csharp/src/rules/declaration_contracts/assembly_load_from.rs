use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::invocation_targets;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3885 — `LoadFrom`/`LoadWithPartialName` resolve assemblies
/// unpredictably; `Assembly.Load` binds by name.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            invocation_targets(
                *invocation,
                source,
                Some("Assembly"),
                &["LoadFrom", "LoadWithPartialName"],
            )
        })
        .map(|invocation| {
            issue(
                language,
                "S3885",
                "Prefer 'Assembly.Load' over this partial load.",
                range_of(invocation, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3885_flags_load_with_partial_name_too() {
        let report = analyze_default(
            "class Loader\n{\n    void Fetch(string name)\n    {\n        Assembly.LoadWithPartialName(name);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3885").len(), 1);
    }

    #[test]
    fn s3885_other_receivers_are_out_of_scope() {
        let report = analyze_default(
            "class Loader\n{\n    void Fetch(string path)\n    {\n        other.LoadFrom(path);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3885").is_empty());
    }
}
