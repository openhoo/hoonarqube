use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::invocation_arguments;
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3878 — arrays built just to feed a `params` call waste an
/// allocation.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .flat_map(|call| invocation_arguments(call))
        .filter(|argument| {
            matches!(
                argument_expression(*argument).kind(),
                "array_creation_expression" | "implicit_array_creation_expression"
            )
        })
        .map(|argument| {
            issue(
                language,
                "S3878",
                "Pass the elements individually to this 'params' call.",
                range_of(argument),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3878_ignores_arrays_outside_invocation_arguments() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        int[] keep = new int[] { 1, 2 };\n        Use(keep);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3878").is_empty());
    }

    #[test]
    fn s3878_flags_both_array_forms_in_one_call() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Use(new[] { \"a\" }, new string[] { \"b\" });\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3878").len(), 2);
    }
}
