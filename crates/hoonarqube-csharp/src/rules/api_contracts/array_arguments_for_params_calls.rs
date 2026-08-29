use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{invocation_arguments, invocation_function};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Canonical BCL members whose final parameter is `params`. A file-local
/// analyzer cannot resolve `params`-ness of user methods, so use qualified
/// spellings rather than treating every user method with the same short name
/// as a BCL call.
const PARAMS_CALLEES: &[&str] = &[
    "string.Format",
    "String.Format",
    "System.String.Format",
    "string.Concat",
    "String.Concat",
    "System.String.Concat",
    "string.Join",
    "String.Join",
    "System.String.Join",
    "Console.WriteLine",
    "System.Console.WriteLine",
];

/// csharpsquid:S3878 — arrays built just to feed a `params` call waste an
/// allocation.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            invocation_function(*call).is_some_and(|function| {
                let function_text = crate::cst::node_text(function, source);
                let name = function_text
                    .strip_prefix("global::")
                    .unwrap_or(function_text);
                PARAMS_CALLEES.contains(&name)
            })
        })
        .filter_map(|call| {
            let arguments = invocation_arguments(call);
            let argument = *arguments.last()?;
            matches!(
                argument_expression(argument).kind(),
                "array_creation_expression" | "implicit_array_creation_expression"
            )
            .then_some(argument)
        })
        .map(|argument| {
            issue(
                language,
                "S3878",
                "Remove this array creation and simply pass the elements.",
                range_of(argument, source),
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
    fn s3878_flags_trailing_arrays_of_known_params_calls() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"{0}{1}\", new[] { \"a\" }, new string[] { \"b\" });\n        joined = string.Join(\",\", new int[] { 3 });\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3878");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s3878_spares_non_trailing_arrays_and_unknown_callees() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(new string[] { \"a\" }, marker);\n        other = Use(new[] { 1, 2 });\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3878").is_empty());
    }

    #[test]
    fn s3878_spares_user_methods_named_like_bcl_params_methods() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        formatter.Format(new[] { 1, 2 });\n        WriteLine(new[] { 3, 4 });\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3878").is_empty());
    }

    #[test]
    fn s3878_accepts_qualified_bcl_type_spellings() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        System.String.Concat(new[] { \"a\", \"b\" });\n        global::System.Console.WriteLine(new object[] { 1 });\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3878").len(), 2);
    }
}
