use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3256 — calls comparing strings to the empty string should use
/// `string.IsNullOrEmpty`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| {
            !is_error_tainted(*invocation) && callee_name(*invocation, source) == Some("Equals")
        })
        .filter(|invocation| {
            let arguments = invocation_arguments(*invocation);
            let Some(receiver) = invocation_receiver(*invocation) else {
                return false;
            };
            is_empty_string(receiver, source)
                || arguments
                    .first()
                    .is_some_and(|argument| is_empty_string(*argument, source))
        })
        .map(|invocation| {
            issue(
                language,
                "S3256",
                "Use 'string.IsNullOrEmpty()' instead of comparing to empty string.",
                range_of(invocation, source),
            )
        })
        .collect()
}

fn is_empty_string(expression: Node<'_>, source: &str) -> bool {
    matches!(
        node_text(expression, source),
        "\"\"" | "string.Empty" | "String.Empty"
    )
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3256_plain_method_has_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M(string name)\n    {\n        Keep(name);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3256").is_empty());
    }

    #[test]
    fn s3256_flags_equals_empty_string() {
        let report = analyze_default(
            "class A\n{\n    void M(string name)\n    {\n        var empty = name.Equals(\"\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3256");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3256_flags_empty_receiver_and_argument_shapes() {
        let report = analyze_default(
            "class A\n{\n    void M(string name, string other)\n    {\n        var a = \"\".Equals(name);\n        var b = other.Equals(\"\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3256");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s3256_nonempty_equals_stays_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(string left, string right)\n    {\n        var marked = right.Equals(\"x\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3256").is_empty());
    }

    #[test]
    fn s3256_string_empty_member_counts_as_empty() {
        let report = analyze_default(
            "class A\n{\n    void M(string name)\n    {\n        var empty = name.Equals(string.Empty);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3256").len(), 1);
    }
}
