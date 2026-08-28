use super::support::child_operator;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_from_byte_offsets};
use crate::rules::expressions::binary_operands;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3244 — a fresh anonymous delegate never equals the one that
/// subscribed, so the handler stays attached.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| child_operator(*assignment, source) == Some("-="))
        .filter(|assignment| {
            binary_operands(*assignment).is_some_and(|(_, value)| {
                matches!(
                    value.kind(),
                    "lambda_expression" | "anonymous_method_expression"
                )
            })
        })
        .map(|assignment| {
            let value = binary_operands(assignment).map_or(assignment, |(_, value)| value);
            let operator_start = source[assignment.start_byte()..value.start_byte()]
                .rfind("-=")
                .map_or(value.start_byte(), |offset| {
                    assignment.start_byte() + offset
                });
            issue(
                language,
                "S3244",
                "Unsubscribe with the same delegate that was used for the subscription.",
                range_from_byte_offsets(operator_start, value.end_byte(), source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3244_flags_delegate_literals_but_not_subscriptions() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        handler += () => { };\n        handler -= delegate { };\n        handler -= stored;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3244");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6); // document line 5
    }

    #[test]
    fn s3244_minimal_class_without_event_wiring_is_clean() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3244").is_empty());
    }
}
