use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::binary_operands;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3247 — a type check followed by the same cast should use a
/// declaration pattern.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for conditional in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(conditional) {
            continue;
        }
        let Some(condition) = conditional.child_by_field_name("condition") else {
            continue;
        };
        if condition.kind() != "is_expression" {
            continue;
        }
        let Some((checked, checked_type)) = binary_operands(condition) else {
            continue;
        };
        let Some(body) = conditional.child_by_field_name("consequence") else {
            continue;
        };
        let repeats_cast = collect_kinds(body, &["cast_expression"])
            .into_iter()
            .any(|cast| {
                cast_fields(cast, source).is_some_and(|(target_type, operand)| {
                    target_type == node_text(checked_type, source)
                        && operand == node_text(checked, source)
                })
            });
        if repeats_cast {
            issues.push(issue(
                language,
                "S3247",
                "Replace this type-check-and-cast sequence to use pattern matching.",
                range_of(condition, source),
            ));
        }
    }
    issues
}

/// Cast type and trimmed operand text of a `(T) x` expression.
fn cast_fields(cast: Node<'_>, source: &str) -> Option<(String, String)> {
    let target_type = cast
        .child_by_field_name("type")
        .map(|type_node| node_text(type_node, source).to_string())?;
    let operand = cast
        .child_by_field_name("value")
        .map(|value| node_text(value, source).trim().to_string())?;
    Some((target_type, operand))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3247_reports_type_check_followed_by_cast() {
        let report = analyze_default(
            "class A\n{\n    void M(object item)\n    {\n        if (item is string)\n        {\n            var a = (string)item;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3247");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3247_matches_cast_operand_whitespace() {
        let report = analyze_default(
            "class A\n{\n    void M(object item)\n    {\n        if (item is string)\n        {\n            var a = (string) item;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3247");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3247_single_cast_per_method_is_clean() {
        let report = analyze_default(
            "class A\n{\n    void M(object item)\n    {\n        var a = (Customer)item;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3247").is_empty());
    }
}
