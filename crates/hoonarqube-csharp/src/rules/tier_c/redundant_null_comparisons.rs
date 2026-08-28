use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, callee_name};
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3610 — `Nullable<T>.GetType()` never yields
/// `typeof(Nullable<T>)`, making that type comparison redundant.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|comparison| !is_error_tainted(*comparison))
        .filter(|comparison| matches!(binary_operator(*comparison, source), "==" | "!="))
        .filter(|comparison| {
            binary_operands(*comparison).is_some_and(|(left, right)| {
                (is_get_type_call(left, source) && is_nullable_typeof(right, source))
                    || (is_get_type_call(right, source) && is_nullable_typeof(left, source))
            })
        })
        .map(|comparison| {
            issue(
                language,
                "S3610",
                "Remove this redundant type comparison.",
                range_of(comparison, source),
            )
        })
        .collect()
}

fn is_get_type_call(node: Node<'_>, source: &str) -> bool {
    node.kind() == "invocation_expression" && callee_name(node, source) == Some("GetType")
}

fn is_nullable_typeof(node: Node<'_>, source: &str) -> bool {
    node.kind() == "typeof_expression"
        && (node_text(node, source).contains('?') || node_text(node, source).contains("Nullable<"))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3610_minimal_input_emits_nothing() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3610").is_empty());
    }

    #[test]
    fn s3610_flags_nullable_get_type_comparison() {
        let report = analyze_default(
            "void Check(int? value)\n{\n    bool same = value.GetType() == typeof(int?);\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3610");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3610_flags_equal_and_unequal_nullable_type_checks() {
        let report = analyze_default(
            "void Check(decimal? amount)\n{\n    bool same = amount.GetType() == typeof(decimal?);\n    bool different = amount.GetType() != typeof(decimal?);\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3610");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 4);
    }

    #[test]
    fn s3610_comparison_between_values_is_not_flagged() {
        let report = analyze_default(
            "void Check()\n{\n    int left = 1;\n    int right = 2;\n    bool equal = left == right;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3610").is_empty());
    }

    #[test]
    fn s3610_nullable_value_type_comparison_stays_clean() {
        let report = analyze_default(
            "void Check()\n{\n    decimal? amount = null;\n    bool empty = amount == null;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3610").is_empty());
    }

    #[test]
    fn s3610_non_nullable_parameter_comparison_is_clean() {
        let report =
            analyze_default("void Check(int count)\n{\n    bool none = count == null;\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3610");
        assert!(flagged.is_empty());
    }
}
