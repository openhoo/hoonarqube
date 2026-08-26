use super::support::declared_type_names;
use super::support::is_predefined_value_type_text;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::binary_operands;
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3610 — `==`/`!=` against `null` on operands whose declared
/// type text is a non-nullable value type. Subset: file-local declarations
/// only; values flowing through parameters of unanalyzed callers stay out.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const NULL_COMPARISONS: [&str; 2] = ["==", "!="];
    let types = declared_type_names(root, source);
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|comparison| !is_error_tainted(*comparison))
        .filter(|comparison| NULL_COMPARISONS.contains(&binary_operator(*comparison, source)))
        .filter_map(|comparison| {
            let (left, right) = binary_operands(comparison)?;
            match (
                left.kind() == "null_literal",
                right.kind() == "null_literal",
            ) {
                (true, false) => Some(right),
                (false, true) => Some(left),
                _ => None,
            }
        })
        .filter(|operand| {
            operand.kind() == "identifier"
                && types
                    .get(node_text(*operand, source))
                    .is_some_and(|declared| is_predefined_value_type_text(declared))
        })
        .map(|operand| {
            issue(
                language,
                "S3610",
                "Remove this redundant comparison; this non-nullable value can never be 'null'.",
                range_of(operand, source),
            )
        })
        .collect()
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
    fn s3610_flags_null_on_the_left_side() {
        let report = analyze_default(
            "void Check()\n{\n    long size = 0;\n    bool missing = null == size;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3610");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s3610_flags_other_value_types_on_distinct_lines() {
        let report = analyze_default(
            "void Check()\n{\n    double ratio = 1.0;\n    bool gone = ratio == null;\n    decimal total = 0m;\n    bool absent = total != null;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3610");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 4);
        assert_eq!(flagged[1].range.start.line, 6);
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
    fn s3610_non_nullable_parameter_comparison_is_flagged() {
        let report =
            analyze_default("void Check(int count)\n{\n    bool none = count == null;\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3610");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }
}
