use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::binary_operands;
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3449 — shift operators whose right operand is a literal that
/// can never be an integer. Subset: literal right operands (real/string/
/// bool/null); identifiers and computed operands need typing and stay out.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const SHIFT_OPERATORS: [&str; 3] = ["<<", ">>", ">>>"];
    const NON_INTEGER_LITERALS: [&str; 4] = [
        "real_literal",
        "string_literal",
        "boolean_literal",
        "null_literal",
    ];
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|shift| !is_error_tainted(*shift))
        .filter(|shift| SHIFT_OPERATORS.contains(&binary_operator(*shift, source)))
        .filter(|shift| {
            binary_operands(*shift)
                .is_some_and(|(_, right)| NON_INTEGER_LITERALS.contains(&right.kind()))
        })
        .map(|shift| {
            issue(
                language,
                "S3449",
                "Use an integer as the right operand of this shift.",
                range_of(shift),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3449_minimal_input_emits_nothing() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3449").is_empty());
    }

    #[test]
    fn s3449_flags_null_right_operand() {
        let report = analyze_default("var shifted = total >> null;\n");
        let flagged = with_key(&report, "csharpsquid:S3449");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s3449_boundary_integer_right_operands_are_not_flagged() {
        let report = analyze_default("var fine = 1 << 3;\nvar ok = amount << shift;\n");
        assert!(with_key(&report, "csharpsquid:S3449").is_empty());
    }

    #[test]
    fn s3449_non_integer_left_operand_is_not_flagged() {
        let report = analyze_default("var padded = 255 << 2;\n");
        assert!(with_key(&report, "csharpsquid:S3449").is_empty());
    }

    #[test]
    fn s3449_flags_two_shifts_on_distinct_lines() {
        let report = analyze_default("var a = page << \"index\";\nvar b = mask >> false;\n");
        let flagged = with_key(&report, "csharpsquid:S3449");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 2);
    }

    #[test]
    fn s3449_flags_unsigned_right_shift_with_boolean_literal() {
        let report = analyze_default("var u = value >>> true;\n");
        let flagged = with_key(&report, "csharpsquid:S3449");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }
}
