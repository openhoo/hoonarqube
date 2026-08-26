use super::support::binary_operands;
use super::support::integer_literal_value;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2183 — shift amounts must fit the operand width; shifts of
/// unknown-width operands above 31 stay unreported.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression)
            || !matches!(operator_of(expression), Some("<<" | ">>" | ">>>"))
        {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        if right.kind() != "integer_literal" {
            continue;
        }
        let Some(amount) = integer_literal_value(node_text(right, source)) else {
            continue;
        };
        // Hexadecimal and binary spellings never contain `l`/`u`, so this
        // suffix probe cannot misread their digits.
        let left_is_32bit_literal = left.kind() == "integer_literal"
            && !node_text(left, source)
                .chars()
                .any(|character| matches!(character, 'l' | 'L' | 'u' | 'U'));
        let out_of_range = match amount {
            // 0 is always out of range; so is anything >= 64 (no wider primitive).
            1..=31 => false,
            32..=63 => left_is_32bit_literal,
            _ => true,
        };
        if out_of_range {
            issues.push(issue(
                language,
                "S2183",
                format!(
                    "Shift by a non-zero amount below the operand width ({amount} is out of range)."
                ),
                range_of(expression),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2183_flags_binary_shift_counts_like_decimal() {
        let report = analyze_default(
            "class C\n{\n    int M(int z)\n    {\n        int a = 1 << 0b100000;\n        int b = 2 >> 32;\n        int c = z << 4;\n        return a + b + c;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2183");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2183_wide_operand_shift_by_32_stays_clean() {
        let report = analyze_default(
            "class C\n{\n    ulong M(ulong value)\n    {\n        return value << 32;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2183").is_empty());
    }

    #[test]
    fn s2183_suffixed_literal_left_operand_stays_unknown() {
        let report = analyze_default(
            "class C\n{\n    long M()\n    {\n        return 1L << 40;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2183").is_empty());
    }

    #[test]
    fn s2183_shift_beyond_all_primitive_widths_flags() {
        let report = analyze_default(
            "class C\n{\n    ulong M(ulong value)\n    {\n        return value << 70;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2183");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2183_unsuffixed_literal_left_operand_flags_in_long_range() {
        let report =
            analyze_default("class C\n{\n    int M()\n    {\n        return 1 << 40;\n    }\n}\n");
        let flagged = with_key(&report, "csharpsquid:S2183");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }
}
