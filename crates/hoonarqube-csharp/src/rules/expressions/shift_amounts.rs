use super::support::binary_operands;
use super::support::integer_literal_value;
use super::support::operator_of;
use super::support::resolved_identifier_type;
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
        let out_of_range = match amount {
            0..=31 => false,
            32..=63 => operand_is_32_bit(left, source),
            64.. => true,
        };
        if out_of_range {
            let message = if amount == 32 {
                "Either promote shift target to a larger integer type or shift by less than 32 instead."
                    .to_owned()
            } else {
                format!("Correct this shift; '{amount}' is larger than the type size.")
            };
            issues.push(issue(
                language,
                "S2183",
                message,
                range_of(expression, source),
            ));
        }
    }
    issues
}

fn operand_is_32_bit(operand: Node<'_>, source: &str) -> bool {
    (operand.kind() == "integer_literal" && literal_is_32_bit(node_text(operand, source)))
        || (operand.kind() == "identifier"
            && resolved_identifier_type(operand, source).is_some_and(is_32_bit_type))
}

fn is_32_bit_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "int" | "uint" | "short" | "ushort" | "byte" | "sbyte"
    )
}

fn literal_is_32_bit(literal: &str) -> bool {
    !literal
        .chars()
        .any(|character| matches!(character, 'l' | 'L'))
        && integer_literal_value(literal).is_some_and(|value| u32::try_from(value).is_ok())
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
    fn s2183_wide_suffixed_literal_left_operand_stays_clean() {
        let report = analyze_default(
            "class C\n{\n    long M()\n    {\n        return 1L << 40;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2183").is_empty());
    }

    #[test]
    fn s2183_uint_literal_left_operand_is_32_bit() {
        let report = analyze_default("class C { uint M() => 1U << 32; }");
        assert_eq!(with_key(&report, "csharpsquid:S2183").len(), 1);
    }

    #[test]
    fn s2183_large_unsuffixed_literal_uses_wide_type() {
        let report = analyze_default("class C { long M() => 4294967296 << 32; }");
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

    #[test]
    fn s2183_does_not_leak_parameter_types_between_methods() {
        let report = analyze_default(
            "class C\n{\n    long Wide(long value) => value << 32;\n    int Narrow(int value) => value << 32;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2183");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s2183_uses_declarator_names_not_initializer_references() {
        let report = analyze_default(
            "class C { long M(long value) { int other = (int)value; return value << 32; } }",
        );
        assert!(with_key(&report, "csharpsquid:S2183").is_empty());
    }

    #[test]
    fn s2183_local_binding_wins_over_same_named_field() {
        let report = analyze_default(
            "class C { int value; long M() { long value = 1; return value << 32; } }",
        );
        assert!(with_key(&report, "csharpsquid:S2183").is_empty());
    }
}
