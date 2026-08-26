use super::support::constant_integer_value;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{binary_operands, operator_of};
use crate::rules::modifiers::has_ancestor_with_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3949 — arithmetic on folded operands that wraps around
/// `int` silently corrupts the result; `checked` blocks are exempt by
/// intent. Bound: both operands must fold to constants within `int`
/// range (`int.MinValue`/`int.MaxValue` included).
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression)
            || has_ancestor_with_kind(expression, &["checked_statement"])
        {
            continue;
        }
        let Some(operator) = operator_of(expression) else {
            continue;
        };
        if !matches!(operator, "+" | "-" | "*") {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let (Some(lhs), Some(rhs)) = (
            constant_integer_value(left, source),
            constant_integer_value(right, source),
        ) else {
            continue;
        };
        let Ok(lhs) = i32::try_from(lhs) else {
            continue;
        };
        let Ok(rhs) = i32::try_from(rhs) else {
            continue;
        };
        let wrapped = match operator {
            "+" => lhs.wrapping_add(rhs),
            "-" => lhs.wrapping_sub(rhs),
            _ => lhs.wrapping_mul(rhs),
        };
        let mathematical = match operator {
            "+" => i128::from(lhs) + i128::from(rhs),
            "-" => i128::from(lhs) - i128::from(rhs),
            _ => i128::from(lhs) * i128::from(rhs),
        };
        if i128::from(wrapped) != mathematical {
            issues.push(issue(
                language,
                "S3949",
                "This calculation overflows the range of 'int'; widen the operands or use a 'checked' block.",
                range_of(expression, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S3949";

    #[test]
    fn s3949_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s3949_max_value_plus_one_wraps() {
        let report =
            analyze_default("class C {\n    int M() {\n        return 2147483647 + 1;\n    }\n}\n");
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s3949_min_value_minus_one_wraps() {
        let report = analyze_default(
            "class C {\n    int M() {\n        return -2147483648 - 1;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s3949_boundary_values_that_do_not_wrap_stay_clean() {
        let report =
            analyze_default("class C {\n    int M() {\n        return 2147483647 + 0;\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s3949_checked_statement_is_exempt_by_intent() {
        // NOTE: only `checked { ... }` statements are exempt; the
        // `checked(...)` expression form parses differently and still
        // flags (impl subset, logged upstream).
        let report = analyze_default(
            "class C {\n    int M() {\n        checked {\n            return 2147483647 + 1;\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s3949_division_and_variables_are_out_of_scope() {
        let report = analyze_default(
            "class C {\n    int M(int scale) {\n        return -2147483648 / -1 + scale;\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s3949_multiplication_overflowing_int_flags() {
        let report =
            analyze_default("class C {\n    long M() {\n        return 65536 * 65536;\n    }\n}\n");
        assert_eq!(with_key(&report, KEY).len(), 1);
    }
}
