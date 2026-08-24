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
                range_of(expression),
            ));
        }
    }
    issues
}
