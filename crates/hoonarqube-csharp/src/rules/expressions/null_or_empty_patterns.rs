use super::support::binary_operands;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::is_zero_literal;
use super::support::null_check_name;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3256 — compound null-and-empty checks collapse into
/// 'string.IsNullOrEmpty'.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || operator_of(expression) != Some("||") {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let collapsible = [
            (
                null_check_name(left, source),
                empty_check_name(right, source),
            ),
            (
                null_check_name(right, source),
                empty_check_name(left, source),
            ),
        ]
        .iter()
        .any(|(null_name, empty_name)| null_name.is_some() && *null_name == *empty_name);
        if collapsible {
            issues.push(issue(
                language,
                "S3256",
                "Replace this compound check with 'string.IsNullOrEmpty'.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// The identifier an empty-string test inspects, when the operand is one
/// (`s == ""`, `s == string.Empty`, and `s.Length == 0` shapes alike).
fn empty_check_name<'a>(comparison: Node<'_>, source: &'a str) -> Option<&'a str> {
    if !matches!(operator_of(comparison), Some("==")) {
        return None;
    }
    let (left, right) = binary_operands(comparison)?;
    for (tested, expected) in [(left, right), (right, left)] {
        let name = match tested.kind() {
            "identifier" => expression_name(tested, source),
            "member_access_expression" => {
                if expression_name(tested, source) == Some("Length") {
                    first_named_child(tested).and_then(|target| expression_name(target, source))
                } else {
                    None
                }
            }
            _ => continue,
        }?;
        let is_empty_test = match expected.kind() {
            "string_literal" => node_text(expected, source) == "\"\"",
            "member_access_expression" => expression_name(expected, source) == Some("Empty"),
            "integer_literal" => is_zero_literal(expected, source),
            _ => false,
        };
        if is_empty_test {
            return Some(name);
        }
    }
    None
}
