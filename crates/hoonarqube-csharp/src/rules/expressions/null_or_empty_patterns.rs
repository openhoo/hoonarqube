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
                range_of(expression, source),
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3256_plain_method_has_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M(string name)\n    {\n        Keep(name);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3256").is_empty());
    }

    #[test]
    fn s3256_flags_null_or_empty_disjunction() {
        let report = analyze_default(
            "class A\n{\n    void M(string name)\n    {\n        var empty = name == null || name == \"\";\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3256");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3256_flags_length_and_reversed_operand_shapes() {
        let report = analyze_default(
            "class A\n{\n    void M(string name, string other)\n    {\n        var a = name.Length == 0 || name == null;\n        var b = \"\" == other || null == other;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3256");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s3256_mismatched_names_conjunction_and_nonempty_literal_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(string left, string right)\n    {\n        var joined = left == null && right == \"\";\n        var split = left == null || right == \"\";\n        var marked = right == null || right == \"x\";\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3256").is_empty());
    }

    #[test]
    fn s3256_string_empty_member_counts_as_empty() {
        let report = analyze_default(
            "class A\n{\n    void M(string name)\n    {\n        var empty = name == null || name == string.Empty;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3256").len(), 1);
    }
}
