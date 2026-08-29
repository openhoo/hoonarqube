use super::support::comparisons;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::integer_literal_value;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3981 — collection sizes never compare against negatives.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn negative_value(operand: Node<'_>, source: &str) -> Option<i64> {
        if operand.kind() != "prefix_unary_expression" || operator_of(operand) != Some("-") {
            return None;
        }
        let literal = first_named_child(operand)?;
        integer_literal_value(node_text(literal, source))
            .and_then(|value| i64::try_from(value).ok())
            .map(|value| -value)
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let size_operand = [left, right].into_iter().find(|operand| {
            expression_name(*operand, source).is_some_and(|name| matches!(name, "Count" | "Length"))
        });
        let negative_side = [left, right]
            .iter()
            .any(|o| negative_value(*o, source).is_some());
        if let Some(size_operand) = size_operand.filter(|_| negative_side) {
            let size_member = expression_name(size_operand, source).unwrap_or("Count");
            let collection_type = collection_type(root, size_operand, size_member, source);
            issues.push(issue(
                language,
                "S3981",
                format!(
                    "The '{size_member}' of '{collection_type}' always evaluates as 'False' regardless the size."
                ),
                range_of(expression, source),
            ));
        }
    }
    issues
}

fn collection_type(
    root: Node<'_>,
    size_operand: Node<'_>,
    size_member: &str,
    source: &str,
) -> String {
    if size_member == "Length" {
        return "Array".to_string();
    }
    let receiver_name = size_operand
        .child_by_field_name("expression")
        .and_then(|receiver| expression_name(receiver, source));
    let declared = receiver_name.and_then(|name| declared_type(root, name, source));
    declared.map_or_else(
        || "ICollection".to_string(),
        |type_text| {
            let simple = simple_name(type_text);
            if type_text.contains('<') {
                format!("{simple}<T>")
            } else {
                simple.to_string()
            }
        },
    )
}

fn declared_type<'a>(root: Node<'_>, name: &str, source: &'a str) -> Option<&'a str> {
    collect_kinds(root, &["parameter", "variable_declaration"])
        .into_iter()
        .find(|declaration| {
            declaration
                .child_by_field_name("name")
                .is_some_and(|candidate| node_text(candidate, source) == name)
                || collect_kinds(*declaration, &["variable_declarator"])
                    .into_iter()
                    .any(|declarator| {
                        declarator
                            .child_by_field_name("name")
                            .is_some_and(|candidate| node_text(candidate, source) == name)
                    })
        })
        .and_then(|declaration| declaration.child_by_field_name("type"))
        .map(|type_node| node_text(type_node, source))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3981_non_negative_bounds_have_no_findings() {
        let report = analyze_default(
            "class A\n{\n    void M(int[] items)\n    {\n        var roomy = items.Length < 10;\n        var empty_ok = items.Length < 0;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3981").is_empty());
    }

    #[test]
    fn s3981_flags_each_count_against_negative_bound() {
        let report = analyze_default(
            "class A\n{\n    void M(System.Collections.Generic.List<int> list, int[] items)\n    {\n        var a = list.Count < -1;\n        var b = -2 >= items.Length;\n        var c = list.Count == -3;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3981");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
        assert_eq!(flagged[2].range.start.line, 7);
    }

    #[test]
    fn s3981_plain_variables_and_non_literal_negatives_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M(int size, int margin)\n    {\n        var plain = size < -1;\n        var symbolic = margin < -margin;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3981").is_empty());
    }
}
