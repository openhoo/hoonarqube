use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3217 — casting the iteration variable per body statement
/// means the sequence should be typed up front.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for each in collect_kinds(root, &["foreach_statement"]) {
        if is_error_tainted(each) {
            continue;
        }
        let Some(loop_variable) = each.child_by_field_name("left") else {
            continue;
        };
        let name = node_text(loop_variable, source);
        let Some(body) = each.child_by_field_name("body") else {
            continue;
        };
        for cast in collect_kinds(body, &["cast_expression"]) {
            let casts_variable = cast.child_by_field_name("value").is_some_and(|operand| {
                operand.kind() == "identifier" && node_text(operand, source) == name
            });
            if casts_variable {
                issues.push(issue(
                    language,
                    "S3217",
                    "Iterate with the correct element type instead of casting.",
                    range_of(cast, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3217_flags_casts_on_var_typed_iteration_variables() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        foreach (var row in rows)\n            Log(((string)row).Length);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3217").len(), 1);
    }

    #[test]
    fn s3217_casts_of_other_values_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        foreach (string raw in values)\n        {\n            Log(((string)other).Length);\n            Log(raw.Length);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3217").is_empty());
    }
}
