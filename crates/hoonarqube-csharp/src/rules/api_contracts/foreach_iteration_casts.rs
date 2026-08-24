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
                    range_of(cast),
                ));
            }
        }
    }
    issues
}
