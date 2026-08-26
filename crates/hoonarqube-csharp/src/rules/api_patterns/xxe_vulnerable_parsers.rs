use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{expression_name, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2755 — DTD-enabled XML parsers accept entity-expansion
/// and external-entity attacks.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        let enables_dtd = expression_name(left, source) == Some("DtdProcessing")
            && left.kind() == "member_access_expression"
            && expression_name(right, source) == Some("Parse");
        let allows_dtd = expression_name(left, source) == Some("ProhibitDtd")
            && right.kind() == "boolean_literal"
            && node_text(right, source) == "false";
        if enables_dtd || allows_dtd {
            issues.push(issue(
                language,
                "S2755",
                "Restrict this XML parser's DTD handling to prevent XXE attacks.",
                range_of(assignment, source),
            ));
        }
    }
    issues
}
