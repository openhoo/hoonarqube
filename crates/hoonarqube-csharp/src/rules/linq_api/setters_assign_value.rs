use super::support::child_operator;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::binary_operands;
use crate::rules::structure::accessor_keyword;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3237 — setters exist to consume `value`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for accessor in collect_kinds(root, &["accessor_declaration"]) {
        if accessor_keyword(accessor, source) != "set" {
            continue;
        }
        let Some(body) = accessor.child_by_field_name("body") else {
            continue;
        };
        let ignores_value =
            collect_kinds(body, &["assignment_expression"])
                .iter()
                .any(|assignment| {
                    child_operator(*assignment, source) == Some("=")
                        && binary_operands(*assignment).is_some_and(|(target, value)| {
                            target.kind() == "identifier"
                                && node_text(target, source) != "value"
                                && value.kind() == "identifier"
                                && node_text(value, source) != "value"
                                && node_text(value, source) != node_text(target, source)
                        })
                });
        if ignores_value {
            issues.push(issue(
                language,
                "S3237",
                "Assign the 'value' keyword in this setter.",
                range_of(accessor),
            ));
        }
    }
    issues
}
