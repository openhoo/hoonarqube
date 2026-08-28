use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    callee_name, expression_name, invocation_arguments, invocation_function, operator_of,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4055 — literals assigned to visible UI text cannot be
/// translated. Bound: string-literal stores into `Text`-family members
/// of types deriving a known UI base.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation)
            || !matches!(callee_name(invocation, source), Some("Write" | "WriteLine"))
            || !invocation_function(invocation)
                .is_some_and(|function| node_text(function, source).contains("Console."))
        {
            continue;
        }
        for argument in invocation_arguments(invocation) {
            if let Some(literal) = collect_kinds(argument, &["string_literal"])
                .into_iter()
                .next()
            {
                issues.push(issue(
                    language,
                    "S4055",
                    "Replace this string literal with a string retrieved through an instance of the 'ResourceManager' class.",
                    range_of(literal, source),
                ));
            }
        }
    }
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if right.kind() != "string_literal"
            || !expression_name(
                assignment.child_by_field_name("left").unwrap_or(right),
                source,
            )
            .is_some_and(|name| {
                LOCALIZABLE_TEXT_MEMBERS
                    .iter()
                    .any(|part| name.contains(part))
            })
        {
            continue;
        }
        issues.push(issue(
            language,
            "S4055",
            "Replace this string literal with a string retrieved through an instance of the 'ResourceManager' class.",
            range_of(right, source),
        ));
    }
    issues
}

/// UI-text property names whose values users can see.
const LOCALIZABLE_TEXT_MEMBERS: [&str; 3] = ["Text", "Message", "Caption"];
