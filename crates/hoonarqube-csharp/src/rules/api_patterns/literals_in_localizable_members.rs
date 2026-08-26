use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{expression_name, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4055 — literals assigned to visible UI text cannot be
/// translated. Bound: string-literal stores into `Text`-family members
/// of types deriving a known UI base.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if !base_simple_names(class_declaration, source)
            .iter()
            .any(|base| UI_BASE_TYPES.contains(base))
        {
            continue;
        }
        for assignment in collect_kinds(class_declaration, &["assignment_expression"]) {
            if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
                continue;
            }
            let Some(right) = assignment.child_by_field_name("right") else {
                continue;
            };
            if right.kind() != "string_literal"
                || !LOCALIZABLE_TEXT_MEMBERS.contains(
                    &expression_name(
                        assignment.child_by_field_name("left").unwrap_or(right),
                        source,
                    )
                    .unwrap_or(""),
                )
            {
                continue;
            }
            issues.push(issue(
                language,
                "S4055",
                "Move this literal into a resource so it can be localized.",
                range_of(assignment, source),
            ));
        }
    }
    issues
}

/// UI-text property names whose values users can see.
const LOCALIZABLE_TEXT_MEMBERS: [&str; 6] =
    ["Text", "Caption", "Title", "Header", "Label", "ToolTip"];

/// Base types whose members render on screen.
const UI_BASE_TYPES: [&str; 5] = ["Form", "Control", "UserControl", "Page", "Window"];
