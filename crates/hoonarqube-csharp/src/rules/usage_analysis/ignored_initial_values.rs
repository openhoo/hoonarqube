use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
};
use crate::rules::expressions::{binary_operands, operator_of};
use crate::rules::structure::{CALLABLE_BODY_OWNER_KINDS, body_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1226 — parameters and caught exceptions keep their initial
/// value only until something reads them.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for callable in collect_kinds(root, &CALLABLE_BODY_OWNER_KINDS) {
        check_callable(callable, source, language, &mut issues);
    }
    for catch_clause in collect_kinds(root, &["catch_clause"]) {
        if let Some((assignment, name)) = catch_offender(catch_clause, source) {
            push_issue(&mut issues, assignment, name, source, language);
        }
    }
    issues
}

fn check_callable(callable: Node<'_>, source: &str, language: CsLanguage, issues: &mut Vec<Issue>) {
    if is_error_tainted(callable) {
        return;
    }
    let Some(body) = body_of(callable) else {
        return;
    };
    for parameter in parameters_of(callable) {
        check_parameter(parameter, body, source, language, issues);
    }
}

fn check_parameter(
    parameter: Node<'_>,
    body: Node<'_>,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    if is_error_tainted(parameter)
        || modifiers_of(parameter, source)
            .iter()
            .any(|modifier| matches!(*modifier, "ref" | "out" | "in"))
    {
        return;
    }
    let Some(name_node) = parameter.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source);
    if let Some(assignment) = ignored_initial_value(body, name, source) {
        push_issue(issues, assignment, name, source, language);
    }
}

fn push_issue(
    issues: &mut Vec<Issue>,
    assignment: Node<'_>,
    name: &str,
    source: &str,
    language: CsLanguage,
) {
    let left = binary_operands(assignment).map_or(assignment, |(left, _)| left);
    issues.push(issue(
        language,
        "S1226",
        format!("Introduce a new variable instead of reusing the parameter '{name}'."),
        range_of(left, source),
    ));
}

/// The assignment overwriting `variable` before any read within `scope`.
fn ignored_initial_value<'t>(scope: Node<'t>, variable: &str, source: &str) -> Option<Node<'t>> {
    let mut references: Vec<Node> = collect_kinds(scope, &["identifier"])
        .into_iter()
        .filter(|candidate| {
            !is_error_tainted(*candidate) && node_text(*candidate, source) == variable
        })
        .collect();
    references.sort_by_key(|node| node.byte_range().start);
    let first = *references.first()?;
    let assignment = first
        .parent()
        .filter(|parent| parent.kind() == "assignment_expression")?;
    if operator_of(assignment) != Some("=") {
        return None;
    }
    let (left, right) = binary_operands(assignment)?;
    if left.id() != first.id()
        || collect_kinds(right, &["identifier"])
            .iter()
            .any(|identifier| node_text(*identifier, source) == variable)
    {
        return None;
    }
    Some(assignment)
}

/// `(assignment, variable)` overwriting a caught exception unread.
fn catch_offender<'a>(catch_clause: Node<'a>, source: &'a str) -> Option<(Node<'a>, &'a str)> {
    if is_error_tainted(catch_clause) {
        return None;
    }
    let declaration = collect_kinds(catch_clause, &["catch_declaration"])
        .into_iter()
        .next()?;
    let block = collect_kinds(catch_clause, &["block"]).into_iter().next()?;
    let name_node = declaration.child_by_field_name("name")?;
    let name = node_text(name_node, source);
    Some((ignored_initial_value(block, name, source)?, name))
}
