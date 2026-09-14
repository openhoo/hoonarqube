use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtFor};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::support::child_bodies;
use crate::support::flow_location;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8510";
const MESSAGE_TEMPLATE: &str = "Rename this loop variable; it shadows the outer loop variable";
const FLOW_MESSAGE: &str = "Outer loop variable is declared here.";

/// python:S8510 — a nested for-loop reusing an enclosing for-loop's
/// variable name shadows that binding: reading the outer variable in the
/// inner body observes the inner iteration instead. The inner target
/// anchors the finding and the shadowed outer target is the flow.
/// Functions and classes start fresh scopes; comprehensions and
/// generator expressions have scopes of their own and are not loops.
pub(crate) fn check_s8510_loop_variable_shadows_outer(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut outer = Vec::new();
    walk_s8510(
        parsed.syntax().body.as_slice(),
        &mut outer,
        index,
        source,
        &mut issues,
    );
    issues
}

/// `outer` holds the enclosing loop targets of the current function
/// scope as `(name, target range)` pairs, innermost last.
fn walk_s8510<'a>(
    stmts: &'a [Stmt],
    outer: &mut Vec<(&'a str, TextRange)>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                let mut fresh = Vec::new();
                walk_s8510(function.body.as_slice(), &mut fresh, index, source, issues);
            }
            Stmt::ClassDef(class) => {
                let mut fresh = Vec::new();
                walk_s8510(class.body.as_slice(), &mut fresh, index, source, issues);
            }
            Stmt::For(for_stmt) => {
                walk_loop(for_stmt, outer, index, source, issues);
            }
            other => {
                for body in child_bodies(other) {
                    walk_s8510(body, outer, index, source, issues);
                }
            }
        }
    }
}

/// Checks this loop's targets against the enclosing ones, then extends
/// the scope with them for the body; the `else` suite runs outside the
/// iterations and keeps the unextended scope.
fn walk_loop<'a>(
    for_stmt: &'a StmtFor,
    outer: &mut Vec<(&'a str, TextRange)>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let targets = target_names(&for_stmt.target);
    let mut reported: Vec<&str> = Vec::new();
    for (name, range) in &targets {
        if reported.contains(name) {
            continue;
        }
        let Some((_, outer_range)) = outer
            .iter()
            .rev()
            .find(|(outer_name, _)| *outer_name == *name)
        else {
            continue;
        };
        reported.push(*name);
        let mut issue = issue_at(
            RULE_KEY,
            &format!("{MESSAGE_TEMPLATE} \"{name}\"."),
            *range,
            index,
            source,
        );
        issue.flows.push(hoonarqube_ir::IssueFlow {
            locations: vec![flow_location(FLOW_MESSAGE, *outer_range, index, source)],
        });
        issues.push(issue);
    }
    let mark = outer.len();
    outer.extend(targets);
    walk_s8510(for_stmt.body.as_slice(), outer, index, source, issues);
    outer.truncate(mark);
    walk_s8510(for_stmt.orelse.as_slice(), outer, index, source, issues);
}

/// Flat `(name, range)` pairs of a loop target, including tuple and
/// list unpacking components.
fn target_names(target: &Expr) -> Vec<(&str, TextRange)> {
    match target {
        Expr::Name(name) => vec![(name.id.as_str(), name.range())],
        Expr::Tuple(tuple) => tuple.elts.iter().flat_map(target_names).collect(),
        Expr::List(list) => list.elts.iter().flat_map(target_names).collect(),
        Expr::Starred(starred) => target_names(&starred.value),
        _ => Vec::new(),
    }
}
