use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtFor};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::child_bodies;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8502";
const MESSAGE: &str = "Use \"set.update()\" instead of a for-loop with \"add()\".";

/// python:S8502 — a for-loop whose only body statement feeds a local set
/// through `receiver.add(item)` with the loop variable should add the
/// whole iterable via `receiver.update(iterable)` instead: one bulk call
/// keeps the observable result while dropping the per-element loop.
pub(crate) fn check_s8502_set_update_instead_of_add_loop(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_s8502(parsed.syntax().body.as_slice(), index, source, &mut issues);
    issues
}

fn walk_s8502(stmts: &[Stmt], index: &LineIndex, source: &str, issues: &mut Vec<Issue>) {
    // Sonar fires only when the receiver is provably a set — a name bound
    // to a set literal, set comprehension, or set() call in this scope.
    let set_names = collect_set_names(stmts);
    for stmt in stmts {
        if let Stmt::For(for_stmt) = stmt {
            check_for_loop(for_stmt, &set_names, index, source, issues);
        }
        for body in child_bodies(stmt) {
            walk_s8502(body, index, source, issues);
        }
    }
}

/// Names bound to a provable set value (`set()`, `{x, y}`, `{x for …}`)
/// anywhere in `stmts`.
fn collect_set_names(stmts: &[Stmt]) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for stmt in stmts {
        let Stmt::Assign(assign) = stmt else {
            continue;
        };
        let is_set = match assign.value.as_ref() {
            Expr::Set(_) | Expr::SetComp(_) => true,
            Expr::Call(call) => matches!(
                call.func.as_ref(),
                Expr::Name(name) if name.id.as_str() == "set"
            ),
            _ => false,
        };
        if !is_set {
            continue;
        }
        for target in &assign.targets {
            if let Expr::Name(name) = target {
                names.insert(name.id.to_string());
            }
        }
    }
    names
}

/// Flags `for item in iterable: receiver.add(item)` with a plain-name
/// target and receiver, one body statement, and no `else` clause. The
/// anchor covers `receiver.add` (the `.add()` call callee). Async loops
/// iterate asynchronous iterators, which `update()` cannot consume, and
/// stay silent.
fn check_for_loop(
    for_stmt: &StmtFor,
    set_names: &std::collections::HashSet<String>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !for_stmt.orelse.is_empty() || for_stmt.body.len() != 1 {
        return;
    }
    let Expr::Name(target) = for_stmt.target.as_ref() else {
        return;
    };
    let Stmt::Expr(statement) = &for_stmt.body[0] else {
        return;
    };
    let Expr::Call(call) = statement.value.as_ref() else {
        return;
    };
    let Expr::Attribute(method) = call.func.as_ref() else {
        return;
    };
    if method.attr.as_str() != "add"
        || call.arguments.args.len() != 1
        || !call.arguments.keywords.is_empty()
    {
        return;
    }
    let Expr::Name(receiver) = method.value.as_ref() else {
        return;
    };
    // The receiver must be provably a set in this scope.
    if !set_names.contains(receiver.id.as_str()) {
        return;
    }
    let Expr::Name(added) = &call.arguments.args[0] else {
        return;
    };
    // The receiver is the set being built; only the added argument
    // must be the loop variable.
    if added.id != target.id {
        return;
    }
    issues.push(issue_at(
        RULE_KEY,
        MESSAGE,
        call.func.range(),
        index,
        source,
    ));
}
