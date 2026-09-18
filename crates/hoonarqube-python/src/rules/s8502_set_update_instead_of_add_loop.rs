use std::collections::HashSet;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtAnnAssign, StmtAssign, StmtFor, StmtFunctionDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::child_bodies;
use crate::support::function_parameters;
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
    walk_s8502_scoped(stmts, &HashSet::new(), index, source, issues);
}

fn walk_s8502_scoped(
    stmts: &[Stmt],
    inherited: &HashSet<String>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    // Sonar fires only when the receiver is provably a set — a name bound
    // to a set literal, set comprehension, or set() call in this scope,
    // declared `set` by annotation, or a set-annotated parameter of an
    // enclosing `def`.
    let mut set_names = collect_set_names(stmts);
    set_names.extend(inherited.iter().cloned());
    for stmt in stmts {
        if let Stmt::For(for_stmt) = stmt {
            check_for_loop(for_stmt, &set_names, index, source, issues);
        }
        if let Stmt::FunctionDef(function) = stmt {
            // Parameters rebind their names inside the body: drop every
            // parameter name, then re-add the set-annotated ones.
            let mut inner = set_names.clone();
            for name in parameter_names(function) {
                inner.remove(name);
            }
            inner.extend(set_annotated_parameters(function));
            walk_s8502_scoped(&function.body, &inner, index, source, issues);
            continue;
        }
        for body in child_bodies(stmt) {
            walk_s8502_scoped(body, &set_names, index, source, issues);
        }
    }
}

/// Names bound to a provable set value (`set()`, `{x, y}`, `{x for …}`)
/// or declared `set` by annotation anywhere in `stmts`.
fn collect_set_names(stmts: &[Stmt]) -> HashSet<String> {
    let mut names = HashSet::new();
    for stmt in stmts {
        match stmt {
            Stmt::Assign(assign) => collect_assign_set_names(assign, &mut names),
            Stmt::AnnAssign(assign) => collect_ann_assign_set_name(assign, &mut names),
            _ => {}
        }
    }
    names
}

/// Plain `name = <provable set>` assignment targets.
fn collect_assign_set_names(assign: &StmtAssign, names: &mut HashSet<String>) {
    if !is_set_expression(&assign.value) {
        return;
    }
    for target in &assign.targets {
        if let Expr::Name(name) = target {
            names.insert(name.id.to_string());
        }
    }
}

/// `name: set` (optionally `= value`): the declared type is the proof —
/// `s: set` counts with or without a value, while a non-set annotation
/// leaves the name unknown even over a set literal.
fn collect_ann_assign_set_name(assign: &StmtAnnAssign, names: &mut HashSet<String>) {
    if !is_set_annotation(&assign.annotation) {
        return;
    }
    if let Expr::Name(name) = assign.target.as_ref() {
        names.insert(name.id.to_string());
    }
}

/// A provable set value: `set()`, `{x, y}`, or `{x for …}`.
fn is_set_expression(value: &Expr) -> bool {
    match value {
        Expr::Set(_) | Expr::SetComp(_) => true,
        Expr::Call(call) => matches!(
            call.func.as_ref(),
            Expr::Name(name) if name.id.as_str() == "set"
        ),
        _ => false,
    }
}

/// An annotation declaring the builtin `set` type: `set`, `set[...]`,
/// or a dotted `*.set`/`*.Set` path such as `typing.Set`/`builtins.set`.
fn is_set_annotation(annotation: &Expr) -> bool {
    match annotation {
        Expr::Subscript(subscript) => is_set_annotation(&subscript.value),
        Expr::Name(name) => matches!(name.id.as_str(), "set" | "Set"),
        Expr::Attribute(attribute) => matches!(attribute.attr.as_str(), "set" | "Set"),
        _ => false,
    }
}

/// Every parameter name of `function`, including `*args`/`**kwargs`:
/// each rebinds its name inside the body.
fn parameter_names(function: &StmtFunctionDef) -> Vec<&str> {
    let mut names: Vec<&str> = function_parameters(function)
        .into_iter()
        .map(|entry| entry.parameter.name.as_str())
        .collect();
    for extra in function
        .parameters
        .vararg
        .iter()
        .chain(&function.parameters.kwarg)
    {
        names.push(extra.name.as_str());
    }
    names
}

/// Names of `def` parameters annotated as `set` — a declared set type is
/// the same provable-set proof Sonar requires before flagging.
fn set_annotated_parameters(function: &StmtFunctionDef) -> Vec<String> {
    function_parameters(function)
        .into_iter()
        .filter(|entry| {
            entry
                .parameter
                .annotation
                .as_deref()
                .is_some_and(is_set_annotation)
        })
        .map(|entry| entry.parameter.name.as_str().to_string())
        .collect()
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

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8502_accepts_add_loops_on_unproven_receivers() {
        // Issue #639: pinned django/django sites — `geom` is an
        // OGRGeometry parameter and `ordered` an OrderedSet(); neither
        // is a provable set, so Sonar stays silent on both.
        let clean = scan(concat!(
            "def merge(geom, new):\n",
            "    for g in new:\n",
            "        geom.add(g)\n",
            "\n",
            "def collect(items):\n",
            "    ordered = OrderedSet()\n",
            "    for item in items:\n",
            "        ordered.add(item)\n",
        ));
        assert!(findings(&clean, "python:S8502").is_empty());
    }

    #[test]
    fn s8502_accepts_non_set_annotations_and_comprehensions() {
        // A non-set annotation leaves the receiver unknown even over a
        // set literal, and a set comprehension needs no update() loop.
        let clean = scan(concat!(
            "def declared_list(items):\n",
            "    s: list = set()\n",
            "    for item in items:\n",
            "        s.add(item)\n",
            "\n",
            "def comprehended(items):\n",
            "    s = {item for item in items}\n",
        ));
        assert!(findings(&clean, "python:S8502").is_empty());
    }

    #[test]
    fn s8502_flags_add_loop_on_literal_set_receiver() {
        let flagged = scan(concat!(
            "def f(items):\n",
            "    s = set()\n",
            "    for item in items:\n",
            "        s.add(item)\n",
        ));
        let found = findings(&flagged, "python:S8502");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start, pos(4, 8));
        assert_eq!(found[0].range.end, pos(4, 13));
    }

    #[test]
    fn s8502_flags_add_loop_on_annotated_set_receiver() {
        // Issue #639 semantics: a declared `set` annotation is the same
        // provable-set proof as a literal — `s: set` flags with or
        // without an initializer, including `set[...]`/`typing.Set`.
        let flagged = scan(concat!(
            "import typing\n",
            "\n",
            "def annotated_value(items):\n",
            "    s: set = set()\n",
            "    for item in items:\n",
            "        s.add(item)\n",
            "\n",
            "def annotated_only(items):\n",
            "    s: set\n",
            "    for item in items:\n",
            "        s.add(item)\n",
            "\n",
            "def subscripted(items):\n",
            "    s: set[int] = set()\n",
            "    for item in items:\n",
            "        s.add(item)\n",
            "\n",
            "def typing_set(items):\n",
            "    s: typing.Set = set()\n",
            "    for item in items:\n",
            "        s.add(item)\n",
        ));
        assert_eq!(findings(&flagged, "python:S8502").len(), 4);
    }

    #[test]
    fn s8502_flags_add_loop_on_set_annotated_parameter() {
        // `def f(s: set)` declares the receiver's type — the same
        // provable-set proof Sonar requires before flagging.
        let flagged = scan(concat!(
            "def f(s: set, items):\n",
            "    for item in items:\n",
            "        s.add(item)\n",
        ));
        assert_eq!(findings(&flagged, "python:S8502").len(), 1);
    }

    #[test]
    fn s8502_unannotated_parameter_shadows_outer_set() {
        // An unannotated `s` parameter rebinds the name: the outer
        // provable set must not leak into the inner scope.
        let clean = scan(concat!(
            "def outer(s: set, items):\n",
            "    def inner(s):\n",
            "        for item in items:\n",
            "            s.add(item)\n",
        ));
        assert!(findings(&clean, "python:S8502").is_empty());
    }
}
