use std::collections::HashSet;

use hoonarqube_ir::Issue;
use ruff_python_ast::{
    CmpOp, Expr, ModModule, Stmt, StmtAnnAssign, StmtAssign, StmtFunctionDef, StmtIf,
};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::child_bodies;
use crate::support::exprs_textually_equal;
use crate::support::function_parameters;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8492";
const MESSAGE: &str =
    "Use \"discard()\" instead of checking membership before calling \"remove()\".";

/// python:S8492 — `if x in s: s.remove(x)` performs two hash lookups and
/// can raise `KeyError` between the check and the removal; `s.discard(x)`
/// is the single-lookup idempotent form. The finding anchors on the `in`
/// test, exactly where the reference reports it.
pub(crate) fn check_set_discard_instead_of_membership_removal(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_s8492_scoped(
        parsed.syntax().body.as_slice(),
        &HashSet::new(),
        index,
        source,
        &mut issues,
    );
    issues
}

fn walk_s8492_scoped(
    stmts: &[Stmt],
    inherited: &HashSet<String>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    // The reference fires only when the receiver is provably a set — a
    // name bound to a set literal, set comprehension, or set() call in
    // this scope, declared `set` by annotation, or a set-annotated
    // parameter of an enclosing `def` (same proof model as python:S8502).
    let mut set_names = collect_set_names(stmts);
    set_names.extend(inherited.iter().cloned());
    for stmt in stmts {
        if let Stmt::If(if_stmt) = stmt {
            check_if_statement(if_stmt, &set_names, index, source, issues);
        }
        if let Stmt::FunctionDef(function) = stmt {
            // Parameters rebind their names inside the body: drop every
            // parameter name, then re-add the set-annotated ones.
            let mut inner = set_names.clone();
            for name in parameter_names(function) {
                inner.remove(name);
            }
            inner.extend(set_annotated_parameters(function));
            walk_s8492_scoped(&function.body, &inner, index, source, issues);
            continue;
        }
        for body in child_bodies(stmt) {
            walk_s8492_scoped(body, &set_names, index, source, issues);
        }
    }
}

/// Flags `if x in s: s.remove(x)` — a bare `if` (no `elif`/`else`) whose
/// test is a plain `in` membership and whose only body statement removes
/// the tested element from the tested set. `not in`, chained
/// comparisons, keyword arguments, and extra body statements stay silent.
fn check_if_statement(
    if_stmt: &StmtIf,
    set_names: &HashSet<String>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !if_stmt.elif_else_clauses.is_empty() {
        return;
    }
    let Expr::Compare(compare) = if_stmt.test.as_ref() else {
        return;
    };
    if !matches!(compare.ops.as_ref(), [CmpOp::In]) {
        return;
    }
    let [Stmt::Expr(statement)] = if_stmt.body.as_slice() else {
        return;
    };
    let Expr::Call(call) = statement.value.as_ref() else {
        return;
    };
    let Expr::Attribute(method) = call.func.as_ref() else {
        return;
    };
    if method.attr.as_str() != "remove"
        || call.arguments.args.len() != 1
        || !call.arguments.keywords.is_empty()
    {
        return;
    }
    // The removed element and the receiver must be the same expressions
    // as the membership test's left and right operands.
    if !exprs_textually_equal(&call.arguments.args[0], &compare.left, source)
        || !exprs_textually_equal(&method.value, &compare.comparators[0], source)
    {
        return;
    }
    let Expr::Name(receiver) = method.value.as_ref() else {
        return;
    };
    if !set_names.contains(receiver.id.as_str()) {
        return;
    }
    issues.push(issue_at(RULE_KEY, MESSAGE, compare.range(), index, source));
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
/// the same provable-set proof the reference requires before flagging.
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

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8492_flags_membership_guarded_remove_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "my_set = {1, 2, 3, 4, 5}\n",
            "value = 3\n",
            "\n",
            "if value in my_set:\n",
            "    my_set.remove(value)\n",
        ));
        let found = findings(&flagged, "python:S8492");
        assert_eq!(found.len(), 1);
        // The anchor covers the `value in my_set` membership test.
        assert_eq!(found[0].range.start, pos(4, 3));
        assert_eq!(found[0].range.end, pos(4, 18));
        assert_eq!(
            found[0].message,
            "Use \"discard()\" instead of checking membership before calling \"remove()\"."
        );
    }

    #[test]
    fn s8492_accepts_discard_and_unguarded_remove() {
        // The reference Compliant solution plus a plain remove() call.
        let clean = scan(concat!(
            "my_set = {1, 2, 3, 4, 5}\n",
            "value = 3\n",
            "\n",
            "my_set.discard(value)\n",
            "my_set.remove(value)\n",
        ));
        assert!(findings(&clean, "python:S8492").is_empty());
    }

    #[test]
    fn s8492_flags_inside_function_with_set_annotated_parameter() {
        let flagged = scan(concat!(
            "def drop(s: set, x):\n",
            "    if x in s:\n",
            "        s.remove(x)\n",
        ));
        assert_eq!(findings(&flagged, "python:S8492").len(), 1);
    }

    #[test]
    fn s8492_accepts_unproven_receivers() {
        // Neither `items` (unannotated parameter) nor `ordered`
        // (OrderedSet, not a provable set) is provably a set.
        let clean = scan(concat!(
            "def drop(items, x):\n",
            "    if x in items:\n",
            "        items.remove(x)\n",
            "\n",
            "def collect(x):\n",
            "    ordered = OrderedSet()\n",
            "    if x in ordered:\n",
            "        ordered.remove(x)\n",
        ));
        assert!(findings(&clean, "python:S8492").is_empty());
    }

    #[test]
    fn s8492_accepts_mismatched_shapes() {
        let clean = scan(concat!(
            "s = {1, 2}\n",
            "x = 1\n",
            "y = 2\n",
            "if x in s:\n",
            "    s.remove(y)\n",
            "if x in s:\n",
            "    s.remove(x)\n",
            "    print(x)\n",
            "if x in s:\n",
            "    s.remove(x)\n",
            "else:\n",
            "    pass\n",
            "if x not in s:\n",
            "    s.remove(x)\n",
            "if x in s and y in s:\n",
            "    s.remove(x)\n",
        ));
        assert!(findings(&clean, "python:S8492").is_empty());
    }

    #[test]
    fn s8492_accepts_remove_on_different_set() {
        // The membership test guards `s`, not `t`.
        let clean = scan(concat!(
            "s = {1, 2}\n",
            "t = {3, 4}\n",
            "x = 1\n",
            "if x in s:\n",
            "    t.remove(x)\n",
        ));
        assert!(findings(&clean, "python:S8492").is_empty());
    }
}
