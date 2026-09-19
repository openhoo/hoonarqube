use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtFunctionDef, StmtReturn};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::child_bodies;
use crate::support::child_exprs;
use crate::support::flow_location;
use crate::support::issue_at;
use crate::support::stmt_exprs;

const RULE_KEY: &str = "python:S8495";
const MESSAGE: &str = "Refactor this function to always return tuples of the same length.";

/// python:S8495 — a function whose `return` statements produce tuples of
/// different lengths forces callers to length-check before unpacking.
/// Generators are exempt, and nested `def`/`lambda` bodies never count
/// toward the enclosing function's returns. The finding anchors on the
/// function name; each tuple return is a secondary location.
pub(crate) fn check_consistent_return_tuple_lengths(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        check_function(function, index, source, &mut issues);
    }
    issues
}

fn check_function(
    function: &StmtFunctionDef,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let mut returns: Vec<(&StmtReturn, usize)> = Vec::new();
    if collect_tuple_returns(&function.body, &mut returns) {
        return;
    }
    if returns.len() < 2 {
        return;
    }
    let first_length = returns[0].1;
    if returns.iter().all(|(_, length)| *length == first_length) {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, function.name.range(), index, source);
    issue = issue.with_flow(
        returns
            .iter()
            .map(|(stmt, length)| {
                flow_location(
                    &format!("Returns a {length}-tuple."),
                    stmt.range(),
                    index,
                    source,
                )
            })
            .collect(),
    );
    issues.push(issue);
}

/// Tuple lengths of every `return` in `stmts`, in source order. Nested
/// `def` bodies are separate functions; a `yield`/`yield from` anywhere
/// in the function (outside nested `def`/`lambda`) makes it a generator
/// and aborts the collection entirely. Returns `true` when a yield was
/// found so the caller can abandon the function.
fn collect_tuple_returns<'a>(
    stmts: &'a [Stmt],
    returns: &mut Vec<(&'a StmtReturn, usize)>,
) -> bool {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(_) => continue,
            Stmt::Return(stmt_return) => {
                if let Some(length) = tuple_return_length(stmt_return) {
                    returns.push((stmt_return, length));
                }
            }
            _ => {}
        }
        if stmt_exprs(stmt).iter().any(|expr| contains_yield(expr)) {
            return true;
        }
        for body in child_bodies(stmt) {
            if collect_tuple_returns(body, returns) {
                return true;
            }
        }
    }
    false
}

/// The tuple length a `return` produces: the element count of a tuple
/// expression, or the arity of a bare `return a, b, c` list. Returns
/// containing `*`-unpacking have no statically known length and are
/// ignored, as are non-tuple values.
fn tuple_return_length(stmt_return: &StmtReturn) -> Option<usize> {
    let value = stmt_return.value.as_deref()?;
    let Expr::Tuple(tuple) = value else {
        return None;
    };
    if tuple.elts.iter().any(|elt| matches!(elt, Expr::Starred(_))) {
        return None;
    }
    Some(tuple.elts.len())
}

/// Whether `expr` contains a `yield`/`yield from` outside any `lambda`
/// body (lambdas cannot yield, matching the reference's lambda skip).
fn contains_yield(expr: &Expr) -> bool {
    if matches!(expr, Expr::Yield(_) | Expr::YieldFrom(_)) {
        return true;
    }
    if matches!(expr, Expr::Lambda(_)) {
        return false;
    }
    child_exprs(expr).iter().any(|child| contains_yield(child))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8495_flags_inconsistent_tuple_lengths_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "def calculate_stats(numbers):\n",
            "    if not numbers:\n",
            "        return (0,)\n",
            "    total = sum(numbers)\n",
            "    average = total / len(numbers)\n",
            "    return (total, average)\n",
        ));
        let found = findings(&flagged, "python:S8495");
        assert_eq!(found.len(), 1);
        // The anchor covers the function name.
        assert_eq!(found[0].range.start, pos(1, 4));
        assert_eq!(found[0].range.end, pos(1, 19));
        assert_eq!(
            found[0].message,
            "Refactor this function to always return tuples of the same length."
        );
    }

    #[test]
    fn s8495_accepts_consistent_lengths_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "def calculate_stats(numbers):\n",
            "    if not numbers:\n",
            "        return (0, 0)\n",
            "    total = sum(numbers)\n",
            "    average = total / len(numbers)\n",
            "    return (total, average)\n",
        ));
        assert!(findings(&clean, "python:S8495").is_empty());
    }

    #[test]
    fn s8495_flags_bare_comma_returns_of_different_arity() {
        let flagged = scan(concat!(
            "def process_data(value):\n",
            "    if value > 0:\n",
            "        return value,\n",
            "    else:\n",
            "        return value, value * 2\n",
        ));
        assert_eq!(findings(&flagged, "python:S8495").len(), 1);
    }

    #[test]
    fn s8495_ignores_non_tuple_and_unpacking_returns() {
        // `return *rest` has no static length; mixing it with tuples and
        // non-tuple returns stays silent.
        let clean = scan(concat!(
            "def f(value, rest):\n",
            "    if value > 0:\n",
            "        return (value,)\n",
            "    if value == 0:\n",
            "        return *rest\n",
            "    return None\n",
        ));
        assert!(findings(&clean, "python:S8495").is_empty());
    }

    #[test]
    fn s8495_ignores_generators_and_nested_functions() {
        // A generator is exempt, and the nested function's returns do
        // not count toward the outer function.
        let clean = scan(concat!(
            "def gen(flag):\n",
            "    if flag:\n",
            "        yield (1,)\n",
            "    return (1, 2)\n",
            "\n",
            "def outer(flag):\n",
            "    def inner():\n",
            "        return (1,)\n",
            "    if flag:\n",
            "        return (1, 2)\n",
            "    return (3, 4)\n",
        ));
        assert!(findings(&clean, "python:S8495").is_empty());
    }

    #[test]
    fn s8495_flags_nested_function_independently() {
        // The inner function is checked on its own returns.
        let flagged = scan(concat!(
            "def outer():\n",
            "    def inner(flag):\n",
            "        if flag:\n",
            "            return (1,)\n",
            "        return (1, 2)\n",
            "    return inner\n",
        ));
        let found = findings(&flagged, "python:S8495");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start, pos(2, 8));
        assert_eq!(found[0].range.end, pos(2, 13));
    }
}
