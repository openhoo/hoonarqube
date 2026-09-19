use crate::engine::file_context::FileContext;
use crate::rules::scope_values::{
    NameResolution, comprehension_target_names, for_each_expr_scoped, for_each_stmt_scoped,
    is_name, pushed_scope, resolve_in_scopes,
};
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{BoolOp, CmpOp, Expr, Stmt, UnaryOp};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S7931";
const MESSAGE: &str = "NotImplemented should not be used in boolean contexts.";

/// python:S7931 — `NotImplemented` evaluated in a boolean context raises a
/// `TypeError` starting with Python 3.14 (it used to evaluate to `True`).
/// Scope `ALL`.
///
/// Mirrors `NotImplementedBooleanContextCheck`: the flagged positions are
/// `if`/`elif`/`while` conditions, comprehension `if` clauses, conditional
/// expression tests, `and`/`or` operands, `not` operands, the sole argument
/// of a `bool(...)` call, and the operands of `is`/`is not` comparisons
/// against a boolean literal. A position is flagged when it is the literal
/// name `NotImplemented` or a name whose single assignment in the enclosing
/// lexical scope chain resolves to it (the reference resolves the
/// `_NotImplementedType` builtin type; the lexical approximation covers the
/// documented `result = NotImplemented` shape). Chained `is` comparisons
/// (`a is b is True`) are `COMPARISON` nodes in the reference grammar and
/// stay silent.
pub(crate) fn check_notimplemented_boolean_contexts(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_scoped(file_ctx.module_body, &mut |stmt, scopes| match stmt {
        Stmt::If(if_stmt) => {
            report_if_notimplemented(&mut issues, &if_stmt.test, scopes, index, source);
            for clause in &if_stmt.elif_else_clauses {
                if let Some(test) = &clause.test {
                    report_if_notimplemented(&mut issues, test, scopes, index, source);
                }
            }
        }
        Stmt::While(while_stmt) => {
            report_if_notimplemented(&mut issues, &while_stmt.test, scopes, index, source);
        }
        _ => {}
    });
    for_each_expr_scoped(file_ctx.module_body, &mut |expr, scopes| {
        check_expr_context(&mut issues, expr, scopes, index, source);
    });
    issues
}

/// Flags `NotImplemented` in expression-level boolean contexts: `and`/`or`
/// operands, `not`, `bool(...)`, conditional-expression tests, `is`/`is
/// not` against boolean literals, and comprehension `if` clauses.
fn check_expr_context<'a>(
    issues: &mut Vec<Issue>,
    expr: &'a Expr,
    scopes: &[(&'a [Stmt], &[&'a str], bool)],
    index: &LineIndex,
    source: &str,
) {
    match expr {
        Expr::BoolOp(bool_op) if matches!(bool_op.op, BoolOp::And | BoolOp::Or) => {
            for operand in &bool_op.values {
                report_if_notimplemented(issues, operand, scopes, index, source);
            }
        }
        Expr::UnaryOp(unary) if matches!(unary.op, UnaryOp::Not) => {
            report_if_notimplemented(issues, &unary.operand, scopes, index, source);
        }
        Expr::Call(call) => {
            if is_name(&call.func, "bool")
                && call.arguments.args.len() == 1
                && call.arguments.keywords.is_empty()
                && !matches!(call.arguments.args[0], Expr::Starred(_))
            {
                report_if_notimplemented(issues, &call.arguments.args[0], scopes, index, source);
            }
        }
        Expr::Compare(compare) => {
            // `x is <bool>` / `x is not <bool>`: single-operator `is`
            // comparisons only; chained comparisons are COMPARISON nodes
            // in the reference grammar and stay silent.
            if compare.ops.len() == 1
                && matches!(compare.ops[0], CmpOp::Is | CmpOp::IsNot)
                && (is_boolean_literal(&compare.left)
                    || compare.comparators.iter().any(is_boolean_literal))
            {
                report_if_notimplemented(issues, &compare.left, scopes, index, source);
                for comparator in &compare.comparators {
                    report_if_notimplemented(issues, comparator, scopes, index, source);
                }
            }
        }
        Expr::If(if_expr) => {
            report_if_notimplemented(issues, &if_expr.test, scopes, index, source);
        }
        Expr::ListComp(comp) => {
            report_comprehension_ifs(issues, &comp.generators, scopes, index, source);
        }
        Expr::SetComp(comp) => {
            report_comprehension_ifs(issues, &comp.generators, scopes, index, source);
        }
        Expr::Generator(comp) => {
            report_comprehension_ifs(issues, &comp.generators, scopes, index, source);
        }
        Expr::DictComp(comp) => {
            report_comprehension_ifs(issues, &comp.generators, scopes, index, source);
        }
        _ => {}
    }
}

/// Flags comprehension `if` clauses; they resolve against the comprehension
/// scope, which binds the `for` targets.
fn report_comprehension_ifs<'a>(
    issues: &mut Vec<Issue>,
    generators: &'a [ruff_python_ast::Comprehension],
    scopes: &[(&'a [Stmt], &[&'a str], bool)],
    index: &LineIndex,
    source: &str,
) {
    let bound = comprehension_target_names(generators);
    let comp_scopes = pushed_scope(scopes, &bound);
    for generator in generators {
        for condition in &generator.ifs {
            report_if_notimplemented(issues, condition, &comp_scopes, index, source);
        }
    }
}

fn report_if_notimplemented<'a>(
    issues: &mut Vec<Issue>,
    expr: &'a Expr,
    scopes: &[(&'a [Stmt], &[&'a str], bool)],
    index: &LineIndex,
    source: &str,
) {
    if is_notimplemented(expr, scopes, 0) {
        issues.push(issue_at(RULE_KEY, MESSAGE, expr.range(), index, source));
    }
}

/// Whether `expr` denotes `NotImplemented`: the literal name, or a name whose
/// single assignment in the scope chain resolves to it (bounded recursion).
fn is_notimplemented<'a>(
    expr: &'a Expr,
    scopes: &[(&'a [Stmt], &[&'a str], bool)],
    depth: u32,
) -> bool {
    let Expr::Name(name) = expr else {
        return false;
    };
    match resolve_in_scopes(scopes, name.id.as_str(), true) {
        NameResolution::Single(value) => {
            if depth >= 8 {
                return false;
            }
            is_notimplemented(value, scopes, depth + 1)
        }
        // A bound-but-unresolvable name is never the builtin; an unbound
        // name is the builtin only when it is literally `NotImplemented`.
        NameResolution::Ambiguous => false,
        NameResolution::Unbound => name.id.as_str() == "NotImplemented",
    }
}

fn is_boolean_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::BooleanLiteral(_))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7931";

    /// Sonar's own noncompliant/compliant pair: a name singly assigned to
    /// `NotImplemented` is flagged in an `if` condition; the identity check
    /// is clean.
    #[test]
    fn s7931_flags_sonar_example() {
        let flagged = scan(concat!(
            "def __eq__(self, other):\n",
            "    result = NotImplemented\n",
            "    if result:\n",
            "        return True\n",
            "    return False\n",
        ));
        let hits = findings(&flagged, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start.line, 3);
        let clean = scan(concat!(
            "def __eq__(self, other):\n",
            "    result = NotImplemented\n",
            "    if result is not NotImplemented:\n",
            "        return True\n",
            "    return False\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }

    /// Every boolean context shape from the reference subscription list.
    #[test]
    fn s7931_flags_each_boolean_context() {
        let report = scan(concat!(
            "if NotImplemented:\n",
            "    pass\n",
            "while NotImplemented:\n",
            "    pass\n",
            "x = NotImplemented and True\n",
            "y = True or NotImplemented\n",
            "z = not NotImplemented\n",
            "w = bool(NotImplemented)\n",
            "v = 1 if NotImplemented else 2\n",
            "seen = [i for i in items if NotImplemented]\n",
            "ok = NotImplemented is True\n",
        ));
        assert_eq!(findings(&report, KEY).len(), 9);
    }

    /// Negative controls: identity checks, non-boolean positions, shadowed
    /// names, and ambiguous bindings stay silent.
    #[test]
    fn s7931_negative_controls() {
        let clean = scan(concat!(
            "if NotImplemented is not None:\n",
            "    pass\n",
            "x = NotImplemented\n",
            "def f(NotImplemented):\n",
            "    if NotImplemented:\n",
            "        pass\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
        let rebound = scan(concat!(
            "result = NotImplemented\n",
            "result = 5\n",
            "if result:\n",
            "    pass\n",
        ));
        assert!(findings(&rebound, KEY).is_empty());
        let shadowed = scan(concat!(
            "NotImplemented = 0\n",
            "if NotImplemented:\n",
            "    pass\n",
        ));
        assert!(findings(&shadowed, KEY).is_empty());
    }
}
