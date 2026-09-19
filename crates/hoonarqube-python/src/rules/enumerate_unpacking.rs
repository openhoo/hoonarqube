use crate::support::child_bodies;
use crate::support::child_exprs;
use crate::support::collect_target_names;
use crate::support::flow_location;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use crate::support::stmt_store_names;
use hoonarqube_ir::{Issue, IssueFlow};
use ruff_python_ast::{ExceptHandler, Expr, ModModule, Stmt, StmtFor};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

const RULE_KEY: &str = "python:S8518";
const MESSAGE: &str =
    "Unpack the value from 'enumerate()' directly instead of using an index lookup.";
const FLOW_MESSAGE: &str = "Replace this index lookup with the unpacked value.";

/// python:S8518 — `for i, value in enumerate(items)` already yields the
/// element, so reading `items[i]` inside the loop is a redundant lookup.
/// The `enumerate(...)` call anchors the finding and every redundant
/// subscript is a secondary location. The loop target must be a bare
/// `name, name` pair, the iterable a plain name, and `start=` absent or the
/// literal `0`. Subscripts used as write targets (`items[i] = x`,
/// `items[i] += x`, `items[i]: T = x`, `del items[i]`) exempt the whole
/// loop, as do nested scopes that rebind the index or iterable name.
pub(crate) fn check_enumerate_unpacking(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::For(for_stmt) = stmt {
            check_for(for_stmt, index, source, &mut issues);
        }
    });
    issues
}

fn check_for(for_stmt: &StmtFor, index: &LineIndex, source: &str, issues: &mut Vec<Issue>) {
    let Expr::Call(call) = for_stmt.iter.as_ref() else {
        return;
    };
    if !matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "enumerate") {
        return;
    }
    // The reference reads the loop's two target expressions; a parenthesized
    // `(i, value)` arrives as one tuple and is out of scope.
    let Expr::Tuple(target) = for_stmt.target.as_ref() else {
        return;
    };
    if target.parenthesized || target.elts.len() != 2 {
        return;
    }
    let Expr::Name(index_name) = &target.elts[0] else {
        return;
    };
    // `start=` must be absent or the literal `0` (textual, like the
    // reference's `valueAsString` comparison — `0x0` does not qualify).
    if let Some(start) = call.arguments.find_argument_value("start", 1)
        && !(matches!(start, Expr::NumberLiteral(_)) && &source[start.range()] == "0")
    {
        return;
    }
    let Some(iterable) = call.arguments.find_argument_value("iterable", 0) else {
        return;
    };
    let Expr::Name(iterable_name) = iterable else {
        return;
    };
    let names = [index_name.id.as_str(), iterable_name.id.as_str()];
    let mut subscripts = Vec::new();
    collect_matching_subscripts(&for_stmt.body, &names, &mut subscripts);
    if subscripts.is_empty() {
        return;
    }
    let writes = subscript_write_ranges(&for_stmt.body);
    if subscripts
        .iter()
        .any(|subscript| writes.contains(&subscript.range()))
    {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, call.range(), index, source);
    issue.flows.push(IssueFlow {
        locations: subscripts
            .iter()
            .map(|subscript| flow_location(FLOW_MESSAGE, subscript.range(), index, source))
            .collect(),
    });
    issues.push(issue);
}

/// Collects `iterable[index]` subscripts inside the loop body. Nested
/// scopes that rebind either name are skipped: a rebound `i` or `items` is
/// a different symbol than the loop's, so its subscripts do not match.
fn collect_matching_subscripts<'a>(
    stmts: &'a [Stmt],
    names: &[&str; 2],
    found: &mut Vec<&'a ruff_python_ast::ExprSubscript>,
) {
    for stmt in stmts {
        for expr in stmt_exprs(stmt) {
            collect_expr_subscripts(expr, names, found);
        }
        if stmt_binds_names(stmt, names) {
            continue;
        }
        for body in child_bodies(stmt) {
            collect_matching_subscripts(body, names, found);
        }
    }
}

fn collect_expr_subscripts<'a>(
    expr: &'a Expr,
    names: &[&str; 2],
    found: &mut Vec<&'a ruff_python_ast::ExprSubscript>,
) {
    if let Expr::Subscript(subscript) = expr
        && matches!(subscript.value.as_ref(), Expr::Name(object) if object.id.as_str() == names[1])
        && matches!(subscript.slice.as_ref(), Expr::Name(index) if index.id.as_str() == names[0])
    {
        found.push(subscript);
    }
    match expr {
        Expr::Lambda(lambda) => {
            // Parameter defaults evaluate in the enclosing scope; the body
            // only counts when no parameter rebinds a tracked name.
            if let Some(parameters) = lambda.parameters.as_deref() {
                for expr in parameter_default_exprs(parameters) {
                    collect_expr_subscripts(expr, names, found);
                }
                if parameters_bind(parameters, names) {
                    return;
                }
            }
            collect_expr_subscripts(&lambda.body, names, found);
        }
        Expr::ListComp(comprehension) => {
            collect_comprehension_subscripts(
                &comprehension.generators,
                &[comprehension.elt.as_ref()],
                names,
                found,
            );
        }
        Expr::SetComp(comprehension) => {
            collect_comprehension_subscripts(
                &comprehension.generators,
                &[comprehension.elt.as_ref()],
                names,
                found,
            );
        }
        Expr::Generator(comprehension) => {
            collect_comprehension_subscripts(
                &comprehension.generators,
                &[comprehension.elt.as_ref()],
                names,
                found,
            );
        }
        Expr::DictComp(comprehension) => {
            let mut elements: Vec<&Expr> = Vec::new();
            if let Some(key) = &comprehension.key {
                elements.push(key.as_ref());
            }
            elements.push(comprehension.value.as_ref());
            collect_comprehension_subscripts(&comprehension.generators, &elements, names, found);
        }
        other => {
            for child in child_exprs(other) {
                collect_expr_subscripts(child, names, found);
            }
        }
    }
}

/// Comprehension generators bind their targets in the comprehension scope;
/// each `iter` still evaluates in the scope of the preceding targets, so it
/// is walked until the first rebinding target. Element expressions only
/// count when no generator rebinds a tracked name.
fn collect_comprehension_subscripts<'a>(
    generators: &'a [ruff_python_ast::Comprehension],
    elements: &[&'a Expr],
    names: &[&str; 2],
    found: &mut Vec<&'a ruff_python_ast::ExprSubscript>,
) {
    let mut rebound = false;
    for generator in generators {
        collect_expr_subscripts(&generator.iter, names, found);
        for condition in &generator.ifs {
            collect_expr_subscripts(condition, names, found);
        }
        rebound |= target_binds(&generator.target, names);
    }
    if rebound {
        return;
    }
    for element in elements {
        collect_expr_subscripts(element, names, found);
    }
}

/// Whether a statement binds one of the tracked names for its nested
/// bodies: shallow stores (assignments, loop/with targets, imports,
/// definition names), `except ... as` names, and function or class scopes
/// whose suite rebinds the name.
fn stmt_binds_names(stmt: &Stmt, names: &[&str; 2]) -> bool {
    if stmt_store_names(stmt)
        .iter()
        .any(|name| names.contains(&name.as_str()))
    {
        return true;
    }
    match stmt {
        Stmt::FunctionDef(function) => {
            parameters_bind(&function.parameters, names) || suite_binds_names(&function.body, names)
        }
        Stmt::ClassDef(class) => suite_binds_names(&class.body, names),
        Stmt::Try(try_stmt) => try_stmt.handlers.iter().any(|handler| {
            let ExceptHandler::ExceptHandler(handler) = handler;
            handler
                .name
                .as_ref()
                .is_some_and(|name| names.contains(&name.as_str()))
        }),
        _ => false,
    }
}

/// Whether any statement in the suite binds a tracked name, descending
/// through non-scope bodies; function and class suites are covered by
/// [`stmt_binds_names`] itself.
fn suite_binds_names(stmts: &[Stmt], names: &[&str; 2]) -> bool {
    stmts.iter().any(|stmt| {
        stmt_binds_names(stmt, names)
            || (!matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_))
                && child_bodies(stmt)
                    .iter()
                    .any(|body| suite_binds_names(body, names)))
    })
}

/// Whether any parameter name of the parameter list matches a tracked name.
fn parameters_bind(parameters: &ruff_python_ast::Parameters, names: &[&str; 2]) -> bool {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .any(|with_default| names.contains(&with_default.parameter.name.as_str()))
        || parameters
            .vararg
            .iter()
            .chain(&parameters.kwarg)
            .any(|parameter| names.contains(&parameter.name.as_str()))
}

/// Default-value expressions of a parameter list; they evaluate where the
/// function or lambda is defined, not inside its scope.
fn parameter_default_exprs(parameters: &ruff_python_ast::Parameters) -> Vec<&Expr> {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .filter_map(|with_default| with_default.default.as_deref())
        .collect()
}

/// Whether a binding target (loop `for`, `with as`, comprehension target)
/// captures one of the tracked names.
fn target_binds(target: &Expr, names: &[&str; 2]) -> bool {
    let mut bound = Vec::new();
    collect_target_names(target, &mut bound);
    bound.iter().any(|name| names.contains(&name.as_str()))
}

/// Ranges of subscripts used as write targets inside the suite, matching
/// the reference's parent-shape check: direct assignment targets (including
/// unparenthesized comma targets), augmented and annotated targets, and a
/// single `del` target.
fn subscript_write_ranges(stmts: &[Stmt]) -> Vec<TextRange> {
    let mut ranges = Vec::new();
    for_each_stmt(stmts, &mut |stmt| match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                collect_write_target(target, &mut ranges);
            }
        }
        Stmt::AugAssign(assign) => collect_write_target(&assign.target, &mut ranges),
        Stmt::AnnAssign(assign) => collect_write_target(&assign.target, &mut ranges),
        Stmt::Delete(delete) => {
            if let [target] = delete.targets.as_slice() {
                collect_write_target(target, &mut ranges);
            }
        }
        _ => {}
    });
    ranges
}

/// Collects subscript ranges of one assignment-shaped target; a bare
/// (unparenthesized) tuple target contributes its element subscripts.
fn collect_write_target(target: &Expr, ranges: &mut Vec<TextRange>) {
    match target {
        Expr::Subscript(subscript) => ranges.push(subscript.range()),
        Expr::Tuple(tuple) if !tuple.parenthesized => {
            for element in &tuple.elts {
                collect_write_target(element, ranges);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8518")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8518_flags_sonar_noncompliant_example() {
        // Sonar's own Noncompliant example; the `enumerate(...)` call anchors
        // and the `fruits[i]` subscript is the secondary location.
        let flagged = found(concat!(
            "fruits = ['apple', 'banana', 'cherry']\n",
            "for i, fruit in enumerate(fruits):\n",
            "    print(f\"Index {i}: {fruits[i]}\")\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Unpack the value from 'enumerate()' directly instead of using an index lookup."
        );
        assert_eq!(flagged[0].range.start, pos(2, 16));
        assert_eq!(flagged[0].range.end, pos(2, 33));
        assert_eq!(flagged[0].flows.len(), 1);
        let locations = &flagged[0].flows[0].locations;
        assert_eq!(locations.len(), 1);
        assert_eq!(
            locations[0].message,
            "Replace this index lookup with the unpacked value."
        );
        assert_eq!(locations[0].range.start, pos(3, 24));
        assert_eq!(locations[0].range.end, pos(3, 33));
    }

    #[test]
    fn s8518_flags_multiple_lookups_and_start_zero() {
        let flagged = found(concat!(
            "for i, item in enumerate(items, 0):\n",
            "    first = items[i]\n",
            "    second = items[i] + items[i]\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].flows[0].locations.len(), 3);
    }

    #[test]
    fn s8518_stays_silent_on_compliant_and_write_targets() {
        // Sonar's Compliant solution plus controls: subscript writes exempt
        // the loop, as do non-zero starts and non-name iterables.
        let clean = concat!(
            "fruits = ['apple', 'banana', 'cherry']\n",
            "for i, fruit in enumerate(fruits):\n",
            "    print(f\"Index {i}: {fruit}\")\n",
            "for i, item in enumerate(items):\n",
            "    items[i] = item * 2\n",
            "for i, item in enumerate(items):\n",
            "    items[i] += 1\n",
            "for i, item in enumerate(items):\n",
            "    del items[i]\n",
            "for i, item in enumerate(items, 1):\n",
            "    use(items[i])\n",
            "for i, item in enumerate(get_items()):\n",
            "    use(items[i])\n",
        );
        assert!(found(clean).is_empty());
    }

    #[test]
    fn s8518_stays_silent_on_rebound_nested_scopes() {
        // A nested function or comprehension rebinding `i` or `items` reads
        // a different symbol; its subscripts do not match.
        let clean = concat!(
            "for i, item in enumerate(items):\n",
            "    def helper(i):\n",
            "        return items[i]\n",
            "    def other():\n",
            "        items = []\n",
            "        return items[i]\n",
            "    squares = [items[i] for i in range(3)]\n",
            "    pairs = [(items[i], j) for j in items for i in items]\n",
            "    quiet = lambda i: items[i]\n",
        );
        assert!(found(clean).is_empty());
    }

    #[test]
    fn s8518_flags_closures_and_outer_scope_reads() {
        // Reads through the loop's own names still match inside nested
        // scopes that do not rebind them, and comprehension `iter`
        // expressions evaluate in the enclosing scope.
        let flagged = found(concat!(
            "for i, item in enumerate(items):\n",
            "    def helper():\n",
            "        return items[i]\n",
            "    picked = [items[i] for j in range(3)]\n",
            "    later = lambda: items[i]\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].flows[0].locations.len(), 3);
    }
}
