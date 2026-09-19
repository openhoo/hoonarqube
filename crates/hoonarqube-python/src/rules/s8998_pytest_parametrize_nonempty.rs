use ruff_python_ast::{Decorator, Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{
    child_bodies, dotted_name_is, for_each_expr, issue_at, single_assigned_constant, stmt_exprs,
    string_value_text,
};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8998";
const MESSAGE: &str = "Add at least one case to the parametrize values.";

/// python:S8998 — `@pytest.mark.parametrize` with an empty `argvalues`
/// collects the test but silently skips it, so the suite passes with no
/// coverage. The second positional argument (or the `argvalues` keyword) is
/// flagged when it is a falsy literal (`[]`, `()`, `{}`, `""`, `0`, `0.0`,
/// `0j`, `False`, `None`), an empty no-argument `list()`/`tuple()`/`dict()`/
/// `set()` constructor, or `range(N)` with a numeric literal `N <= 0`. A name
/// is flagged when its single assignment in an enclosing scope is one of
/// those shapes — unless module-level code populates the collection through
/// a mutating method call (`append`/`extend`/`insert`, `update`/
/// `setdefault`, `add`) on the name or a simple `alias = name` binding, which
/// the reference treats as executed before collection. The finding anchors
/// the argvalues expression.
pub(crate) fn check_s8998_pytest_parametrize_nonempty(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let module = parsed.syntax().body.as_slice();
    let mut scopes: Vec<&[Stmt]> = vec![module];
    visit_statements(module, &mut scopes, &mut |decorator, scopes| {
        check_decorator(decorator, scopes, index, source, &mut issues);
    });
    issues
}

/// Depth-first statement walk that tracks the enclosing suites so name
/// resolution sees the decorator's own scope before outer ones.
fn visit_statements<'a>(
    stmts: &'a [Stmt],
    scopes: &mut Vec<&'a [Stmt]>,
    visit: &mut impl FnMut(&'a Decorator, &[&'a [Stmt]]),
) {
    for stmt in stmts {
        let decorators: &[Decorator] = match stmt {
            Stmt::FunctionDef(function) => &function.decorator_list,
            Stmt::ClassDef(class) => &class.decorator_list,
            _ => &[],
        };
        for decorator in decorators {
            visit(decorator, scopes);
        }
        for body in child_bodies(stmt) {
            scopes.push(body);
            visit_statements(body, scopes, visit);
            scopes.pop();
        }
    }
}

fn check_decorator(
    decorator: &Decorator,
    scopes: &[&[Stmt]],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Expr::Call(call) = &decorator.expression else {
        return;
    };
    if !dotted_name_is(&call.func, "pytest.mark.parametrize") {
        return;
    }
    let Some(argvalues) = argvalues_argument(call) else {
        return;
    };
    if !is_empty_parametrize_values(argvalues, scopes, source)
        || is_populated_before_collection(argvalues, scopes)
    {
        return;
    }
    issues.push(issue_at(
        RULE_KEY,
        MESSAGE,
        argvalues.range(),
        index,
        source,
    ));
}

/// `TreeUtils.nthArgumentOrKeyword(1, "argvalues", ...)`: the second
/// positional argument wins over the keyword when both are present, and
/// starred positional arguments occupy a position without matching.
fn argvalues_argument(call: &ruff_python_ast::ExprCall) -> Option<&Expr> {
    for (position, arg) in call.arguments.args.iter().enumerate() {
        if position == 1 && !arg.is_starred_expr() {
            return Some(arg);
        }
    }
    for keyword in &call.arguments.keywords {
        if keyword.arg.as_deref() == Some("argvalues") {
            return Some(&keyword.value);
        }
    }
    None
}

/// `isEmptyParametrizeValues`: falsy literals and empty iterable
/// constructors directly, or a name whose single assignment is one.
fn is_empty_parametrize_values(expr: &Expr, scopes: &[&[Stmt]], source: &str) -> bool {
    if is_falsy_literal(expr, source) || is_empty_iterable_constructor(expr) {
        return true;
    }
    let Expr::Name(name) = expr else {
        return false;
    };
    let Some(assigned) = single_assigned_value(scopes, name.id.as_str()) else {
        return false;
    };
    is_falsy_literal(assigned, source) || is_empty_iterable_constructor(assigned)
}

/// `Expressions.isFalsy` restricted to literal shapes: `False`, `None`,
/// empty strings, the zero spellings `0`/`0.0`/`0j`, and empty list, tuple,
/// and dict literals.
fn is_falsy_literal(expr: &Expr, source: &str) -> bool {
    match expr {
        Expr::BooleanLiteral(boolean) => !boolean.value,
        Expr::NoneLiteral(_) => true,
        Expr::StringLiteral(literal) => string_value_text(&literal.value).is_empty(),
        Expr::NumberLiteral(_) => matches!(&source[expr.range()], "0" | "0.0" | "0j"),
        Expr::List(list) => list.elts.is_empty(),
        Expr::Tuple(tuple) => tuple.elts.is_empty(),
        Expr::Dict(dict) => dict.items.is_empty(),
        _ => false,
    }
}

/// `isEmptyIterableConstructor`: a no-argument `list()`/`tuple()`/`dict()`/
/// `set()` call, or `range(N)` with a single numeric literal `N <= 0`.
fn is_empty_iterable_constructor(expr: &Expr) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    let Expr::Name(callee) = call.func.as_ref() else {
        return false;
    };
    let name = callee.id.as_str();
    if matches!(name, "list" | "tuple" | "dict" | "set") {
        return call.arguments.args.is_empty() && call.arguments.keywords.is_empty();
    }
    if name != "range" || call.arguments.args.len() != 1 {
        return false;
    }
    numeric_literal_value(&call.arguments.args[0]).is_some_and(|value| value <= 0)
}

/// `numericLiteralValue`: integer and float literals plus unary `-` applied
/// to one; anything else is not a numeric literal.
fn numeric_literal_value(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64(),
            ruff_python_ast::Number::Float(value) => integral_f64(*value),
            ruff_python_ast::Number::Complex { .. } => None,
        },
        Expr::UnaryOp(unary) if matches!(unary.op, ruff_python_ast::UnaryOp::USub) => {
            numeric_literal_value(&unary.operand).map(|value| -value)
        }
        _ => None,
    }
}

/// `valueAsLong` on a float literal: exact integral values only (the
/// reference throws on fractions and out-of-range values).
#[allow(clippy::cast_possible_truncation)]
fn integral_f64(value: f64) -> Option<i64> {
    (value.fract() == 0.0
        && (-9.223_372_036_854_776e18..=9.223_372_036_854_776e18).contains(&value))
    .then_some(value as i64)
}

/// The single assignment of `name` in the innermost enclosing suite that
/// binds it exactly once, searched innermost to outermost.
fn single_assigned_value<'a>(scopes: &[&'a [Stmt]], name: &str) -> Option<&'a Expr> {
    scopes
        .iter()
        .rev()
        .find_map(|scope| single_assigned_constant(scope, name))
}

/// `isCollectionPopulatedBeforeTest`: module-level code (anything outside a
/// function body, including class bodies) calling a collection-populating
/// method on the name or on a simple `alias = name` binding.
fn is_populated_before_collection(expr: &Expr, scopes: &[&[Stmt]]) -> bool {
    let Expr::Name(name) = expr else {
        return false;
    };
    let name = name.id.as_str();
    let Some(methods) = collection_methods(expr, scopes) else {
        return false;
    };
    let mut receivers = vec![name];
    collect_module_aliases(scopes[0], name, &mut receivers);
    let mut populated = false;
    visit_module_exprs(scopes[0], &mut |candidate| {
        if populated {
            return;
        }
        let Expr::Call(call) = candidate else {
            return;
        };
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            return;
        };
        if !methods.contains(&attribute.attr.as_str()) {
            return;
        }
        if let Expr::Name(receiver) = attribute.value.as_ref()
            && receivers.contains(&receiver.id.as_str())
        {
            populated = true;
        }
    });
    populated
}

/// The populating methods of the collection kind the name was assigned, per
/// the reference's typed matcher (`list.append` on a `str` binding does not
/// count).
fn collection_methods(expr: &Expr, scopes: &[&[Stmt]]) -> Option<&'static [&'static str]> {
    const LIST_METHODS: &[&str] = &["append", "extend", "insert"];
    const DICT_METHODS: &[&str] = &["update", "setdefault"];
    const SET_METHODS: &[&str] = &["add", "update"];
    let Expr::Name(name) = expr else {
        return None;
    };
    let assigned = single_assigned_value(scopes, name.id.as_str())?;
    let methods = match assigned {
        Expr::List(_) => LIST_METHODS,
        Expr::Dict(_) => DICT_METHODS,
        Expr::Call(call) => match call.func.as_ref() {
            Expr::Name(callee) if callee.id.as_str() == "list" => LIST_METHODS,
            Expr::Name(callee) if callee.id.as_str() == "dict" => DICT_METHODS,
            Expr::Name(callee) if callee.id.as_str() == "set" => SET_METHODS,
            _ => return None,
        },
        _ => return None,
    };
    Some(methods)
}

/// `collectSimpleAliasSymbols`: module-level `alias = name` assignments add
/// `alias` to the receiver set (one level, matching the reference).
fn collect_module_aliases<'a>(stmts: &'a [Stmt], name: &str, aliases: &mut Vec<&'a str>) {
    for stmt in stmts {
        if let Stmt::Assign(assign) = stmt
            && let Expr::Name(value) = assign.value.as_ref()
            && value.id.as_str() == name
        {
            for target in &assign.targets {
                if let Expr::Name(target) = target {
                    aliases.push(target.id.as_str());
                }
            }
        }
        if !matches!(stmt, Stmt::FunctionDef(_)) {
            for body in child_bodies(stmt) {
                collect_module_aliases(body, name, aliases);
            }
        }
    }
}

/// Visits every expression in module-level code: statements outside function
/// bodies, including class bodies (which execute at module level).
fn visit_module_exprs<'a>(stmts: &'a [Stmt], visit: &mut impl FnMut(&'a Expr)) {
    for stmt in stmts {
        if !matches!(stmt, Stmt::FunctionDef(_)) {
            for expr in stmt_exprs(stmt) {
                for_each_expr(expr, &mut *visit);
            }
            for body in child_bodies(stmt) {
                visit_module_exprs(body, visit);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan_test_file};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan_test_file(source), "python:S8998")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8998_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: an empty list literal anchors the
        // finding on the `[]` (line 4, columns 43-45).
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.mark.parametrize('operand,expected', [])\n",
            "def test_double(operand, expected):\n",
            "    assert double(operand) == expected\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(3, 45));
        assert_eq!(ranges[0].end, pos(3, 47));
    }

    #[test]
    fn s8998_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.mark.parametrize('operand,expected', [\n",
                "    (1, 2),\n",
                "    (2, 4),\n",
                "    (3, 6),\n",
                "    (0, 0),\n",
                "])\n",
                "def test_double(operand, expected):\n",
                "    assert double(operand) == expected\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8998_flags_every_empty_shape_and_the_keyword_form() {
        for source in [
            "@pytest.mark.parametrize('x', ())\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', {})\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', '')\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', 0)\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', None)\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', False)\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', list())\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', set())\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', range(0))\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', range(-2))\ndef test_t(x):\n    pass\n",
            "@pytest.mark.parametrize('x', argvalues=[])\ndef test_t(x):\n    pass\n",
        ] {
            assert_eq!(found(source).len(), 1, "{source}");
        }
    }

    #[test]
    fn s8998_flags_names_bound_to_empty_collections() {
        // A module-level name assigned an empty literal or empty constructor
        // is flagged on the name.
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "cases = []\n",
            "\n",
            "@pytest.mark.parametrize('x', cases)\n",
            "def test_t(x):\n",
            "    pass\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(5, 30));
        assert_eq!(ranges[0].end, pos(5, 35));

        assert_eq!(
            found(concat!(
                "import pytest\n",
                "\n",
                "cases = list()\n",
                "\n",
                "@pytest.mark.parametrize('x', cases)\n",
                "def test_t(x):\n",
                "    pass\n",
            ))
            .len(),
            1
        );
    }

    #[test]
    fn s8998_spares_populated_and_nonempty_collections() {
        // Module-level population through a mutating method — on the name or
        // a simple alias — suppresses the finding, as do non-empty values,
        // reassigned names, and non-parametrize decorators.
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "cases = []\n",
                "cases.append((1, 2))\n",
                "\n",
                "@pytest.mark.parametrize('x', cases)\n",
                "def test_t(x):\n",
                "    pass\n",
            ))
            .is_empty()
        );
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "cases = []\n",
                "more = cases\n",
                "more.extend([(1, 2)])\n",
                "\n",
                "@pytest.mark.parametrize('x', cases)\n",
                "def test_t(x):\n",
                "    pass\n",
            ))
            .is_empty()
        );
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "cases = []\n",
                "cases = [(1, 2)]\n",
                "\n",
                "@pytest.mark.parametrize('x', cases)\n",
                "def test_t(x):\n",
                "    pass\n",
            ))
            .is_empty()
        );
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.mark.parametrize('x', [1])\n",
                "def test_t(x):\n",
                "    pass\n",
                "\n",
                "@pytest.mark.skip\n",
                "def test_s():\n",
                "    pass\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8998_ignores_population_inside_function_bodies() {
        // Population inside a function body runs after collection, so the
        // empty module-level binding is still flagged.
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "cases = []\n",
            "\n",
            "def fill():\n",
            "    cases.append(1)\n",
            "\n",
            "@pytest.mark.parametrize('x', cases)\n",
            "def test_t(x):\n",
            "    pass\n",
        ));
        assert_eq!(ranges.len(), 1);
    }
}
