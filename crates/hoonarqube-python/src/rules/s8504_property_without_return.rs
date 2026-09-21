use ruff_python_ast::{Expr, ModModule, Stmt, StmtFunctionDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{
    NameResolver, NameValue, WebFrameworkFacts, child_bodies, child_exprs, issue_at, stmt_exprs,
};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8504";
const MESSAGE: &str = "Add a return statement to this property method.";

/// python:S8504 — a `@property` getter without any `return` statement
/// implicitly returns `None`, which is almost always a bug. The reference
/// flags the method's name when its body contains no `return`, no `yield`
/// (a generator property is a deliberate lazy accessor), and no `raise`
/// (an intentional "not supported" marker). Bodies made only of `pass`,
/// `...`, or docstring statements are stub/hook patterns and stay silent,
/// as do methods also decorated with `abc.abstractmethod` and methods
/// whose decorator is not the builtin `property` (`x.setter`,
/// `x.deleter`, `functools.cached_property`, a local `property`
/// shadowing). Returns, yields, and raises inside nested `def`s,
/// `class`es, or lambdas belong to the nested scope and do not count.
pub(crate) fn check_s8504_property_without_return(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let resolver = NameResolver::build(file_ctx);
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        if !is_property(function, &facts, &resolver) || is_abstract(function, &facts, &resolver) {
            continue;
        }
        if function.body.iter().all(is_empty_statement) {
            continue;
        }
        let body = BodyFacts::collect(&function.body);
        if !body.has_return && !body.has_yield && !body.has_raise {
            issues.push(issue_at(
                RULE_KEY,
                MESSAGE,
                function.name.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// Whether `function` is decorated with the builtin `property` (bare
/// decorator only — the reference matches the decorator expression's
/// type, so `@property(...)` calls and attribute decorators like
/// `@x.setter` never match).
fn is_property(
    function: &StmtFunctionDef,
    facts: &WebFrameworkFacts,
    resolver: &NameResolver,
) -> bool {
    function.decorator_list.iter().any(|decorator| {
        decorator_fqn(&decorator.expression, facts, resolver)
            .is_some_and(|fqn| fqn == "property" || fqn == "builtins.property")
    })
}

/// Whether `function` is decorated with `abc.abstractmethod`.
fn is_abstract(
    function: &StmtFunctionDef,
    facts: &WebFrameworkFacts,
    resolver: &NameResolver,
) -> bool {
    function.decorator_list.iter().any(|decorator| {
        decorator_fqn(&decorator.expression, facts, resolver)
            .is_some_and(|fqn| fqn == "abc.abstractmethod")
    })
}

/// The FQN of a bare decorator expression: import provenance via
/// [`WebFrameworkFacts::expr_fqn`], with a name the symbol table reports
/// unbound treated as the `builtins` member of the same spelling (a
/// `def`/`class`/parameter of the same spelling resolves `Ambiguous`, so
/// shadowing stays silent). Called decorators (`@decorator(...)`) resolve
/// to `None` — the reference matches the decorator expression itself, not
/// the call's callee.
fn decorator_fqn(
    expr: &Expr,
    facts: &WebFrameworkFacts,
    resolver: &NameResolver,
) -> Option<String> {
    if let Some(fqn) = facts.expr_fqn(expr) {
        return Some(fqn);
    }
    if let Expr::Name(name) = expr
        && matches!(resolver.resolve(expr), NameValue::Unbound)
    {
        return Some(format!("builtins.{}", name.id.as_str()));
    }
    None
}

/// The reference's `CheckUtils.isEmptyStatement`: `pass`, or an
/// expression statement whose expression is a string literal (docstring)
/// or `...`.
fn is_empty_statement(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Pass(_) => true,
        Stmt::Expr(expr) => matches!(
            expr.value.as_ref(),
            Expr::StringLiteral(_) | Expr::EllipsisLiteral(_)
        ),
        _ => false,
    }
}

/// Return/yield/raise facts of a function body, collected without
/// descending into nested `def`/`class` bodies — the reference's
/// `ReturnStmtCollector` skips nested function and lambda bodies the same
/// way (lambdas cannot contain `yield`, so expression descent is safe).
struct BodyFacts {
    has_return: bool,
    has_yield: bool,
    has_raise: bool,
}

impl BodyFacts {
    fn collect(body: &[Stmt]) -> Self {
        let mut facts = BodyFacts {
            has_return: false,
            has_yield: false,
            has_raise: false,
        };
        let mut pending: Vec<&Stmt> = body.iter().collect();
        while let Some(stmt) = pending.pop() {
            match stmt {
                Stmt::FunctionDef(_) | Stmt::ClassDef(_) => continue,
                Stmt::Return(_) => facts.has_return = true,
                Stmt::Raise(_) => facts.has_raise = true,
                _ => {}
            }
            for expr in stmt_exprs(stmt) {
                if scope_local_expr_has_yield(expr) {
                    facts.has_yield = true;
                }
            }
            pending.extend(child_bodies(stmt).into_iter().flat_map(|body| body.iter()));
        }
        facts
    }
}

/// Whether `expr` contains a `yield` outside lambda bodies: a lambda body
/// is its own function scope, so `yield` inside it belongs to the lambda
/// and does not make the enclosing property a generator.
fn scope_local_expr_has_yield(expr: &Expr) -> bool {
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        if matches!(expr, Expr::Lambda(_)) {
            continue;
        }
        if matches!(expr, Expr::Yield(_) | Expr::YieldFrom(_)) {
            return true;
        }
        pending.extend(child_exprs(expr).into_iter().rev());
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8504")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8504_flags_the_sonar_noncompliant_example() {
        let flagged = found(concat!(
            "class Rectangle:\n",
            "    @property\n",
            "    def area(self):\n",
            "        3.14159 * self._radius ** 2\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start, pos(3, 8));
        assert_eq!(flagged[0].range.end, pos(3, 12));
        assert_eq!(
            flagged[0].message,
            "Add a return statement to this property method."
        );
    }

    #[test]
    fn s8504_flags_bodies_without_any_return() {
        // Assignments, branches, loops, and prints without a return all
        // flag; a `return` nested in a helper `def` does not count.
        let flagged = found(concat!(
            "class C:\n",
            "    @property\n",
            "    def cached(self):\n",
            "        result = self._x * 2\n",
            "        self._y = result\n",
            "    @property\n",
            "    def branched(self):\n",
            "        if self._x:\n",
            "            value = 1\n",
            "        else:\n",
            "            value = 2\n",
            "    @property\n",
            "    def computed(self):\n",
            "        def helper():\n",
            "            return self._x * 2\n",
        ));
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[2].range.start, pos(13, 8));
    }

    #[test]
    fn s8504_flags_property_assigning_yield_lambda() {
        // The lambda is its own function scope: its `yield` does not make
        // the property a generator, and the getter still returns None.
        let flagged = found(concat!(
            "class C:\n",
            "    @property\n",
            "    def value(self):\n",
            "        self.factory = lambda: (yield 1)\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start, pos(3, 8));

        let control = found(concat!(
            "class C:\n",
            "    @property\n",
            "    def value(self):\n",
            "        self.factory = lambda: 1\n",
        ));
        assert_eq!(control.len(), 1);
    }

    #[test]
    fn s8504_accepts_return_raise_yield_and_stubs() {
        assert!(
            found(concat!(
                "class C:\n",
                "    @property\n",
                "    def a(self):\n",
                "        return self._x\n",
                "    @property\n",
                "    def b(self):\n",
                "        return\n",
                "    @property\n",
                "    def c(self):\n",
                "        raise NotImplementedError\n",
                "    @property\n",
                "    def d(self):\n",
                "        yield from self._data\n",
                "    @property\n",
                "    def e(self):\n",
                "        pass\n",
                "    @property\n",
                "    def f(self):\n",
                "        ...\n",
                "    @property\n",
                "    def g(self):\n",
                "        \"\"\"docstring.\"\"\"\n",
                "        ...\n",
                "    @property\n",
                "    def h(self):\n",
                "        try:\n",
                "            return self._x\n",
                "        except KeyError:\n",
                "            raise ValueError\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8504_accepts_abstract_and_non_property_decorators() {
        assert!(
            found(concat!(
                "import abc\n",
                "from abc import abstractmethod\n",
                "import functools\n",
                "\n",
                "class C:\n",
                "    @property\n",
                "    @abstractmethod\n",
                "    def a(self):\n",
                "        self._x = 0\n",
                "    @property\n",
                "    @abc.abstractmethod\n",
                "    def b(self):\n",
                "        self._x = 0\n",
                "    @functools.cached_property\n",
                "    def c(self):\n",
                "        self._x * 2\n",
                "    @property\n",
                "    def x(self):\n",
                "        return self._x\n",
                "    @x.setter\n",
                "    def x(self, value):\n",
                "        self._x = value\n",
                "    @x.deleter\n",
                "    def x(self):\n",
                "        del self._x\n",
            ))
            .is_empty()
        );
    }
}
