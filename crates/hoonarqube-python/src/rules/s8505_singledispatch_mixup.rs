use ruff_python_ast::{Expr, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{NameResolver, NameValue, WebFrameworkFacts, for_each_function_def, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8505";
const MSG_USE_SINGLEDISPATCHMETHOD: &str = "Use \"@singledispatchmethod\" instead of \"@singledispatch\" on methods defined in a class body.";
const MSG_USE_SINGLEDISPATCH: &str =
    "Use \"@singledispatch\" instead of \"@singledispatchmethod\" on standalone functions.";

/// python:S8505 — `functools.singledispatch` dispatches on the first
/// positional argument, so on a method it dispatches on `self`/`cls` and
/// the registered implementations are never selected; applied to a
/// `@classmethod` it wraps the descriptor and fails at call time, and
/// placed above `@staticmethod` it wraps the `staticmethod` descriptor
/// (the inverse order — `@staticmethod` above `@singledispatch` — is the
/// one valid combination). `functools.singledispatchmethod` returns a
/// non-callable descriptor, so on a standalone function it can never be
/// invoked. The reference flags the offending decorator: `@singledispatch`
/// on a method unless an earlier decorator is `@staticmethod`, and
/// `@singledispatchmethod` on anything that is not a method (module-level
/// functions and functions nested inside other functions — a `def` inside
/// a method body is not a method). Called decorators (`@singledispatch()`)
/// and unresolvable spellings stay silent.
pub(crate) fn check_s8505_singledispatch_mixup(
    parsed: &ruff_python_parser::Parsed<ruff_python_ast::ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let resolver = NameResolver::build(parsed, source);
    let mut issues = Vec::new();
    let mut visit = |function: &StmtFunctionDef, is_method: bool| {
        for (position, decorator) in function.decorator_list.iter().enumerate() {
            let Some(fqn) = decorator_fqn(&decorator.expression, &facts, &resolver) else {
                continue;
            };
            if fqn == "functools.singledispatch" {
                if is_method
                    && !wrapped_by_outer_staticmethod(function, position, &facts, &resolver)
                {
                    issues.push(issue_at(
                        RULE_KEY,
                        MSG_USE_SINGLEDISPATCHMETHOD,
                        decorator.range(),
                        index,
                        source,
                    ));
                }
            } else if fqn == "functools.singledispatchmethod" && !is_method {
                issues.push(issue_at(
                    RULE_KEY,
                    MSG_USE_SINGLEDISPATCH,
                    decorator.range(),
                    index,
                    source,
                ));
            }
        }
    };
    for_each_function_def(parsed.syntax().body.as_slice(), false, &mut visit);
    issues
}

/// Whether a decorator before position `index` is `@staticmethod` — the
/// only order in which `@singledispatch` wraps a plain function instead
/// of a descriptor.
fn wrapped_by_outer_staticmethod(
    function: &StmtFunctionDef,
    index: usize,
    facts: &WebFrameworkFacts,
    resolver: &NameResolver,
) -> bool {
    function.decorator_list[..index].iter().any(|decorator| {
        decorator_fqn(&decorator.expression, facts, resolver)
            .is_some_and(|fqn| fqn == "staticmethod" || fqn == "builtins.staticmethod")
    })
}

/// The FQN of a bare decorator expression: import provenance via
/// [`WebFrameworkFacts::expr_fqn`], with a name the symbol table reports
/// unbound treated as the `builtins` member of the same spelling (a
/// `def`/`class`/parameter of the same spelling resolves `Ambiguous`, so
/// shadowing stays silent). Called decorators (`@singledispatch(...)`)
/// resolve to `None` — the reference matches the decorator expression
/// itself, not the call's callee.
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

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8505")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8505_flags_singledispatch_on_methods() {
        // Sonar's Noncompliant examples: `@singledispatch` on an instance
        // method, above `@staticmethod`, and above `@classmethod`.
        let flagged = found(concat!(
            "from functools import singledispatch, singledispatchmethod\n",
            "\n",
            "class WithSingledispatch:\n",
            "    @singledispatch\n",
            "    def process(self, data):\n",
            "        pass\n",
            "\n",
            "class WithWrongStaticmethodOrder:\n",
            "    @singledispatch\n",
            "    @staticmethod\n",
            "    def handle(data):\n",
            "        pass\n",
            "\n",
            "class WithClassmethodAndSingledispatch:\n",
            "    @singledispatch\n",
            "    @classmethod\n",
            "    def handle(cls, data):\n",
            "        pass\n",
        ));
        assert_eq!(flagged.len(), 3);
        // The issue anchors on the whole decorator including `@`.
        assert_eq!(flagged[0].range.start, pos(4, 4));
        assert_eq!(flagged[0].range.end, pos(4, 19));
        assert_eq!(
            flagged[0].message,
            "Use \"@singledispatchmethod\" instead of \"@singledispatch\" on methods defined in a class body."
        );
    }

    #[test]
    fn s8505_flags_singledispatchmethod_on_standalone_functions() {
        let flagged = found(concat!(
            "from functools import singledispatchmethod\n",
            "\n",
            "@singledispatchmethod\n",
            "def process_standalone(data):\n",
            "    pass\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start, pos(3, 0));
        assert_eq!(flagged[0].range.end, pos(3, 21));
        assert_eq!(
            flagged[0].message,
            "Use \"@singledispatch\" instead of \"@singledispatchmethod\" on standalone functions."
        );
    }

    #[test]
    fn s8505_accepts_correct_pairings_and_nested_functions() {
        assert!(
            found(concat!(
                "from functools import singledispatch, singledispatchmethod\n",
                "\n",
                "@singledispatch\n",
                "def compliant_standalone(data):\n",
                "    pass\n",
                "\n",
                "class WithSingledispatchmethod:\n",
                "    @singledispatchmethod\n",
                "    def process(self, data):\n",
                "        pass\n",
                "\n",
                "class WithValidStaticmethodOrder:\n",
                "    @staticmethod\n",
                "    @singledispatch\n",
                "    def process(data):\n",
                "        pass\n",
                "\n",
                "class WithSingledispatchmethodAndClassmethod:\n",
                "    @singledispatchmethod\n",
                "    @classmethod\n",
                "    def process(cls, data):\n",
                "        pass\n",
                "\n",
                "class WithNestedFunction:\n",
                "    def outer(self):\n",
                "        @singledispatch\n",
                "        def inner(data):\n",
                "            pass\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8505_accepts_shadowed_and_unrelated_decorators() {
        // A local `singledispatch` is not `functools.singledispatch`, and
        // unrelated decorators never flag.
        assert!(
            found(concat!(
                "def singledispatch(fn):\n",
                "    return fn\n",
                "\n",
                "class C:\n",
                "    @singledispatch\n",
                "    def process(self, data):\n",
                "        pass\n",
                "    @classmethod\n",
                "    def other(cls):\n",
                "        pass\n",
            ))
            .is_empty()
        );
    }
}
