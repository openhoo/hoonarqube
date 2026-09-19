use ruff_python_ast::{Expr, ExprCall, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{NameResolver, NameValue, WebFrameworkFacts, issue_at, keyword_argument};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8508";
const MESSAGE: &str = "Replace this mutable value with an immutable default to avoid shared state.";

/// Mutable-constructor FQNs the reference's `IS_MUTABLE_CONSTRUCTOR`
/// matcher accepts.
const MUTABLE_CONSTRUCTOR_FQNS: &[&str] = &[
    "builtins.list",
    "builtins.dict",
    "builtins.set",
    "builtins.bytearray",
];

/// python:S8508 — `dict.fromkeys(keys, value)` points every key at the
/// same `value` object, and `ContextVar('v', default=value)` shares the
/// default across all contexts, so a mutable default silently couples
/// unrelated state. The reference flags the mutable argument: for
/// `dict.fromkeys` only the second positional argument (a keyword
/// `value=` is not inspected), for `ContextVar` only the `default`
/// keyword. Mutable shapes are `[]`/`{}`/`{…}` literals and calls to the
/// `list`/`dict`/`set`/`bytearray` builtins; a name flags when every
/// assignment binding that can reach it resolves to a mutable shape (the
/// reference's `valuesAtLocation` all-match). The `fromkeys` qualifier
/// must be dict-typed — the `dict` builtin, a dict literal, or a name
/// provably bound to one — so `MyMapping.fromkeys` and local `ContextVar`
/// classes stay silent, as do immutable defaults, `frozenset`, tuples,
/// and arbitrary call results.
pub(crate) fn check_s8508_mutable_default_values(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let resolver = NameResolver::build(parsed, source);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if is_dict_fromkeys(call, &facts, &resolver) {
            // Only the second positional argument is inspected; a keyword
            // `value=` or a starred argument is out of scope.
            if let Some(value) = call.arguments.args.get(1)
                && !matches!(value, Expr::Starred(_))
                && is_mutable_value(value, &facts, &resolver, 0)
            {
                issues.push(issue_at(RULE_KEY, MESSAGE, value.range(), index, source));
            }
        } else if facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| fqn == "contextvars.ContextVar")
            && let Some(default) = keyword_argument(call, "default")
            && is_mutable_value(default, &facts, &resolver, 0)
        {
            issues.push(issue_at(RULE_KEY, MESSAGE, default.range(), index, source));
        }
    }
    issues
}

/// Whether `call` is `X.fromkeys(...)` where `X` is dict-typed — the
/// reference's `isType("builtins.dict")` on the qualifier.
fn is_dict_fromkeys(call: &ExprCall, facts: &WebFrameworkFacts, resolver: &NameResolver) -> bool {
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return false;
    };
    attribute.attr.as_str() == "fromkeys" && is_dict_type(&attribute.value, facts, resolver, 0)
}

/// Whether `expr` is provably dict-typed: a dict literal, a `dict(...)`
/// call, or a name resolving to one of those (imported `builtins.dict`
/// aliases like `from builtins import dict as d` resolve through import
/// provenance).
fn is_dict_type(
    expr: &Expr,
    facts: &WebFrameworkFacts,
    resolver: &NameResolver,
    depth: u32,
) -> bool {
    if depth > 8 {
        return false;
    }
    match expr {
        Expr::Dict(_) => true,
        Expr::Call(call) => {
            callee_fqn(&call.func, facts, resolver).is_some_and(|fqn| fqn == "builtins.dict")
        }
        Expr::Name(_) => {
            if type_fqn(expr, facts, resolver, depth).is_some_and(|fqn| fqn == "builtins.dict") {
                return true;
            }
            match resolver.resolve(expr) {
                NameValue::Single(value) => is_dict_type(value, facts, resolver, depth + 1),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Whether `expr` is a mutable default shape: a `[]`/`{}`/`{…}` literal,
/// a call to a mutable builtin constructor, or a name whose every
/// reachable assignment value is mutable.
fn is_mutable_value(
    expr: &Expr,
    facts: &WebFrameworkFacts,
    resolver: &NameResolver,
    depth: u32,
) -> bool {
    if depth > 8 {
        return false;
    }
    match expr {
        Expr::List(_) | Expr::Dict(_) | Expr::Set(_) => true,
        Expr::Call(call) => callee_fqn(&call.func, facts, resolver)
            .is_some_and(|fqn| MUTABLE_CONSTRUCTOR_FQNS.contains(&fqn.as_str())),
        Expr::Name(_) => {
            let values = resolver.resolve_all(expr);
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| is_mutable_value(value, facts, resolver, depth + 1))
        }
        _ => false,
    }
}

/// The FQN of a callee expression: import provenance via
/// [`WebFrameworkFacts::expr_fqn`], with a name the symbol table reports
/// unbound treated as the `builtins` member of the same spelling (a
/// `def`/`class`/parameter of the same spelling resolves `Ambiguous`, so
/// shadowing stays silent).
fn callee_fqn(expr: &Expr, facts: &WebFrameworkFacts, resolver: &NameResolver) -> Option<String> {
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

/// The FQN of a type expression: import provenance first, then the
/// `builtins` fallback for unbound names, then a single-assignment hop so
/// `d = dict; d.fromkeys(...)` still resolves.
fn type_fqn(
    expr: &Expr,
    facts: &WebFrameworkFacts,
    resolver: &NameResolver,
    depth: u32,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    if let Some(fqn) = facts.expr_fqn(expr) {
        return Some(fqn);
    }
    if let Expr::Name(name) = expr {
        match resolver.resolve(expr) {
            NameValue::Unbound => {
                return Some(format!("builtins.{}", name.id.as_str()));
            }
            NameValue::Single(value) => return type_fqn(value, facts, resolver, depth + 1),
            NameValue::Ambiguous => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8508")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8508_flags_the_sonar_noncompliant_examples() {
        let flagged = found(concat!(
            "from contextvars import ContextVar\n",
            "keys = ['a', 'b', 'c']\n",
            "my_dict = dict.fromkeys(keys, [])\n",
            "my_var = ContextVar('my_var', default=[])\n",
        ));
        assert_eq!(flagged.len(), 2);
        // The `[]` argument of `dict.fromkeys` (line 3, columns 30-32).
        assert_eq!(flagged[0].range.start, pos(3, 30));
        assert_eq!(flagged[0].range.end, pos(3, 32));
        assert_eq!(
            flagged[0].message,
            "Replace this mutable value with an immutable default to avoid shared state."
        );
        // The `[]` default of `ContextVar` (line 4, columns 38-40).
        assert_eq!(flagged[1].range.start, pos(4, 38));
        assert_eq!(flagged[1].range.end, pos(4, 40));
    }

    #[test]
    fn s8508_flags_every_mutable_shape() {
        let flagged = found(concat!(
            "from contextvars import ContextVar\n",
            "keys = ['a', 'b', 'c']\n",
            "a = dict.fromkeys(keys, {})\n",
            "b = dict.fromkeys(keys, {1, 2, 3})\n",
            "c = dict.fromkeys(keys, list())\n",
            "d = dict.fromkeys(keys, dict())\n",
            "e = dict.fromkeys(keys, set())\n",
            "f = dict.fromkeys(keys, bytearray())\n",
            "g = dict.fromkeys(keys, [1, 2, 3])\n",
            "h = dict.fromkeys(keys, {'x': 1})\n",
            "i = dict.fromkeys(keys, bytearray(b'abc'))\n",
            "j = ContextVar('v', default={})\n",
            "k = ContextVar('v', default={1, 2})\n",
            "l = ContextVar('v', default=list())\n",
            "m = ContextVar('v', default=dict())\n",
            "n = ContextVar('v', default=set())\n",
            "o = ContextVar('v', default=bytearray())\n",
            "p = ContextVar('v', default=[1, 2, 3])\n",
        ));
        assert_eq!(flagged.len(), 16);
    }

    #[test]
    fn s8508_flags_variable_defaults_when_all_values_are_mutable() {
        // The reference's `valuesAtLocation` all-match: a name flags when
        // every assignment binding resolves to a mutable shape, including
        // both branches of a conditional.
        let flagged = found(concat!(
            "from contextvars import ContextVar\n",
            "def f(some_condition):\n",
            "    keys = ['a', 'b', 'c']\n",
            "    default_value = []\n",
            "    a = dict.fromkeys(keys, default_value)\n",
            "    initial = []\n",
            "    b = ContextVar('v', default=initial)\n",
            "    if some_condition:\n",
            "        branch = []\n",
            "    else:\n",
            "        branch = {}\n",
            "    c = dict.fromkeys(keys, branch)\n",
        ));
        assert_eq!(flagged.len(), 3);
    }

    #[test]
    fn s8508_accepts_immutable_and_unprovable_defaults() {
        assert!(
            found(concat!(
                "from contextvars import ContextVar\n",
                "def f(some_condition, some_function):\n",
                "    keys = ['a', 'b', 'c']\n",
                "    a = dict.fromkeys(keys)\n",
                "    b = dict.fromkeys(keys, None)\n",
                "    c = dict.fromkeys(keys, \"default\")\n",
                "    d = dict.fromkeys(keys, 0)\n",
                "    e = dict.fromkeys(keys, (1, 2, 3))\n",
                "    f = dict.fromkeys(keys, frozenset({1, 2, 3}))\n",
                "    g = dict.fromkeys(keys, some_function())\n",
                "    h = dict.fromkeys(keys, ([],))\n",
                "    i = dict.fromkeys(keys, sorted([3, 1, 2]))\n",
                "    j = ContextVar('v')\n",
                "    k = ContextVar('v', default=None)\n",
                "    l = ContextVar('v', default=\"initial\")\n",
                "    m = ContextVar('v', default=0)\n",
                "    n = ContextVar('v', default=(1, 2, 3))\n",
                "    o = ContextVar('v', default=frozenset({1, 2}))\n",
                "    p = ContextVar('v', default=some_function())\n",
                "    if some_condition:\n",
                "        mixed = []\n",
                "    else:\n",
                "        mixed = None\n",
                "    q = dict.fromkeys(keys, mixed)\n",
                "    immutable = 0\n",
                "    r = dict.fromkeys(keys, immutable)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8508_accepts_keyword_second_arg_and_non_dict_qualifiers() {
        assert!(
            found(concat!(
                "from contextvars import ContextVar\n",
                "def f():\n",
                "    keys = ['a', 'b', 'c']\n",
                "    a = dict.fromkeys(keys, value=[])\n",
                "    args = (keys, [])\n",
                "    b = dict.fromkeys(*args)\n",
                "    c = ContextVar('v', [])\n",
                "    class MyMapping:\n",
                "        @classmethod\n",
                "        def fromkeys(cls, keys, value=None):\n",
                "            return {}\n",
                "    d = MyMapping.fromkeys(['a', 'b'], [])\n",
                "    class ContextVar:\n",
                "        def __init__(self, name, default=None):\n",
                "            pass\n",
                "    e = ContextVar('v', default=[])\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8508_flags_aliased_dict_and_qualified_contextvar() {
        // `from builtins import dict as d` keeps the `builtins.dict` FQN,
        // and `contextvars.ContextVar` resolves through the module import.
        let flagged = found(concat!(
            "import contextvars\n",
            "from builtins import dict as d\n",
            "keys = range(5)\n",
            "a = d.fromkeys(keys, [])\n",
            "b = contextvars.ContextVar('v', default=[])\n",
        ));
        assert_eq!(flagged.len(), 2);
    }
}
