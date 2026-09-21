use ruff_python_ast::{CmpOp, Expr, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::{NameResolver, NameValue, WebFrameworkFacts, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8503";
const MESSAGE: &str =
    "Remove this membership test on an empty collection; it will always be the same value.";

/// Empty-collection constructor FQNs the reference's
/// `EMPTY_COLLECTION_CONSTRUCTOR` matcher accepts (`builtins.set`,
/// `builtins.tuple`, `builtins.frozenset`; `list()`/`dict()` are
/// deliberately not covered).
const EMPTY_CONSTRUCTOR_FQNS: &[&str] = &["builtins.set", "builtins.tuple", "builtins.frozenset"];

/// python:S8503 — `x in []` is always `False` and `x not in []` always
/// `True`, so a membership test on a provably empty collection is dead
/// code or an incomplete implementation. The reference flags the right
/// operand of every `in`/`not in` comparison when it is an empty `[]`,
/// `{}`, or `()` literal or a no-argument `set()`/`tuple()`/`frozenset()`
/// call. The issue anchors on the membership expression from the left
/// operand through the empty comparator (chained comparisons flag each
/// empty comparator pair, matching the reference's nested `InExpression`
/// trees). Non-empty literals, constructor calls with arguments,
/// `list()`/`dict()`, names, and shadowed builtins stay silent.
pub(crate) fn check_s8503_empty_collection_membership(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let resolver = NameResolver::build(file_ctx);
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Compare(compare) = expr else {
            continue;
        };
        let mut left = compare.left.as_ref();
        for (op, comparator) in compare.ops.iter().zip(compare.comparators.iter()) {
            if matches!(op, CmpOp::In | CmpOp::NotIn)
                && is_empty_collection(comparator, &facts, &resolver)
            {
                issues.push(issue_at(
                    RULE_KEY,
                    MESSAGE,
                    TextRange::new(left.range().start(), comparator.range().end()),
                    index,
                    source,
                ));
            }
            left = comparator;
        }
    }
    issues
}

/// Whether `expr` is a provably empty collection: an empty `[]`/`{}`/`()`
/// literal or a no-argument call to `set`/`tuple`/`frozenset` resolved to
/// the builtin (a locally bound or imported name of the same spelling is
/// not the builtin).
fn is_empty_collection(expr: &Expr, facts: &WebFrameworkFacts, resolver: &NameResolver) -> bool {
    match expr {
        Expr::List(list) => list.elts.is_empty(),
        Expr::Dict(dict) => dict.items.is_empty(),
        Expr::Tuple(tuple) => tuple.elts.is_empty(),
        Expr::Call(call) => {
            if !call.arguments.args.is_empty() || !call.arguments.keywords.is_empty() {
                return false;
            }
            callee_fqn(&call.func, facts, resolver)
                .is_some_and(|fqn| EMPTY_CONSTRUCTOR_FQNS.contains(&fqn.as_str()))
        }
        _ => false,
    }
}

/// The FQN of a callee expression: import provenance via
/// [`WebFrameworkFacts::expr_fqn`], with a name the symbol table reports
/// unbound treated as the `builtins` member of the same spelling (the
/// reference's type inference resolves unshadowed builtins the same way;
/// a `def`/`class`/parameter of the same spelling resolves `Ambiguous`,
/// not `Unbound`, so shadowing stays silent).
fn callee_fqn(expr: &Expr, facts: &WebFrameworkFacts, resolver: &NameResolver) -> Option<String> {
    if let Some(fqn) = facts.expr_fqn(expr) {
        return Some(fqn);
    }
    if matches!(expr, Expr::Name(_)) && matches!(resolver.resolve(expr), NameValue::Unbound) {
        let Expr::Name(name) = expr else { return None };
        return Some(format!("builtins.{}", name.id.as_str()));
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8503")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8503_flags_empty_literal_membership_tests() {
        // Sonar's Noncompliant examples: `in`/`not in` on `[]`, `{}`, `()`.
        let flagged = found(concat!(
            "def f(x):\n",
            "    if x in []: ...\n",
            "    if x in {}: ...\n",
            "    if x in (): ...\n",
            "    if x not in []: ...\n",
            "    if x not in {}: ...\n",
            "    if x not in (): ...\n",
        ));
        assert_eq!(flagged.len(), 6);
        // `x in []` on line 2 spans columns 7-14.
        assert_eq!(flagged[0].range.start, pos(2, 7));
        assert_eq!(flagged[0].range.end, pos(2, 14));
        assert_eq!(
            flagged[0].message,
            "Remove this membership test on an empty collection; it will always be the same value."
        );
        // `x not in []` on line 5 spans columns 7-18.
        assert_eq!(flagged[3].range.start, pos(5, 7));
        assert_eq!(flagged[3].range.end, pos(5, 18));
    }

    #[test]
    fn s8503_flags_empty_constructor_calls() {
        let flagged = found(concat!(
            "def f(x):\n",
            "    if x in set(): ...\n",
            "    if x in tuple(): ...\n",
            "    if x in frozenset(): ...\n",
            "    if x not in set(): ...\n",
        ));
        assert_eq!(flagged.len(), 4);
        assert_eq!(flagged[0].range.start, pos(2, 7));
        assert_eq!(flagged[0].range.end, pos(2, 17));
    }

    #[test]
    fn s8503_flags_membership_outside_conditions() {
        // The rule fires on any membership test, not only conditions.
        let flagged = found(concat!(
            "def f(x):\n",
            "    result = x in []\n",
            "    flag = x not in set()\n",
            "    values = [y for y in range(10) if y in ()]\n",
        ));
        assert_eq!(flagged.len(), 3);
    }

    #[test]
    fn s8503_accepts_non_empty_and_uncovered_shapes() {
        assert!(
            found(concat!(
                "def f(x, values, iterable, p1, p2):\n",
                "    if x in [1, 2, 3]: ...\n",
                "    if x in {\"a\": 1}: ...\n",
                "    if x in {1, 2}: ...\n",
                "    if x in (1,): ...\n",
                "    if x in set(iterable): ...\n",
                "    if x in tuple(iterable): ...\n",
                "    if x in frozenset(iterable): ...\n",
                "    if x in list(): ...\n",
                "    if x in dict(): ...\n",
                "    if x in values: ...\n",
                "    my_list = []\n",
                "    if x in my_list: ...\n",
                "    if x in [*p1, *p2]: ...\n",
                "    if x in {**p1}: ...\n",
                "    if x in {*p1}: ...\n",
                "    if x in (*p1,): ...\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8503_accepts_shadowed_builtins() {
        // A user-defined `set` is not `builtins.set`.
        assert!(
            found(concat!(
                "def f(x):\n",
                "    def set():\n",
                "        return [1, 2]\n",
                "    if x in set(): ...\n",
            ))
            .is_empty()
        );
    }
}
