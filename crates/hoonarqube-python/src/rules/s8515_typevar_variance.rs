use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::{ImportFqns, WebFrameworkFacts};

const RULE_KEY: &str = "python:S8515";
const MESSAGE: &str = "Remove either \"covariant=True\" or \"contravariant=True\"; a TypeVar cannot be both covariant and contravariant.";
const TYPEVAR_FQNS: [&str; 2] = ["typing.TypeVar", "typing_extensions.TypeVar"];

/// python:S8515 — `TypeVar(..., covariant=True, contravariant=True)` raises
/// `ValueError` at import time because the two variance modes are mutually
/// exclusive. The finding anchors on the `TypeVar` callee, matching the
/// reference's `call.callee()` anchor.
pub(crate) fn check_s8515_typevar_variance(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let fqns = ImportFqns::build(file_ctx);
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if is_typevar_call(call, &fqns) && has_both_truthy_variances(call, &facts, source) {
            issues.push(issue_at(
                RULE_KEY,
                MESSAGE,
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// Whether `call` invokes `typing.TypeVar` or `typing_extensions.TypeVar`
/// through any import spelling (`TypeVar`, `typing.TypeVar`, aliases).
fn is_typevar_call(call: &ExprCall, fqns: &ImportFqns) -> bool {
    fqns.is_fqn_in(&call.func, &TYPEVAR_FQNS)
}

/// Both `covariant=` and `contravariant=` keywords are present and each
/// argument is truthy under the reference's `Expressions.isTruthy`: literal
/// truthiness plus names bound exactly once to a literal.
fn has_both_truthy_variances(call: &ExprCall, facts: &WebFrameworkFacts<'_>, source: &str) -> bool {
    let Some(covariant) = keyword_value(&call.arguments, "covariant") else {
        return false;
    };
    let Some(contravariant) = keyword_value(&call.arguments, "contravariant") else {
        return false;
    };
    is_truthy(covariant, facts, source) && is_truthy(contravariant, facts, source)
}

/// `Expressions.isTruthy`: a `Name` is truthy when it is `True` or bound
/// exactly once to a truthy literal; every other expression defers to the
/// literal check. Non-literal expressions (calls, subscripts, arithmetic)
/// are not provably truthy and stay silent.
fn is_truthy(expr: &Expr, facts: &WebFrameworkFacts<'_>, source: &str) -> bool {
    if let Expr::Name(name) = expr {
        if name.id.as_str() == "True" {
            return true;
        }
        return facts
            .single_assigned_value(name.id.as_str(), name.range())
            .is_some_and(|value| is_truthy_literal(value, source));
    }
    is_truthy_literal(expr, source)
}

/// Literal truthiness, mirroring `isTruthyInternal`/`isFalsyInternal`:
/// `True` is truthy; strings, numbers, lists, tuples, sets, and dicts are
/// truthy unless empty or the exact zero spellings `0`/`0.0`/`0j`. `False`
/// and `None` are not truthy; bytes literals are outside the reference's
/// truthy kinds.
fn is_truthy_literal(expr: &Expr, source: &str) -> bool {
    match expr {
        Expr::BooleanLiteral(boolean) => boolean.value,
        Expr::NoneLiteral(_) => false,
        Expr::StringLiteral(string) => !string.value.to_str().is_empty(),
        Expr::NumberLiteral(_) => {
            let text = source[expr.range()].trim();
            !matches!(text, "0" | "0.0" | "0j")
        }
        Expr::List(list) => !list.elts.is_empty(),
        Expr::Tuple(tuple) => !tuple.elts.is_empty(),
        Expr::Set(set) => !set.elts.is_empty(),
        Expr::Dict(dict) => !dict.items.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8515_flags_both_variances_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "from typing import TypeVar\n",
            "\n",
            "T = TypeVar('T', covariant=True, contravariant=True)  # Noncompliant\n",
        ));
        let found = findings(&flagged, "python:S8515");
        assert_eq!(found.len(), 1);
        // The anchor covers the `TypeVar` callee.
        assert_eq!(found[0].range.start, pos(3, 4));
        assert_eq!(found[0].range.end, pos(3, 11));
        assert_eq!(
            found[0].message,
            "Remove either \"covariant=True\" or \"contravariant=True\"; a TypeVar cannot be both covariant and contravariant."
        );
    }

    #[test]
    fn s8515_accepts_single_variance_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "from typing import TypeVar\n",
            "\n",
            "T_co = TypeVar('T_co', covariant=True)\n",
        ));
        assert!(findings(&clean, "python:S8515").is_empty());
    }

    #[test]
    fn s8515_flags_qualified_aliased_and_extension_spellings() {
        let flagged = scan(concat!(
            "import typing\n",
            "import typing_extensions\n",
            "from typing import TypeVar as TV\n",
            "from typing_extensions import TypeVar as ExtTV\n",
            "\n",
            "A = typing.TypeVar('A', covariant=True, contravariant=True)\n",
            "B = typing_extensions.TypeVar('B', covariant=True, contravariant=True)\n",
            "C = TV('C', covariant=True, contravariant=True)\n",
            "D = ExtTV('D', covariant=True, contravariant=True)\n",
        ));
        assert_eq!(findings(&flagged, "python:S8515").len(), 4);
    }

    #[test]
    fn s8515_flags_names_singly_bound_to_truthy_literals() {
        // `cov`/`contra` resolve through their single assignments, while
        // doubly-bound and falsy-bound names stay silent.
        let flagged = scan(concat!(
            "from typing import TypeVar\n",
            "\n",
            "cov = True\n",
            "contra = True\n",
            "T7 = TypeVar('T7', covariant=cov, contravariant=True)\n",
            "T8 = TypeVar('T8', covariant=True, contravariant=contra)\n",
            "T9 = TypeVar('T9', covariant=cov, contravariant=contra)\n",
        ));
        assert_eq!(findings(&flagged, "python:S8515").len(), 3);
    }

    #[test]
    fn s8515_accepts_falsy_rebound_and_unknown_arguments() {
        let clean = scan(concat!(
            "from typing import TypeVar\n",
            "\n",
            "T1 = TypeVar('T1', covariant=False, contravariant=False)\n",
            "T2 = TypeVar('T2', covariant=True, contravariant=False)\n",
            "T3 = TypeVar('T3', covariant=0, contravariant=True)\n",
            "T4 = TypeVar('T4', covariant=\"\", contravariant=True)\n",
            "T5 = TypeVar('T5', covariant=[], contravariant=True)\n",
            "T6 = TypeVar('T6', covariant=None, contravariant=True)\n",
            "T7 = TypeVar('T7', covariant=True)\n",
            "T8 = TypeVar('T8', contravariant=True)\n",
            "rebound = False\n",
            "rebound = True\n",
            "T9 = TypeVar('T9', covariant=rebound, contravariant=True)\n",
            "def flag():\n",
            "    return True\n",
            "T10 = TypeVar('T10', covariant=flag(), contravariant=True)\n",
            "T11 = TypeVar('T11', **{'covariant': True, 'contravariant': True})\n",
        ));
        assert!(findings(&clean, "python:S8515").is_empty());
    }

    #[test]
    fn s8515_flags_truthy_non_boolean_literals() {
        let flagged = scan(concat!(
            "from typing import TypeVar\n",
            "\n",
            "A = TypeVar('A', covariant=1, contravariant=1)\n",
            "B = TypeVar('B', covariant=\"yes\", contravariant=True)\n",
            "C = TypeVar('C', covariant=[1], contravariant=True)\n",
            "D = TypeVar('D', covariant=(1,), contravariant=True)\n",
            "E = TypeVar('E', covariant={1: 2}, contravariant=True)\n",
            "F = TypeVar('F', covariant={1, 2}, contravariant=True)\n",
        ));
        assert_eq!(findings(&flagged, "python:S8515").len(), 6);
    }

    #[test]
    fn s8515_ignores_unrelated_calls_with_same_keywords() {
        let clean = scan(concat!(
            "def my_func(name, covariant=False, contravariant=False):\n",
            "    pass\n",
            "\n",
            "my_func('X', covariant=True, contravariant=True)\n",
        ));
        assert!(findings(&clean, "python:S8515").is_empty());
    }
}
