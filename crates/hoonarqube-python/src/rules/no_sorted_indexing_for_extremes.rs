use crate::engine::file_context::FileContext;
use crate::support::int_literal_value;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, UnaryOp};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S8517";

/// python:S8517 — `sorted(iterable)[0]` and `sorted(iterable)[-1]` sort the
/// whole collection to read one extreme; `min()`/`max()` do it in one pass.
/// The `reverse=` keyword flips the replacement: `sorted(x, reverse=True)[0]`
/// is `max(x)`, `sorted(x, reverse=True)[-1]` is `min(x)`. A `reverse=`
/// argument that is neither a provably truthy nor a provably falsy literal
/// keeps the finding silent, matching the reference's constant check. The
/// whole subscript expression anchors the finding.
pub(crate) fn check_no_sorted_indexing_for_extremes(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Subscript(subscript) = expr else {
            continue;
        };
        let Some(index_is_zero) = zero_or_minus_one(&subscript.slice) else {
            continue;
        };
        let Expr::Call(call) = subscript.value.as_ref() else {
            continue;
        };
        if !matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "sorted") {
            continue;
        }
        let Some(reversed) = reversed_flag(call) else {
            continue;
        };
        let replacement = if index_is_zero == reversed {
            "max"
        } else {
            "min"
        };
        issues.push(issue_at(
            RULE_KEY,
            &format!("Use \"{replacement}()\" instead of sorting to find this value."),
            subscript.range(),
            index,
            source,
        ));
    }
    issues
}

/// `Some(true)` for `[0]`, `Some(false)` for `[-1]`, `None` for any other
/// subscript shape (slices, tuples, names, calls).
fn zero_or_minus_one(slice: &Expr) -> Option<bool> {
    if int_literal_value(slice) == Some(0) {
        return Some(true);
    }
    if let Expr::UnaryOp(unary) = slice
        && unary.op == UnaryOp::USub
        && int_literal_value(&unary.operand) == Some(1)
    {
        return Some(false);
    }
    None
}

/// `Some` truth value of the `reverse=` keyword when it is a provably
/// constant literal; `Some(false)` when the keyword is absent; `None` when
/// the value is not a decidable literal.
fn reversed_flag(call: &ExprCall) -> Option<bool> {
    let Some(keyword) = call.arguments.find_keyword("reverse") else {
        return Some(false);
    };
    if is_truthy_literal(&keyword.value) {
        return Some(true);
    }
    if is_falsy_literal(&keyword.value) {
        return Some(false);
    }
    None
}

/// Literal-level truthiness matching Sonar's `Expressions.isTruthy`.
fn is_truthy_literal(expr: &Expr) -> bool {
    match expr {
        Expr::BooleanLiteral(literal) => literal.value,
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64() != Some(0),
            ruff_python_ast::Number::Float(value) => *value != 0.0,
            ruff_python_ast::Number::Complex { real, imag } => *real != 0.0 || *imag != 0.0,
        },
        Expr::StringLiteral(literal) => literal.value.iter().any(|part| !part.value.is_empty()),
        Expr::BytesLiteral(literal) => literal.value.iter().any(|part| !part.value.is_empty()),
        Expr::FString(_) | Expr::EllipsisLiteral(_) => true,
        Expr::List(list) => !list.elts.is_empty(),
        Expr::Tuple(tuple) => !tuple.elts.is_empty(),
        Expr::Set(set) => !set.elts.is_empty(),
        Expr::Dict(dict) => !dict.items.is_empty(),
        Expr::UnaryOp(unary) => {
            matches!(unary.op, UnaryOp::UAdd | UnaryOp::USub) && is_truthy_literal(&unary.operand)
        }
        _ => false,
    }
}

/// Literal-level falsiness matching Sonar's `Expressions.isFalsy`.
fn is_falsy_literal(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_) => true,
        Expr::BooleanLiteral(literal) => !literal.value,
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64() == Some(0),
            ruff_python_ast::Number::Float(value) => *value == 0.0,
            ruff_python_ast::Number::Complex { real, imag } => *real == 0.0 && *imag == 0.0,
        },
        Expr::StringLiteral(literal) => literal.value.iter().all(|part| part.value.is_empty()),
        Expr::BytesLiteral(literal) => literal.value.iter().all(|part| part.value.is_empty()),
        Expr::List(list) => list.elts.is_empty(),
        Expr::Tuple(tuple) => tuple.elts.is_empty(),
        Expr::Set(set) => set.elts.is_empty(),
        Expr::Dict(dict) => dict.items.is_empty(),
        Expr::UnaryOp(unary) => {
            matches!(unary.op, UnaryOp::UAdd | UnaryOp::USub) && is_falsy_literal(&unary.operand)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8517")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8517_flags_sonar_noncompliant_examples() {
        // Sonar's own Noncompliant examples: plain [0], plain [-1], and
        // reverse=True with [0].
        let flagged = found(concat!(
            "numbers = [42, 17, 93, 8, 51]\n",
            "smallest = sorted(numbers)[0]\n",
            "largest = sorted(numbers)[-1]\n",
            "largest = sorted(numbers, reverse=True)[0]\n",
        ));
        assert_eq!(flagged.len(), 3);
        assert_eq!(
            flagged[0].message,
            "Use \"min()\" instead of sorting to find this value."
        );
        assert_eq!(flagged[0].range.start, pos(2, 11));
        assert_eq!(flagged[0].range.end, pos(2, 29));
        assert_eq!(
            flagged[1].message,
            "Use \"max()\" instead of sorting to find this value."
        );
        assert_eq!(
            flagged[2].message,
            "Use \"max()\" instead of sorting to find this value."
        );
    }

    #[test]
    fn s8517_reverse_true_with_minus_one_maps_to_min() {
        let flagged = found("smallest = sorted(numbers, reverse=True)[-1]\n");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Use \"min()\" instead of sorting to find this value."
        );
    }

    #[test]
    fn s8517_flags_key_and_falsy_reverse_variants() {
        // `key=` does not change the mapping; `reverse=False` behaves like
        // an absent keyword.
        let flagged = found(concat!(
            "low = sorted(items, key=len)[0]\n",
            "high = sorted(items, reverse=False)[-1]\n",
        ));
        assert_eq!(flagged.len(), 2);
        assert_eq!(
            flagged[0].message,
            "Use \"min()\" instead of sorting to find this value."
        );
        assert_eq!(
            flagged[1].message,
            "Use \"max()\" instead of sorting to find this value."
        );
    }

    #[test]
    fn s8517_stays_silent_on_compliant_and_undecidable_shapes() {
        // Sonar's Compliant solutions plus controls: other indexes, slices,
        // non-sorted calls, and a non-constant reverse flag.
        let clean = concat!(
            "numbers = [42, 17, 93, 8, 51]\n",
            "smallest = min(numbers)\n",
            "largest = max(numbers)\n",
            "second = sorted(numbers)[1]\n",
            "head = sorted(numbers)[0:2]\n",
            "first = numbers[0]\n",
            "picked = order(numbers)[0]\n",
            "maybe = sorted(numbers, reverse=flag)[0]\n",
        );
        assert!(found(clean).is_empty());
    }
}
