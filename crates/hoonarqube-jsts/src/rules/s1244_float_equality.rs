// Rule module s1244_float_equality (generated).
//
// `javascript:S1244` + `typescript:S1244` — floating point numbers should
// not be tested for equality. Reference semantics: the SonarJS-owned rule
// (packages/analysis/src/jsts/rules/S1244): "Do not check floating point
// equality or inequality with exact values, use a range instead." is
// reported on
//
// - `===`, `!==`, `==`, `!=` binary expressions where either operand is
//   floating-point-sensitive;
// - `a <= t && a >= t` / `a < t || a > t` logical pairs that collapse to
//   an exact equality/inequality when the compared expression or the
//   threshold is floating-point-sensitive (the reference
//   `isIndirectExactComparison` with token equivalence);
// - test-framework comparison assertions (`expect(x).toBe(y)`,
//   `assert.strictEqual`, chai `equal`/`eql`, …) whose actual or expected
//   is floating-point-sensitive, reported on the assertion's report node;
// - `switch` case tests that are floating-point-sensitive.
//
// Floating-point-sensitive means: a decimal/exponent numeric literal not
// exactly representable as a binary fraction; `+`/`-` unary on a
// sensitive operand; `+`/`-`/`*`/`%`/`**` arithmetic with a sensitive
// operand; `/` division with a sensitive operand or between integer
// literals whose result is a non-exactly-representable fraction; and
// `const` bindings whose initializer is sensitive. Constant expressions
// that evaluate to a safe integer are not sensitive. The reference's
// token equivalence is approximated by whitespace-stripped source text.

use crate::context::AnalysisContext;
use crate::rules::test_assertions::{
    AssertionKind, collect_file_imports, extract_test_assertion,
};
use crate::support::{IssueSink, RuleScope, span_text, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{BinaryOperator, Expression, LogicalOperator, UnaryOperator};
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};
use oxc_syntax::symbol::SymbolId;
use std::collections::HashSet;

/// Entry point: `javascript:S1244` + `typescript:S1244`
/// no-floating-point-equality check over the parsed program. Requires the
/// semantic model for const resolution, so recoverable-parse files stay
/// silent.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    let imports = collect_file_imports(semantic);
    for node in semantic.nodes().iter() {
        check_node(&mut sink, semantic, ctx.source, node, &imports);
    }
    sink.issues
}

/// Per-node dispatch for the equality, indirect-comparison, assertion,
/// and switch-case surfaces.
fn check_node(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    source: &str,
    node: &oxc_semantic::AstNode<'_>,
    imports: &std::collections::HashSet<String>,
) {
    match node.kind() {
        AstKind::BinaryExpression(binary) => {
            if is_equality_operator(binary.operator)
                && (is_sensitive(semantic, &binary.left)
                    || is_sensitive(semantic, &binary.right))
            {
                emit(sink, binary.span());
            }
        }
        AstKind::LogicalExpression(logical) => {
            if is_indirect_exact_comparison(semantic, source, logical) {
                emit(sink, logical.span());
            }
        }
        AstKind::CallExpression(_) => check_assertion_call(sink, semantic, node, imports),
        AstKind::SwitchCase(case) => {
            if let Some(test) = case.test.as_ref() {
                if is_sensitive(semantic, test) {
                    emit(sink, test.span());
                }
            }
        }
        _ => {}
    }
}

/// Test-framework comparison assertions with a sensitive side.
fn check_assertion_call(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    node: &oxc_semantic::AstNode<'_>,
    imports: &std::collections::HashSet<String>,
) {
    let Some(assertion) = extract_test_assertion(semantic, node, imports) else {
        return;
    };
    let AssertionKind::Comparison {
        actual, expected, ..
    } = assertion.kind
    else {
        return;
    };
    if is_sensitive(semantic, actual) || is_sensitive(semantic, expected) {
        emit(sink, assertion.report_span);
    }
}
fn emit(sink: &mut IssueSink<'_>, span: Span) {
    sink.emit_span(
        RuleScope::Both,
        "S1244",
        "Do not check floating point equality or inequality with exact values, use a range instead.",
        span,
    );
}

fn is_equality_operator(operator: BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::StrictEquality
            | BinaryOperator::StrictInequality
            | BinaryOperator::Equality
            | BinaryOperator::Inequality
    )
}

/// `isFloatingPointExpression`: whether the expression can carry a
//  floating-point-sensitive value.
fn is_sensitive(semantic: &Semantic<'_>, expression: &Expression<'_>) -> bool {
    let mut visited: HashSet<SymbolId> = HashSet::new();
    is_sensitive_inner(semantic, expression, &mut visited)
}

fn is_sensitive_inner(
    semantic: &Semantic<'_>,
    expression: &Expression<'_>,
    visited: &mut HashSet<SymbolId>,
) -> bool {
    match unparenthesized(expression) {
        Expression::NumericLiteral(literal) => is_floating_point_literal(literal),
        Expression::UnaryExpression(unary) => {
            matches!(
                unary.operator,
                UnaryOperator::UnaryPlus | UnaryOperator::UnaryNegation
            ) && is_sensitive_inner(semantic, &unary.argument, visited)
        }
        Expression::BinaryExpression(binary) => {
            if numeric_expression_value(expression)
                .is_some_and(|value| value.is_finite() && value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0)
            {
                return false;
            }
            if binary.operator == BinaryOperator::Division {
                return is_sensitive_inner(semantic, &binary.left, visited)
                    || is_sensitive_inner(semantic, &binary.right, visited)
                    || is_fraction_producing_division(binary);
            }
            matches!(
                binary.operator,
                BinaryOperator::Addition
                    | BinaryOperator::Subtraction
                    | BinaryOperator::Multiplication
                    | BinaryOperator::Remainder
                    | BinaryOperator::Exponential
            ) && (is_sensitive_inner(semantic, &binary.left, visited)
                || is_sensitive_inner(semantic, &binary.right, visited))
        }
        Expression::Identifier(identifier) => {
            is_floating_point_const(semantic, identifier, visited)
        }
        _ => false,
    }
}

/// `isFloatingPointConst`: a `const` binding whose initializer is
/// sensitive (with the reference's visited-set cycle guard).
fn is_floating_point_const(
    semantic: &Semantic<'_>,
    identifier: &oxc_ast::ast::IdentifierReference<'_>,
    visited: &mut HashSet<SymbolId>,
) -> bool {
    let Some(symbol) = identifier
        .reference_id
        .get()
        .and_then(|id| semantic.scoping().get_reference(id).symbol_id())
    else {
        return false;
    };
    if visited.contains(&symbol)
        || semantic.scoping().symbol_declarations(symbol).count() != 1
    {
        return false;
    }
    let declaration = semantic.symbol_declaration(symbol);
    let AstKind::VariableDeclarator(declarator) = semantic.nodes().kind(declaration.id()) else {
        return false;
    };
    let AstKind::VariableDeclaration(kind) = semantic.nodes().parent_kind(declaration.id()) else {
        return false;
    };
    if kind.kind != oxc_ast::ast::VariableDeclarationKind::Const {
        return false;
    }
    if !matches!(declarator.id, oxc_ast::ast::BindingPattern::BindingIdentifier(_)) {
        return false;
    }
    let Some(init) = declarator.init.as_ref() else {
        return false;
    };
    visited.insert(symbol);
    is_sensitive_inner(semantic, init, visited)
}

/// `isFloatingPointLiteral`: a decimal/exponent literal not exactly
/// representable as a binary fraction.
fn is_floating_point_literal(literal: &oxc_ast::ast::NumericLiteral<'_>) -> bool {
    let Some(raw) = literal.raw.as_ref() else {
        return false;
    };
    let raw = raw.replace('_', "").to_lowercase();
    if !raw.contains('.') && !raw.contains('e') {
        return false;
    }
    if !is_decimal_literal(&raw) {
        return false;
    }
    !is_exactly_representable_as_binary_fraction(&raw)
}

/// `decimalLiteralPattern`: `^(\d*)(?:\.(\d*))?(?:e([+-]?\d+))?$`.
fn is_decimal_literal(raw: &str) -> bool {
    let (mantissa, exponent) = match raw.split_once(['e', 'E']) {
        Some((m, e)) => (m, Some(e)),
        None => (raw, None),
    };
    if let Some(exp) = exponent {
        let digits = exp.strip_prefix(['+', '-']).unwrap_or(exp);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    let mut seen_dot = false;
    let mut seen_digit = false;
    for byte in mantissa.bytes() {
        match byte {
            b'.' if !seen_dot => seen_dot = true,
            b'0'..=b'9' => seen_digit = true,
            _ => return false,
        }
    }
    seen_digit
}

/// `isExactlyRepresentableAsBinaryFraction`: digits × 10^exp reduces to a
//  denominator that is a power of two.
fn is_exactly_representable_as_binary_fraction(raw: &str) -> bool {
    let (mantissa, exponent) = match raw.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i64>().unwrap_or(0)),
        None => (raw, 0),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mantissa, ""),
    };
    let digits = format!("{integer}{fraction}");
    if digits.is_empty() {
        return false;
    }
    let exponent = exponent - i64::try_from(fraction.len()).unwrap_or(0);
    let Ok(numerator) = digits.parse::<u128>() else {
        return false;
    };
    if numerator == 0 || exponent >= 0 {
        return true;
    }
    let denominator = 10_u128.pow(u32::try_from(-exponent).unwrap_or(38));
    let reduced = denominator / gcd(numerator, denominator);
    reduced.is_power_of_two()
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// `isExactlyRepresentableIntegerDivision`: |l|/|r| reduces to a
/// power-of-two denominator.
fn is_exactly_representable_integer_division(left: i64, right: i64) -> bool {
    if right == 0 {
        return false;
    }
    let numerator = left.unsigned_abs() as u128;
    let denominator = right.unsigned_abs() as u128;
    let reduced = denominator / gcd(numerator, denominator);
    reduced.is_power_of_two()
}

/// `numericLiteralValue`: a numeric literal or `+`/`-` unary on one.
fn numeric_literal_value(expression: &Expression<'_>) -> Option<f64> {
    match unparenthesized(expression) {
        Expression::NumericLiteral(literal) => Some(literal.value),
        Expression::UnaryExpression(unary)
            if matches!(
                unary.operator,
                UnaryOperator::UnaryPlus | UnaryOperator::UnaryNegation
            ) =>
        {
            let Expression::NumericLiteral(literal) = unparenthesized(&unary.argument) else {
                return None;
            };
            Some(if unary.operator == UnaryOperator::UnaryNegation {
                -literal.value
            } else {
                literal.value
            })
        }
        _ => None,
    }
}

/// `numericExpressionValue`: constant-folded value of a numeric
/// expression over `+ - * / % **` and literals.
fn numeric_expression_value(expression: &Expression<'_>) -> Option<f64> {
    if let Some(value) = numeric_literal_value(expression) {
        return Some(value);
    }
    let Expression::BinaryExpression(binary) = unparenthesized(expression) else {
        return None;
    };
    if !matches!(
        binary.operator,
        BinaryOperator::Addition
            | BinaryOperator::Subtraction
            | BinaryOperator::Multiplication
            | BinaryOperator::Division
            | BinaryOperator::Remainder
            | BinaryOperator::Exponential
    ) {
        return None;
    }
    let left = numeric_expression_value(&binary.left)?;
    let right = numeric_expression_value(&binary.right)?;
    match binary.operator {
        BinaryOperator::Addition => Some(left + right),
        BinaryOperator::Subtraction => Some(left - right),
        BinaryOperator::Multiplication => Some(left * right),
        BinaryOperator::Division => (right != 0.0).then_some(left / right),
        BinaryOperator::Remainder => (right != 0.0).then_some(left % right),
        BinaryOperator::Exponential => Some(left.powf(right)),
        _ => None,
    }
}

/// `isFractionProducingDivision`: integer literals whose quotient is a
/// non-exactly-representable fraction.
fn is_fraction_producing_division(binary: &oxc_ast::ast::BinaryExpression<'_>) -> bool {
    let Some(left) = numeric_literal_value(&binary.left) else {
        return false;
    };
    let Some(right) = numeric_literal_value(&binary.right) else {
        return false;
    };
    if right == 0.0 {
        return false;
    }
    let result = left / right;
    if !(left.fract() == 0.0 && left.is_finite() && result.fract() != 0.0) {
        return false;
    }
    let (Ok(left_i), Ok(right_i)) = (
        i64::try_from(left as i128),
        i64::try_from(right as i128),
    ) else {
        return false;
    };
    !is_exactly_representable_integer_division(left_i, right_i)
}

/// `isIndirectExactComparison`: `a <= t && a >= t` or `a < t || a > t`
/// with equivalent operands and a sensitive side.
fn is_indirect_exact_comparison(
    semantic: &Semantic<'_>,
    source: &str,
    logical: &oxc_ast::ast::LogicalExpression<'_>,
) -> bool {
    let accepted: &[BinaryOperator] = match logical.operator {
        LogicalOperator::And => &[BinaryOperator::LessEqualThan, BinaryOperator::GreaterEqualThan],
        LogicalOperator::Or => &[BinaryOperator::LessThan, BinaryOperator::GreaterThan],
        _ => return false,
    };
    let (Expression::BinaryExpression(left), Expression::BinaryExpression(right)) = (
        unparenthesized(&logical.left),
        unparenthesized(&logical.right),
    ) else {
        return false;
    };
    if !accepted.contains(&left.operator) || !accepted.contains(&right.operator) {
        return false;
    }
    for left_orientation in comparison_orientations(left) {
        for right_orientation in comparison_orientations(right) {
            if left_orientation.is_above == right_orientation.is_above {
                continue;
            }
            if !are_equivalent(source, left_orientation.expression, right_orientation.expression)
                || !are_equivalent(source, left_orientation.threshold, right_orientation.threshold)
            {
                continue;
            }
            if is_sensitive(semantic, left_orientation.expression)
                || is_sensitive(semantic, left_orientation.threshold)
            {
                return true;
            }
        }
    }
    false
}

struct Orientation<'a> {
    expression: &'a Expression<'a>,
    threshold: &'a Expression<'a>,
    is_above: bool,
}

/// `comparisonOrientations`: both readings of a relational comparison.
fn comparison_orientations<'a>(
    binary: &'a oxc_ast::ast::BinaryExpression<'a>,
) -> [Orientation<'a>; 2] {
    match binary.operator {
        BinaryOperator::LessThan | BinaryOperator::LessEqualThan => [
            Orientation {
                expression: &binary.left,
                threshold: &binary.right,
                is_above: false,
            },
            Orientation {
                expression: &binary.right,
                threshold: &binary.left,
                is_above: true,
            },
        ],
        _ => [
            Orientation {
                expression: &binary.left,
                threshold: &binary.right,
                is_above: true,
            },
            Orientation {
                expression: &binary.right,
                threshold: &binary.left,
                is_above: false,
            },
        ],
    }
}

/// `areEquivalent` approximation: same unparenthesized source text with
/// whitespace removed (token-value equality).
fn are_equivalent(source: &str, left: &Expression<'_>, right: &Expression<'_>) -> bool {
    fn normalized<'a>(source: &'a str, expression: &Expression<'_>) -> String {
        span_text(source, unparenthesized(expression).span())
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }
    normalized(source, left) == normalized(source, right)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1244_flags_float_equality_forms() {
        let source = "\
const total = 0.1 + 0.2;
const average = 0.9 + 0.2;
if (total === 0.3) {
  publish(total);
}
const status = total === 0.3 ? 'done' : 'retry';
if (average <= 1.1 && average >= 1.1) {
  publish(average);
}
if (average < 1.1 || average > 1.1) {
  publish(average);
}
if (getRatio() !== 10 / 3) {
  publish(getRatio());
}
const loose = total == 0.3;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S1244"), 6);
    }

    #[test]
    fn s1244_flags_assertions_and_switch_cases() {
        let source = "\
import { expect } from 'vitest';
import assert from 'node:assert/strict';

expect(0.1 + 0.2).toBe(0.3);
assert.strictEqual(0.1 + 0.2, 0.3);
switch (kind) {
  case 0.3:
    break;
}
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S1244"), 3);
    }

    #[test]
    fn s1244_flags_typescript_too() {
        let source = "if (0.1 + 0.2 === 0.3) { go(); }\n";
        assert_eq!(count_key(&ts_keys(source), "typescript:S1244"), 1);
    }

    #[test]
    fn s1244_ignores_exact_and_range_comparisons() {
        let source = "\
const count = 1 + 2;
if (count === 3) {
  publish(count);
}
if (Math.abs(total - 0.3) < Number.EPSILON) {
  publish(total);
}
if (0.5 === 0.5) {
  publish(0.5);
}
if (2 / 4 === 0.5) {
  publish(0.5);
}
const status = total !== 0 ? 'ok' : 'zero';
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S1244"), 0);
    }
}
