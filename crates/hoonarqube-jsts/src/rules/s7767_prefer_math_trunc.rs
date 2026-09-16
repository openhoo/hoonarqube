// Rule module s7767_prefer_math_trunc (generated).
//
// `javascript:S7767` + `typescript:S7767` — `Math.trunc` should be used
// instead of bitwise truncation idioms. Reference semantics:
// eslint-plugin-unicorn `prefer-math-trunc` at the version pinned by
// SonarJS 13.x (v65.0.1, exposed unmodified by SonarJS S7767):
//
// - a binary expression whose right operand is the numeric literal `0`
//   and whose operator is `|`, `>>`, `<<`, or `^` reports the whole
//   expression with "Use `Math.trunc` instead of `<op> <raw>`.";
// - the matching compound assignments `|= 0`, `>>= 0`, `<<= 0`, and
//   `^= 0` report the assignment with the same message shape;
// - the innermost double bitwise NOT `~~<expr>` reports the outer `~~`
//   expression with "Use `Math.trunc` instead of `~~`.", so `~~~x`
//   reports its inner `~~x` pair only.
//
// `>>>`/`>>>=` and `&`/`&=` are not in the reference operator set and
// stay silent, as do non-zero right operands, `0n`, `-0`, and `0 | x`.
// The reference is fixable but no auto-fix is offered here.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, span_text, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentOperator, BinaryExpression, BinaryOperator, Expression,
    UnaryExpression, UnaryOperator,
};
use oxc_span::GetSpan;

/// Entry point: `javascript:S7767` + `typescript:S7767` prefer-math-trunc
/// check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::BinaryExpression(binary) => check_binary(&mut sink, ctx, binary),
            AstKind::AssignmentExpression(assignment) => {
                check_assignment(&mut sink, ctx, assignment);
            }
            AstKind::UnaryExpression(unary) => check_unary(&mut sink, unary),
            _ => {}
        }
    }
    sink.issues
}

/// The reference `isLiteral(right, 0)`: a numeric literal whose value is
/// zero, regardless of its written base or spelling.
fn is_zero_literal(expression: &Expression<'_>) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::NumericLiteral(literal) if literal.value == 0.0
    )
}

/// `|`, `>>`, `<<`, `^` — the reference `bitwiseOperators` set; `>>>` and
/// `&` are deliberately absent.
fn is_truncation_operator(operator: BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::BitwiseOR
            | BinaryOperator::ShiftRight
            | BinaryOperator::ShiftLeft
            | BinaryOperator::BitwiseXOR
    )
}

/// `|=`, `>>=`, `<<=`, `^=` — the reference `operator.slice(0, -1)`
/// membership check over the same set.
fn is_truncation_assignment(operator: AssignmentOperator) -> bool {
    matches!(
        operator,
        AssignmentOperator::BitwiseOR
            | AssignmentOperator::ShiftRight
            | AssignmentOperator::ShiftLeft
            | AssignmentOperator::BitwiseXOR
    )
}

fn check_binary(sink: &mut IssueSink<'_>, ctx: &AnalysisContext, binary: &BinaryExpression<'_>) {
    if !is_truncation_operator(binary.operator) || !is_zero_literal(&binary.right) {
        return;
    }
    emit_bitwise(
        sink,
        ctx,
        binary.operator.as_str(),
        &binary.right,
        binary.span,
    );
}

fn check_assignment(
    sink: &mut IssueSink<'_>,
    ctx: &AnalysisContext,
    assignment: &AssignmentExpression<'_>,
) {
    if !is_truncation_assignment(assignment.operator) || !is_zero_literal(&assignment.right) {
        return;
    }
    emit_bitwise(
        sink,
        ctx,
        assignment.operator.as_str(),
        &assignment.right,
        assignment.span,
    );
}

/// The shared `error-bitwise` report: "Use `Math.trunc` instead of
/// `<operator> <raw>`." where `<raw>` is the literal's source text.
fn emit_bitwise(
    sink: &mut IssueSink<'_>,
    ctx: &AnalysisContext,
    operator: &str,
    right: &Expression<'_>,
    span: oxc_span::Span,
) {
    let raw = span_text(ctx.source, unparenthesized(right).span());
    let message = format!("Use `Math.trunc` instead of `{operator} {raw}`.");
    sink.emit_span(RuleScope::Both, "S7767", &message, span);
}

/// The reference `UnaryExpression` listener: report `~~x` where `x` does
/// not itself start with `~`, i.e. the innermost pair of a `~` run.
fn check_unary(sink: &mut IssueSink<'_>, unary: &UnaryExpression<'_>) {
    if unary.operator != UnaryOperator::BitwiseNot || !is_innermost_double_not(unary) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7767",
        "Use `Math.trunc` instead of `~~`.",
        unary.span,
    );
}

fn is_bitwise_not(expression: &Expression<'_>) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::BitwiseNot
    )
}

/// `~(~x)` where `x` is not itself a bitwise NOT: the outer `~` of the
/// innermost `~~` pair.
fn is_innermost_double_not(unary: &UnaryExpression<'_>) -> bool {
    let Expression::UnaryExpression(inner) = unparenthesized(&unary.argument) else {
        return false;
    };
    inner.operator == UnaryOperator::BitwiseNot && !is_bitwise_not(&inner.argument)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7767_flags_zero_truncation_idioms() {
        let source = "\
const a = x | 0;
const b = y >> 0;
const c = z << 0;
const d = w ^ 0;
let e = 0;
e |= 0;
e >>= 0;
e <<= 0;
e ^= 0;
const f = ~~value;
const g = x | (0);
const h = y | 0x0;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7767"), 11);
    }

    #[test]
    fn s7767_flags_typescript_too() {
        let source = "const x = (y | 0) as number;\nconst z = w << 0;\n";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7767"), 2);
    }

    #[test]
    fn s7767_reports_innermost_double_not_once() {
        let source = "const a = ~~~x;\nconst b = ~~~~y;\n";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7767"), 2);
    }

    #[test]
    fn s7767_ignores_non_truncation_bitwise() {
        let source = "\
const a = x | 1;
const b = x | y;
const c = x & 0;
const d = x >>> 0;
const e = x | 0n;
const f = x | -0;
const g = 0 | x;
const h = x | 0.5;
let i = 0;
i &= 0;
i >>>= 0;
const j = ~x;
const k = x || 0;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7767"), 0);
    }
}
