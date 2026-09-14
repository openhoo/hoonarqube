// Rule module s7766_prefer_math_min_max (generated).
//
// `javascript:S7766` + `typescript:S7766` — Ternary expressions should be
// replaced with "Math.min()" or "Math.max()" for simple comparisons.
// Reference semantics: eslint-plugin-unicorn `prefer-math-min-max` at the
// version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7766):
// a conditional expression whose test is a `<`, `<=`, `>`, or `>=`
// comparison and whose branches repeat the comparison operands
// textually (`a > b ? a : b` -> `Math.max(a, b)`, `a > b ? b : a` ->
// `Math.min(a, b)`, and the mirrored `<`/`<=` forms) is reported on the
// whole conditional expression with the reference message
// "Prefer `Math.{min,max}()` to simplify ternary expressions.".
//
// Guards from the reference implementation: BigInt literals and `BigInt(...)`
// operands stay silent, `new Date` operands stay silent, TS-unwrapped
// operands (`as`/`satisfies`/non-null) must carry number type annotations,
// and identifiers declared with a non-number type annotation, with a
// non-number literal initializer, or initialized with `new Date` stay
// silent. NaN and signed-zero propagation therefore remain caller-visible
// per the issue guard: only provably textual operand repetition is
// reported, and no auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, span_text, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{BinaryExpression, BinaryOperator, ConditionalExpression, Expression, TSType};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;

/// Entry point: `javascript:S7766` + `typescript:S7766` prefer-math-min-max
/// check over the parsed program. Requires the semantic model for the
/// declaration guards, so recoverable-parse files stay silent.
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
        if let AstKind::ConditionalExpression(conditional) = node.kind() {
            check_conditional(&mut sink, ctx, semantic, conditional);
        }
    }
    sink.issues
}

fn unwrap_ts<'a, 'b>(expression: &'a Expression<'b>) -> &'a Expression<'b> {
    let mut current = expression;
    loop {
        match current {
            Expression::TSAsExpression(inner) => current = &inner.expression,
            Expression::TSSatisfiesExpression(inner) => current = &inner.expression,
            Expression::TSNonNullExpression(inner) => current = &inner.expression,
            _ => return current,
        }
    }
}

fn text_of<'a>(source: &'a str, expression: &Expression<'_>) -> &'a str {
    span_text(source, unwrap_ts(expression).span())
}

fn is_bigint_operand(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::BigIntLiteral(_) => true,
        Expression::CallExpression(call) => {
            !call.optional
                && call.arguments.len() == 1
                && matches!(unparenthesized(&call.callee), Expression::Identifier(identifier) if identifier.name == "BigInt")
        }
        _ => false,
    }
}

fn is_new_date(expression: &Expression<'_>) -> bool {
    let Expression::NewExpression(new_expression) = expression else {
        return false;
    };
    matches!(
        unparenthesized(&new_expression.callee),
        Expression::Identifier(identifier) if identifier.name == "Date"
    )
}

fn is_number_type(ts_type: &TSType<'_>) -> bool {
    match ts_type {
        TSType::TSNumberKeyword(_) => true,
        TSType::TSTypeReference(reference) => {
            matches!(&reference.type_name, oxc_ast::ast::TSTypeName::IdentifierReference(identifier) if identifier.name == "Number")
        }
        _ => false,
    }
}

/// The reference `getTypeAnnotation`: only TS non-null, `as`, and angle
/// assertions carry a usable annotation.
fn ts_type_annotation<'a>(expression: &'a Expression<'a>) -> Option<&'a TSType<'a>> {
    match expression {
        Expression::TSNonNullExpression(inner) => ts_type_annotation(&inner.expression),
        Expression::TSAsExpression(inner) => Some(&inner.type_annotation),
        Expression::TSTypeAssertion(inner) => Some(&inner.type_annotation),
        _ => None,
    }
}

fn is_non_number_literal(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::RegExpLiteral(_)
    )
}

/// The reference min/max decision on the textual operand repetition.
fn min_max_method(
    is_greater_or_equal: bool,
    is_less_or_equal: bool,
    left_text: &str,
    right_text: &str,
    consequent_text: &str,
    alternate_text: &str,
) -> Option<&'static str> {
    if (is_greater_or_equal && left_text == alternate_text && right_text == consequent_text)
        || (is_less_or_equal && left_text == consequent_text && right_text == alternate_text)
    {
        return Some("min");
    }
    if (is_greater_or_equal && left_text == consequent_text && right_text == alternate_text)
        || (is_less_or_equal && left_text == alternate_text && right_text == consequent_text)
    {
        return Some("max");
    }
    None
}

/// The reference declaration guards: TS-unwrapped operands must carry number
/// annotations, and identifiers declared with non-number annotations, with
/// non-number literal initializers, or initialized with `new Date` stay
/// silent.
fn operand_declarations_are_numeric(
    semantic: &Semantic<'_>,
    binary: &BinaryExpression<'_>,
) -> bool {
    for operand in [&binary.left, &binary.right] {
        let unwrapped = unwrap_ts(operand);
        if operand.span() != unwrapped.span()
            && let Some(annotation) = ts_type_annotation(operand)
            && !is_number_type(annotation)
        {
            return false;
        }
        let Expression::Identifier(identifier) = unwrapped else {
            continue;
        };
        if !identifier_declarations_are_numeric(semantic, identifier) {
            return false;
        }
    }
    true
}

fn identifier_declarations_are_numeric(
    semantic: &Semantic<'_>,
    identifier: &oxc_ast::ast::IdentifierReference<'_>,
) -> bool {
    let Some(symbol_id) = identifier
        .reference_id
        .get()
        .and_then(|reference_id| semantic.scoping().get_reference(reference_id).symbol_id())
    else {
        return true;
    };
    let declaration = semantic
        .nodes()
        .get_node(semantic.scoping().symbol_declaration(symbol_id));
    match declaration.kind() {
        AstKind::FormalParameter(parameter) => parameter_has_number_shape(parameter),
        AstKind::VariableDeclarator(declarator) => declarator_has_number_shape(declarator),
        _ => true,
    }
}

fn parameter_has_number_shape(parameter: &oxc_ast::ast::FormalParameter<'_>) -> bool {
    if let Some(annotation) = &parameter.type_annotation
        && !is_number_type(&annotation.type_annotation)
    {
        return false;
    }
    if let Some(initializer) = &parameter.initializer
        && is_non_number_literal(unparenthesized(initializer))
    {
        return false;
    }
    true
}

fn declarator_has_number_shape(declarator: &oxc_ast::ast::VariableDeclarator<'_>) -> bool {
    if let Some(init) = &declarator.init
        && is_new_date(init)
    {
        return false;
    }
    if let Some(annotation) = &declarator.type_annotation
        && !is_number_type(&annotation.type_annotation)
    {
        return false;
    }
    if let Some(init) = &declarator.init
        && is_non_number_literal(unparenthesized(init))
    {
        return false;
    }
    true
}

fn check_conditional(
    sink: &mut IssueSink<'_>,
    ctx: &AnalysisContext,
    semantic: &Semantic<'_>,
    conditional: &ConditionalExpression<'_>,
) {
    let Expression::BinaryExpression(test) = unparenthesized(&conditional.test) else {
        return;
    };
    let is_greater_or_equal = matches!(
        test.operator,
        BinaryOperator::GreaterThan | BinaryOperator::GreaterEqualThan
    );
    let is_less_or_equal = matches!(
        test.operator,
        BinaryOperator::LessThan | BinaryOperator::LessEqualThan
    );
    if !is_greater_or_equal && !is_less_or_equal {
        return;
    }
    for operand in [&test.left, &test.right] {
        if is_bigint_operand(operand) || is_new_date(operand) {
            return;
        }
    }
    let left_text = text_of(ctx.source, &test.left);
    let right_text = text_of(ctx.source, &test.right);
    let alternate_text = text_of(ctx.source, &conditional.alternate);
    let consequent_text = text_of(ctx.source, &conditional.consequent);
    let Some(method) = min_max_method(
        is_greater_or_equal,
        is_less_or_equal,
        left_text,
        right_text,
        consequent_text,
        alternate_text,
    ) else {
        return;
    };
    if !operand_declarations_are_numeric(semantic, test) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S7766",
        &format!("Prefer `Math.{method}()` to simplify ternary expressions."),
        conditional.span(),
    );
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7766_flags_pinned_zod_dec_count_anchor() {
        // Pinned anchor: colinhacks/zod@46da957 packages/zod/src/v3/types.ts:1357
        // `const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;`
        let source = "\
function decCounts(valDecCount: number, stepDecCount: number) {
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  return decCount;
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7766"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7766")
            .expect("pinned zod decCount ternary must be reported");
        assert_eq!(
            issue.message,
            "Prefer `Math.max()` to simplify ternary expressions."
        );
        assert_eq!(issue.range.start.line, 2);
        let prefix = "  const decCount = ";
        assert_eq!(
            issue.range.start.column,
            u32::try_from(prefix.len()).unwrap()
        );
        let ternary = "valDecCount > stepDecCount ? valDecCount : stepDecCount";
        assert_eq!(
            issue.range.end.column,
            u32::try_from(prefix.len() + ternary.len()).unwrap()
        );
    }

    #[test]
    fn s7766_flags_reference_min_and_max_families() {
        let source = "\
const min1 = height > 50 ? 50 : height;
const min2 = height < 50 ? height : 50;
const max1 = height >= 50 ? height : 50;
const max2 = height <= 50 ? 50 : height;
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7766"), 4);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7766")
            .map(|issue| issue.message.as_str())
            .collect();
        assert_eq!(
            messages
                .iter()
                .filter(
                    |message| **message == "Prefer `Math.min()` to simplify ternary expressions."
                )
                .count(),
            2
        );
        assert_eq!(
            messages
                .iter()
                .filter(
                    |message| **message == "Prefer `Math.max()` to simplify ternary expressions."
                )
                .count(),
            2
        );
    }

    #[test]
    fn s7766_flags_literal_operand_text_repetition() {
        let source = "\
const smaller = 'a' > 'b' ? 'b' : 'a';
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7766"), 1);
    }

    #[test]
    fn s7766_non_equivalent_ternaries_stay_silent() {
        let source = "\
const wrong = alpha > beta ? alpha : gamma;
const nonTest = flag ? alpha : beta;
const equality = alpha == beta ? alpha : beta;
const inequality = alpha != beta ? alpha : beta;
const swapped = alpha > beta ? beta : gamma;
const big = 10n > 5n ? 10n : 5n;
const dates = new Date(alpha) > new Date(beta) ? alpha : beta;
var sa = 'x';
var sb = 'y';
const literals = sa > sb ? sa : sb;
function typed(a: string, b: string) {
  return a > b ? a : b;
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7766"), 0);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7766"), 0);
    }

    #[test]
    fn s7766_reports_in_both_languages() {
        let ts_source = "\
declare const height: number;
const m = height > 50 ? 50 : height;
";
        let js_source = "\
const height = readHeight();
const m = height > 50 ? 50 : height;
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7766"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7766"), 1);
    }
}
