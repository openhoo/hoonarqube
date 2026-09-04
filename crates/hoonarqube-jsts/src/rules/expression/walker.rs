// Family walker for 'expression' (generated).
use super::collectors::{check_collection_and_object_calls, check_logging_and_binding_calls};
use super::s1125_binary_operators::check_binary_operators;
use super::s1313_string_literal_raw::check_string_literal_raw;
use super::s1314_numeric_literal::check_numeric_literal;
use super::s1442_plain_calls::check_plain_calls;
use super::s1528_constructor_calls::check_constructor_calls;
use super::s2424_assignment_rules::check_assignment_rules;
use super::s2692_index_of_comparisons::check_index_of_comparisons;
use super::s3003_relational_strings::check_relational_strings;
use super::s3981_length_comparison::check_length_comparison;
use super::s4125_typeof_literal::check_typeof_literal;
use super::s6644_redundant_ternary::check_redundant_ternary;
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::shared::{call_property, is_equality_operator, regex_pattern_text};
use crate::support::{
    IssueSink, LineIndex, RuleScope, callee_name, identifier_name, unparenthesized,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrayExpression, ArrayExpressionElement, ArrowFunctionExpression, AssignmentExpression,
    BinaryExpression, BinaryOperator, CallExpression, ConditionalExpression, DoWhileStatement,
    Expression, ForStatement, Function, IfStatement, LogicalExpression, LogicalOperator,
    NewExpression, NumericLiteral, ParenthesizedExpression, RegExpLiteral, SequenceExpression,
    StaticBlock, StringLiteral, TemplateLiteral, UnaryExpression, UnaryOperator, WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_array_expression, walk_arrow_function_expression, walk_assignment_expression,
    walk_binary_expression, walk_call_expression, walk_function, walk_new_expression,
    walk_parenthesized_expression, walk_sequence_expression, walk_static_block,
    walk_template_literal, walk_unary_expression,
};
use oxc_span::GetSpan;
use oxc_syntax::scope::ScopeFlags;
use std::collections::HashSet;

fn check_expression_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ExpressionCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        contexts: Vec::new(),
        ternary_spans: HashSet::new(),
        template_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Expression-level batch rules in one traversal: `S1774`, `S3735`, `S878`,
/// `S2688`, `S6679`, `S2757`, `S1440`, `S1125`, `S1529`, `S1940`, `S6638`,
/// `S2692`, `S6557`, `S3981`, `S6676`, `S6637`, `S6509`, `S1529`, `S6958`,
/// `S6959`, `S2871`, `S3003`, `S4125`, `S2427`, `S2817`, `S3533`, `S106`,
/// `S1442`, `S6653`, `S6661`, `S6666`, `S2685`, `S6654`, `S6643`, `S2424`,
/// `S1528`, `S1533`, `S2428`, `S3834`, `S4624`, `S3786`, `S1516`, `S6535`,
/// `S6657`, `S1314`, `S6534`, `S1313`, `S4140`, `S1110`, and `S3812`.
struct ExpressionCollector<'index> {
    sink: IssueSink<'index>,
    source: &'index str,
    contexts: Vec<ExpressionContext>,
    ternary_spans: HashSet<(u32, u32)>,
    /// Nesting depth of template literals for `S4624`.
    template_depth: u32,
}
impl ExpressionCollector<'_> {
    fn visit_condition(&mut self, expression: &Expression<'_>) {
        self.contexts.push(ExpressionContext::Condition);
        self.visit_expression(expression);
        self.contexts.pop();
    }
    /// Calls and nested function bodies are value contexts, even when the
    /// enclosing expression is used as a condition.
    fn with_non_condition_context(&mut self, walk: impl FnOnce(&mut Self)) {
        let contexts = std::mem::take(&mut self.contexts);
        walk(self);
        self.contexts = contexts;
    }
}

impl<'a> Visit<'a> for ExpressionCollector<'_> {
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        self.with_non_condition_context(|collector| walk_function(collector, it, flags));
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.with_non_condition_context(|collector| {
            walk_arrow_function_expression(collector, it);
        });
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.with_non_condition_context(|collector| walk_static_block(collector, it));
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.visit_condition(&it.test);
        self.visit_statement(&it.consequent);
        if let Some(alternate) = &it.alternate {
            self.visit_statement(alternate);
        }
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(init) = &it.init {
            self.visit_for_statement_init(init);
        }
        if let Some(test) = &it.test {
            self.visit_condition(test);
        }
        if let Some(update) = &it.update {
            self.visit_expression(update);
        }
        self.visit_statement(&it.body);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.visit_condition(&it.test);
        self.visit_statement(&it.body);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.visit_statement(&it.body);
        self.visit_condition(&it.test);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        let span = it.span();
        if self.ternary_spans.insert((span.start, span.end)) {
            self.sink
                .emit_span(RuleScope::Both, "S1774", "Ternary operator used.", span);
        }
        check_redundant_ternary(&mut self.sink, it);
        self.visit_condition(&it.test);
        self.visit_expression(&it.consequent);
        self.visit_expression(&it.alternate);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        if matches!(it.operator, LogicalOperator::And | LogicalOperator::Or)
            && let (Some(left_name), Some(right_name)) =
                (identifier_name(&it.left), identifier_name(&it.right))
            && left_name == right_name
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6638",
                "Both operands are identical; simplify this expression.",
                it.span(),
            );
        }
        let in_condition = self.contexts.contains(&ExpressionContext::Condition);
        let in_logical_condition = self.contexts.contains(&ExpressionContext::LogicalOperand);
        for operand in [&it.left, &it.right] {
            if in_condition || in_logical_condition {
                self.contexts.push(ExpressionContext::LogicalOperand);
            }
            self.visit_expression(operand);
            if in_condition || in_logical_condition {
                self.contexts.pop();
            }
        }
    }
    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        let logical_operand_context = self.contexts.contains(&ExpressionContext::LogicalOperand);
        if logical_operand_context && is_bitwise_operator(it.operator) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1529",
                "Convert the result of this bitwise operation to a boolean explicitly.",
                it.span(),
            );
        }
        let boolean_context = self.contexts.iter().any(|context| {
            matches!(
                context,
                ExpressionContext::Condition | ExpressionContext::LogicalOperand
            )
        });
        if matches!(it.operator, BinaryOperator::In | BinaryOperator::Instanceof)
            && matches!(
                &it.left,
                Expression::UnaryExpression(unary)
                    if unary.operator == UnaryOperator::LogicalNot
            )
        {
            let operator = if it.operator == BinaryOperator::In {
                "in"
            } else {
                "instanceof"
            };
            self.sink.emit_span(
                RuleScope::Both,
                "S3812",
                &format!("Unexpected negating the left operand of '{operator}' operator."),
                it.left.span(),
            );
        }
        check_binary_operators(&mut self.sink, self.source, it);
        check_index_of_comparisons(&mut self.sink, it);
        check_length_comparison(&mut self.sink, it);
        check_relational_strings(&mut self.sink, it);
        check_typeof_literal(&mut self.sink, it);
        let comparison = is_equality_operator(it.operator)
            || matches!(
                it.operator,
                BinaryOperator::LessThan
                    | BinaryOperator::LessEqualThan
                    | BinaryOperator::GreaterThan
                    | BinaryOperator::GreaterEqualThan
                    | BinaryOperator::In
                    | BinaryOperator::Instanceof
            );
        if boolean_context && comparison {
            self.with_non_condition_context(|collector| walk_binary_expression(collector, it));
        } else {
            walk_binary_expression(self, it);
        }
    }
    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        match it.operator {
            UnaryOperator::Void => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3735",
                    "Remove this use of the \"void\" operator.",
                    it.span(),
                );
            }
            UnaryOperator::LogicalNot => {
                if let Expression::BinaryExpression(binary) = unparenthesized(&it.argument)
                    && (is_equality_operator(binary.operator)
                        || matches!(
                            binary.operator,
                            BinaryOperator::LessThan
                                | BinaryOperator::LessEqualThan
                                | BinaryOperator::GreaterThan
                                | BinaryOperator::GreaterEqualThan
                        ))
                {
                    let opposite = opposite_comparison_operator(binary.operator);
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S1940",
                        &format!("Use the opposite operator ({opposite}) instead."),
                        it.span(),
                    );
                }
                if matches!(
                    unparenthesized(&it.argument),
                    Expression::UnaryExpression(inner) if inner.operator == UnaryOperator::LogicalNot
                ) && self
                    .contexts
                    .last()
                    .is_some_and(|context| *context == ExpressionContext::Condition)
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S6509",
                        "Remove this redundant double negation.",
                        it.span(),
                    );
                }
                self.contexts.push(ExpressionContext::Negation);
                self.visit_expression(&it.argument);
                self.contexts.pop();
                return;
            }
            _ => {}
        }
        walk_unary_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        check_assignment_rules(&mut self.sink, self.source, it);
        walk_assignment_expression(self, it);
    }

    fn visit_parenthesized_expression(&mut self, it: &ParenthesizedExpression<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1110",
            "Remove these redundant parentheses.",
            it.span(),
        );
        walk_parenthesized_expression(self, it);
    }

    fn visit_sequence_expression(&mut self, it: &SequenceExpression<'a>) {
        let comma = it
            .expressions
            .first()
            .zip(it.expressions.get(1))
            .and_then(|(first, second)| {
                let start = usize::try_from(first.span().end).ok()?;
                let end = usize::try_from(second.span().start).ok()?;
                let offset = self.source.get(start..end)?.find(',')?;
                let comma = crate::support::to_u32(start + offset);
                Some(oxc_span::Span::new(comma, comma.saturating_add(1)))
            })
            .unwrap_or_else(|| it.span());
        self.sink.emit_span(
            RuleScope::Both,
            "S878",
            "Unexpected use of comma operator.",
            comma,
        );
        walk_sequence_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        check_member_calls(&mut self.sink, it);
        check_plain_calls(&mut self.sink, it);
        if callee_name(it).is_some_and(|name| name == "Boolean")
            && it.arguments.len() == 1
            && self
                .contexts
                .last()
                .is_some_and(|context| *context == ExpressionContext::Condition)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6509",
                "Remove this redundant \"Boolean()\" cast.",
                it.span(),
            );
        }
        self.with_non_condition_context(|collector| walk_call_expression(collector, it));
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        check_constructor_calls(&mut self.sink, it);
        self.with_non_condition_context(|collector| walk_new_expression(collector, it));
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        if self.template_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S4624",
                "Refactor this code to not use nested template literals.",
                it.span(),
            );
        }
        self.template_depth += 1;
        walk_template_literal(self, it);
        self.template_depth -= 1;
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        check_string_literal_raw(&mut self.sink, it);
    }

    fn visit_reg_exp_literal(&mut self, it: &RegExpLiteral<'a>) {
        if has_octal_escape(regex_pattern_text(it)) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6657",
                "Replace this octal escape sequence with a decimal escape.",
                it.span(),
            );
        }
    }

    fn visit_numeric_literal(&mut self, it: &NumericLiteral<'a>) {
        check_numeric_literal(&mut self.sink, it);
    }

    fn visit_array_expression(&mut self, it: &ArrayExpression<'a>) {
        if it
            .elements
            .iter()
            .any(|element| matches!(element, ArrayExpressionElement::Elision(_)))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4140",
                "Unexpected comma in middle of array.",
                it.span(),
            );
        }
        walk_array_expression(self, it);
    }
}

fn opposite_comparison_operator(operator: BinaryOperator) -> &'static str {
    match operator {
        BinaryOperator::Equality => "!=",
        BinaryOperator::Inequality => "==",
        BinaryOperator::StrictEquality => "!==",
        BinaryOperator::StrictInequality => "===",
        BinaryOperator::LessThan => ">=",
        BinaryOperator::LessEqualThan => ">",
        BinaryOperator::GreaterThan => "<=",
        BinaryOperator::GreaterEqualThan => "<",
        _ => "opposite",
    }
}

/// Boolean-context stack for the condition-sensitive rules (`S1529`,
/// `S6509`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpressionContext {
    /// Directly in an `if`/loop/ternary test.
    Condition,
    /// Operand of a logical expression used as a condition.
    LogicalOperand,
    /// Operand of a `!` operator.
    Negation,
}

fn is_bitwise_operator(operator: BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::BitwiseAnd
            | BinaryOperator::BitwiseOR
            | BinaryOperator::BitwiseXOR
            | BinaryOperator::ShiftLeft
            | BinaryOperator::ShiftRight
            | BinaryOperator::ShiftRightZeroFill
    )
}

/// Member-call rules: `S106`, `S1442`, `S6637`, `S6676`, `S6666`, `S6959`,
/// `S2871`, `S6653`, `S2685`, `S6654`, and `S6661`.
fn check_member_calls(sink: &mut IssueSink, it: &CallExpression<'_>) {
    let Some((property, member)) = call_property(it) else {
        return;
    };
    check_logging_and_binding_calls(sink, it, property, member);
    check_collection_and_object_calls(sink, it, property, member);
}

/// Legacy octal escapes (`\101`), including `\0`-prefixed forms.
fn has_octal_escape(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    chars
        .windows(2)
        .any(|window| window[0] == '\\' && ('1'..='7').contains(&window[1]))
}

pub(crate) fn numeric_literal_value(expression: &Expression<'_>) -> Option<f64> {
    match expression {
        Expression::NumericLiteral(literal) => Some(literal.value),
        _ => None,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_expression_rules(ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s3812_flags_negated_in_expressions_requiring_parentheses() {
        let bad = js_keys("const present = !key in object;\n");
        assert_eq!(count_key(&bad, "javascript:S3812"), 1);

        let good = js_keys("const present = !(key in object);\n");
        assert_eq!(count_key(&good, "javascript:S3812"), 0);
    }

    #[test]
    fn expression_level_batch_rules_fire() {
        let source = "\
if (a == b) { void c; (d, e); }
if (x === NaN) { if (list.length < 0) { } }
const n = parseInt(s);
console.log(n);
alert(n);
values.sort();
other.reduce(cb);
if (list.indexOf(x) > 0) { }
if ('a' < 'b') { }
q = cond ? nested(1) : outer(cond ? nested(2) : 3);
r = flag ? true : false;
f = (() => 1).bind(this);
g.call(ctx);
h.apply(ctx, [args]);
Object.assign({}, opts);
const arr = new Array(1, 2);
const num = new Number(5);
legacy = require('mod');
db = openDatabase(name);
outer = `${inner `${deep}`}`;
text = \"interp ${x}\";
host = '10.0.0.1';
";
        let flagged = js_keys(source);
        for key in [
            "S1440", "S3735", "S878", "S6679", "S3981", "S2427", "S106", "S1442", "S2871", "S6959",
            "S2692", "S3003", "S1774", "S6644", "S6637", "S6676", "S6666", "S6661", "S1528",
            "S1533", "S3533", "S2817", "S4624", "S3786", "S1313",
        ] {
            assert!(
                count_key(&flagged, &format!("javascript:{key}")) >= 1,
                "expected {key}"
            );
        }
    }

    #[test]
    fn s1774_flags_each_ternary_once() {
        let single = js_keys("const v = a ? b : c;\n");
        assert_eq!(count_key(&single, "javascript:S1774"), 1);

        let nested = js_keys("const v = a ? b : (c ? d : e);\n");
        assert_eq!(count_key(&nested, "javascript:S1774"), 2);
    }

    #[test]
    fn comma_operator_span_uses_the_actual_token_after_unicode_trivia() {
        let source = "(a\u{00a0}, b);\n";
        let report = js(source);
        let finding = report
            .issues
            .iter()
            .find(|issue| issue.rule_key.ends_with(":S878"))
            .expect("comma operator finding");
        let comma = source.find(',').expect("comma");
        assert_eq!(
            finding.range.start.column,
            u32::try_from(source[..comma].chars().count()).expect("column")
        );
        assert_eq!(finding.range.end.column, finding.range.start.column + 1);
    }

    #[test]
    fn s1940_and_s6509_see_through_parenthesized_negation_arguments() {
        let flagged = js_keys("if (!(a === b)) { }\nif (!(a < b)) { }\nif (!(!(flag))) { }\n");
        assert!(
            count_key(&flagged, "javascript:S1940") >= 2,
            "expected parenthesized negated comparisons to fire S1940"
        );
        assert!(
            count_key(&flagged, "javascript:S6509") >= 1,
            "expected parenthesized double negation to fire S6509"
        );

        // `!flag` is not a comparison, and `!a === b` parses as `(!a) === b`,
        // so neither may fire S1940.
        let clean = js_keys("if (!flag) { }\nlet inverted = !a === b;\n");
        assert_eq!(count_key(&clean, "javascript:S1940"), 0);
    }

    #[test]
    fn direct_bitwise_conditions_match_the_oracle_clean_control() {
        let source = concat!(
            "if (flags & mask) {}\n",
            "while (flags | mask) { break; }\n",
            "for (; flags ^ mask; ) { break; }\n",
            "const value = flags & mask ? left : right;\n",
        );
        assert_eq!(count_key(&js_keys(source), "javascript:S1529"), 0);
    }

    #[test]
    fn s1529_does_not_leak_into_call_or_nested_function_bodies() {
        let clean = js_keys(
            "if (check(flags & mask)) {}\n\
             if (new Checker(flags & mask)) {}\n\
             if (() => flags & mask) {}\n\
             if (function () { return flags & mask; }) {}\n\
             if ((flags & mask) === 0) {}\n",
        );
        assert_eq!(count_key(&clean, "javascript:S1529"), 0);

        let composed = js_keys("if (ready && (flags & mask)) {}\n");
        assert_eq!(count_key(&composed, "javascript:S1529"), 1);
    }

    #[test]
    fn multiple_array_elisions_emit_one_finding_at_the_array_span() {
        let source = "const values = [one,, two,,, three];\n";
        let report = js(source);
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S4140"))
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].range.start.line, 1);
        assert_eq!(findings[0].range.start.column, 15);
    }
}
