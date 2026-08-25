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
use crate::support::{IssueSink, LineIndex, RuleScope, callee_name, identifier_name};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrayExpression, ArrayExpressionElement, AssignmentExpression, BinaryExpression,
    BinaryOperator, CallExpression, ConditionalExpression, Expression, IfStatement,
    LogicalExpression, LogicalOperator, NewExpression, NumericLiteral, ParenthesizedExpression,
    RegExpLiteral, SequenceExpression, StringLiteral, TemplateLiteral, UnaryExpression,
    UnaryOperator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_array_expression, walk_assignment_expression, walk_binary_expression,
    walk_call_expression, walk_new_expression, walk_parenthesized_expression,
    walk_sequence_expression, walk_template_literal, walk_unary_expression,
};
use oxc_span::GetSpan;

fn check_expression_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ExpressionCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        contexts: Vec::new(),
        ternary_depth: 0,
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
/// `S6657`, `S1314`, `S6534`, `S1313`, `S4140`, and `S1110`-adjacent
/// parenthesized-expression checks (`S1110`, `S3812`).
struct ExpressionCollector<'index> {
    sink: IssueSink<'index>,
    contexts: Vec<ExpressionContext>,
    ternary_depth: u32,
    /// Nesting depth of template literals for `S4624`.
    template_depth: u32,
}

impl<'a> Visit<'a> for ExpressionCollector<'_> {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.contexts.push(ExpressionContext::Condition);
        self.visit_expression(&it.test);
        self.contexts.pop();
        self.visit_statement(&it.consequent);
        if let Some(alternate) = &it.alternate {
            self.visit_statement(alternate);
        }
    }

    /// Intentional CE divergence (`S1774`): the upstream documentation example
    /// marks even a single-level ternary Noncompliant, and the captured engine
    /// emits "Ternary operator used." on every ternary in oracle-js. We
    /// deliberately implement the narrower nesting-only policy: only ternaries
    /// nested inside another ternary are flagged.
    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        if self.ternary_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1774",
                "Refactor this nested ternary into a statement.",
                it.span(),
            );
        }
        check_redundant_ternary(&mut self.sink, it);
        self.contexts.push(ExpressionContext::Condition);
        self.visit_expression(&it.test);
        self.contexts.pop();
        self.ternary_depth += 1;
        self.visit_expression(&it.consequent);
        self.visit_expression(&it.alternate);
        self.ternary_depth -= 1;
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
        let operand_is_condition = !self.contexts.is_empty();
        for operand in [&it.left, &it.right] {
            if let Expression::BinaryExpression(binary) = operand
                && is_bitwise_operator(binary.operator)
                && operand_is_condition
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1529",
                    "Convert the result of this bitwise operation to a boolean explicitly.",
                    binary.span(),
                );
            }
            self.contexts.push(ExpressionContext::Condition);
            self.visit_expression(operand);
            self.contexts.pop();
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
                if let Expression::BinaryExpression(binary) = &it.argument
                    && (is_equality_operator(binary.operator)
                        || matches!(
                            binary.operator,
                            BinaryOperator::LessThan
                                | BinaryOperator::LessEqualThan
                                | BinaryOperator::GreaterThan
                                | BinaryOperator::GreaterEqualThan
                        ))
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S1940",
                        "Invert the comparison operator instead of negating it.",
                        it.span(),
                    );
                }
                if matches!(
                    &it.argument,
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

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        check_binary_operators(&mut self.sink, it);
        check_index_of_comparisons(&mut self.sink, it);
        check_length_comparison(&mut self.sink, it);
        check_relational_strings(&mut self.sink, it);
        check_typeof_literal(&mut self.sink, it);
        walk_binary_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        check_assignment_rules(&mut self.sink, it);
        walk_assignment_expression(self, it);
    }

    fn visit_parenthesized_expression(&mut self, it: &ParenthesizedExpression<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1110",
            "Remove these redundant parentheses.",
            it.span(),
        );
        if let Expression::UnaryExpression(unary) = &it.expression
            && unary.operator == UnaryOperator::LogicalNot
            && let Expression::BinaryExpression(binary) = &unary.argument
            && matches!(
                binary.operator,
                BinaryOperator::In | BinaryOperator::Instanceof
            )
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3812",
                "The parentheses are required here; negate the operator instead.",
                unary.span(),
            );
        }
        walk_parenthesized_expression(self, it);
    }

    fn visit_sequence_expression(&mut self, it: &SequenceExpression<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S878",
            "Split this comma-separated sequence into separate statements.",
            it.span(),
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
        walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        check_constructor_calls(&mut self.sink, it);
        walk_new_expression(self, it);
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        if self.template_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S4624",
                "Extract this nested template literal.",
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
        for element in &it.elements {
            if matches!(element, ArrayExpressionElement::Elision(_)) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4140",
                    "Fill or remove the empty slots in this array literal.",
                    element.span(),
                );
            }
        }
        walk_array_expression(self, it);
    }
}

/// Boolean-context stack for the condition-sensitive rules (`S1529`,
/// `S6509`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpressionContext {
    /// Directly in an `if`/ternary test or a logical operand.
    Condition,
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
    check_expression_rules(ctx.program, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

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
    fn s1774_flags_only_nested_ternaries_intentional_ce_divergence() {
        // Single ternary: clean here, though the captured engine would flag
        // it (SQ-OVERFIRE quirk; disposition pinned per project decision).
        let single = js_keys("const v = a ? b : c;\n");
        assert_eq!(count_key(&single, "javascript:S1774"), 0);

        let nested = js_keys("const v = a ? b : (c ? d : e);\n");
        assert_eq!(count_key(&nested, "javascript:S1774"), 1);
    }
}
