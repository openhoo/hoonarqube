use crate::context::AnalysisContext;
use crate::support::{identifier_name, static_property_name, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    AssignmentExpression, BinaryExpression, BinaryOperator, ConditionalExpression, Expression,
    IfStatement, LogicalExpression, LogicalOperator, NewExpression, Statement, TSType, TSTypeName,
    UnaryExpression, UnaryOperator, VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_assignment_expression, walk_binary_expression, walk_conditional_expression,
    walk_if_statement, walk_logical_expression, walk_new_expression, walk_unary_expression,
    walk_variable_declarator,
};
use oxc_parser::{Kind, Token};
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};

use super::{Candidate, candidate, issue_offsets};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    S1125,
    S1126,
    S1528,
    S1533,
    S1940,
    S2757,
    S3403,
    S3981,
    S3984,
    S4619,
}

#[derive(Clone, Copy)]
struct IssueRef {
    index: usize,
    rule: Rule,
    start: usize,
    end: usize,
}

struct Collector<'ctx, 'ast> {
    ctx: &'ctx AnalysisContext<'ast>,
    semantic: &'ctx Semantic<'ast>,
    issues: Vec<IssueRef>,
    used: Vec<bool>,
    out: Vec<(usize, Candidate)>,
    /// The unparenthesized root expression of the active `if` test, if any.
    /// This lets S1125 enforce the upstream `x || true` condition restriction
    /// without searching source text for a parent expression.
    condition_roots: Vec<(u32, u32)>,
    /// Number of unary-expression ancestors currently being visited.
    unary_depth: usize,
}

pub(super) fn collect<'a>(
    ctx: &AnalysisContext<'a>,
    semantic: &Semantic<'a>,
    issues: &[Issue],
) -> Vec<(usize, Candidate)> {
    let issue_refs = issues
        .iter()
        .enumerate()
        .filter_map(|(index, issue)| {
            let rule = match issue.rule_key.rsplit(':').next()? {
                "S1125" => Rule::S1125,
                "S1126" => Rule::S1126,
                "S1528" => Rule::S1528,
                "S1533" => Rule::S1533,
                "S1940" => Rule::S1940,
                "S2757" => Rule::S2757,
                "S3403" => Rule::S3403,
                "S3981" => Rule::S3981,
                "S3984" => Rule::S3984,
                "S4619" => Rule::S4619,
                _ => return None,
            };
            let (start, end) = issue_offsets(ctx, issue)?;
            Some(IssueRef {
                index,
                rule,
                start,
                end,
            })
        })
        .collect::<Vec<_>>();
    if issue_refs.is_empty() {
        return Vec::new();
    }

    let mut collector = Collector {
        ctx,
        semantic,
        used: vec![false; issue_refs.len()],
        issues: issue_refs,
        out: Vec::new(),
        condition_roots: Vec::new(),
        unary_depth: 0,
    };
    collector.visit_program(ctx.program);
    collector.out
}

impl Collector<'_, '_> {
    fn source(&self) -> &str {
        self.ctx.source
    }

    fn span_bounds(span: Span) -> (usize, usize) {
        (span.start as usize, span.end as usize)
    }

    fn text(&self, span: Span) -> Option<&str> {
        let (start, end) = Self::span_bounds(span);
        self.source().get(start..end)
    }

    fn issue_slot(&self, rule: Rule, start: usize, end: usize, enclosing: bool) -> Option<usize> {
        self.issues.iter().enumerate().find_map(|(slot, issue)| {
            if self.used[slot] || issue.rule != rule {
                return None;
            }
            let matches = if enclosing {
                issue.start >= start && issue.end <= end
            } else {
                issue.start == start && issue.end == end
            };
            matches.then_some(slot)
        })
    }

    fn take_issue(
        &mut self,
        rule: Rule,
        start: usize,
        end: usize,
        enclosing: bool,
    ) -> Option<IssueRef> {
        let slot = self.issue_slot(rule, start, end, enclosing)?;
        self.used[slot] = true;
        Some(self.issues[slot])
    }

    fn emit(&mut self, issue: IssueRef, value: Candidate) {
        self.out.push((issue.index, value));
    }

    fn token_between(&self, start: usize, end: usize, kind: Kind) -> Option<&Token> {
        self.ctx.tokens.iter().find(|token| {
            token.kind() == kind && token.start() as usize >= start && token.end() as usize <= end
        })
    }

    fn binary_operator_span(&self, expression: &BinaryExpression<'_>) -> Option<(usize, usize)> {
        let left_end = expression.left.span().end as usize;
        let right_start = expression.right.span().start as usize;
        let kind = match expression.operator {
            BinaryOperator::Equality => Kind::Eq2,
            BinaryOperator::Inequality => Kind::Neq,
            BinaryOperator::StrictEquality => Kind::Eq3,
            BinaryOperator::StrictInequality => Kind::Neq2,
            BinaryOperator::LessThan => Kind::LAngle,
            BinaryOperator::GreaterEqualThan => Kind::GtEq,
            _ => return None,
        };
        self.token_between(left_end, right_start, kind)
            .map(|token| (token.start() as usize, token.end() as usize))
    }

    fn check_boolean_binary(&mut self, expression: &BinaryExpression<'_>) {
        if !matches!(
            expression.operator,
            BinaryOperator::Equality | BinaryOperator::Inequality
        ) {
            return;
        }
        for (boolean, other) in [
            (&expression.left, &expression.right),
            (&expression.right, &expression.left),
        ] {
            let Expression::BooleanLiteral(literal) = unparenthesized(boolean) else {
                continue;
            };
            let span = literal.span();
            let (start, end) = Self::span_bounds(span);
            let Some(issue) = self.take_issue(Rule::S1125, start, end, false) else {
                continue;
            };
            let Some(other_text) = self.text(other.span()) else {
                continue;
            };
            let should_negate = (expression.operator == BinaryOperator::Equality && !literal.value)
                || (expression.operator == BinaryOperator::Inequality && literal.value);
            let replacement = if should_negate {
                format!("!{other_text}")
            } else {
                other_text.to_owned()
            };
            self.emit(
                issue,
                candidate(
                    "s1125-remove-boolean",
                    "Remove the unnecessary boolean literal",
                    [(
                        expression.span().start as usize,
                        expression.span().end as usize,
                        replacement,
                    )],
                ),
            );
        }
    }

    fn check_logical(&mut self, expression: &LogicalExpression<'_>) {
        let operator = expression.operator;
        let left_bool = matches!(
            unparenthesized(&expression.left),
            Expression::BooleanLiteral(_)
        );
        let right_bool = matches!(
            unparenthesized(&expression.right),
            Expression::BooleanLiteral(_)
        );
        if left_bool {
            self.check_logical_operand(expression, &expression.left);
        }
        let allow_right = operator == LogicalOperator::And
            || (operator == LogicalOperator::Or && self.is_condition_root(expression));
        if right_bool && allow_right {
            self.check_logical_operand(expression, &expression.right);
        }
    }
    fn check_if_boolean_return(&mut self, statement: &IfStatement<'_>) {
        let parent = self.semantic.nodes().parent_kind(statement.node_id.get());
        // The upstream rule ignores an `else if` node; its outer if owns the
        // complete boolean-return flow.
        if matches!(parent, AstKind::IfStatement(_)) {
            return;
        }
        let Some(consequent) = Self::boolean_return(&statement.consequent) else {
            return;
        };
        let (alternate, end) = if let Some(alternate) = statement.alternate.as_ref() {
            let Some(alternate_value) = Self::boolean_return(alternate) else {
                return;
            };
            (alternate_value, alternate.span().end as usize)
        } else {
            let siblings: &[Statement<'_>] = match parent {
                AstKind::BlockStatement(block) => block.body.as_slice(),
                AstKind::FunctionBody(body) => body.statements.as_slice(),
                _ => return,
            };
            let Some(index) = siblings
                .iter()
                .position(|sibling| sibling.span() == statement.span())
            else {
                return;
            };
            let Some(next) = siblings.get(index + 1) else {
                return;
            };
            if siblings[..index].iter().any(|sibling| {
                matches!(
                    sibling,
                    Statement::IfStatement(previous)
                        if Self::boolean_return(&previous.consequent).is_some()
                )
            }) {
                return;
            }
            let Some(alternate_value) = Self::boolean_return(next) else {
                return;
            };
            (alternate_value, next.span().end as usize)
        };
        if consequent == alternate {
            return;
        }
        let start = statement.span.start as usize;
        if self.ctx.comments.iter().any(|comment| {
            comment.token.start as usize >= start && comment.token.end as usize <= end
        }) {
            return;
        }
        let Some(issue) = self.take_issue(Rule::S1126, start, statement.span.end as usize, false)
        else {
            return;
        };
        let Some(test_text) = self.text(statement.test.span()).map(str::to_owned) else {
            return;
        };
        let boolean_test = Self::is_boolean_expression(unparenthesized(&statement.test));
        self.emit_s1126(issue, start, end, &test_text, consequent, boolean_test);
    }
    fn check_conditional_boolean_return(&mut self, expression: &ConditionalExpression<'_>) {
        let Expression::BooleanLiteral(consequent) = &expression.consequent else {
            return;
        };
        let Expression::BooleanLiteral(alternate) = &expression.alternate else {
            return;
        };
        if consequent.value == alternate.value {
            return;
        }
        let (start, end) = Self::span_bounds(expression.span());
        let Some(issue) = self.take_issue(Rule::S1126, start, end, false) else {
            return;
        };
        let Some(test_text) = self.text(expression.test.span()).map(str::to_owned) else {
            return;
        };
        let replacement = if consequent.value {
            format!("return {test_text};")
        } else {
            format!("return !({test_text});")
        };
        let id = if consequent.value {
            "s1126-return-condition"
        } else {
            "s1126-return-negated"
        };
        self.emit(
            issue,
            candidate(
                id,
                "Replace with single return statement",
                [(start, end, replacement)],
            ),
        );
    }

    fn emit_s1126(
        &mut self,
        issue: IssueRef,
        start: usize,
        end: usize,
        test_text: &str,
        consequent: bool,
        boolean_test: bool,
    ) {
        if !consequent {
            self.emit(
                issue,
                candidate(
                    "s1126-return-negated",
                    "Replace with single return statement",
                    [(start, end, format!("return !({test_text});"))],
                ),
            );
        } else if boolean_test {
            self.emit(
                issue,
                candidate(
                    "s1126-return-condition",
                    "Replace with single return statement",
                    [(start, end, format!("return {test_text};"))],
                ),
            );
        } else {
            let cast = candidate(
                "s1126-return-double-negation",
                "Replace with single return statement using \"!!\" cast",
                [(start, end, format!("return !!({test_text});"))],
            );
            let direct = candidate(
                "s1126-return-condition",
                "Replace with single return statement without cast (condition should be boolean!)",
                [(start, end, format!("return {test_text};"))],
            );
            self.emit(issue, cast);
            self.out.push((issue.index, direct));
        }
    }

    fn boolean_return(statement: &Statement<'_>) -> Option<bool> {
        match statement {
            Statement::ReturnStatement(return_statement) => {
                match return_statement.argument.as_ref() {
                    Some(Expression::BooleanLiteral(literal)) => Some(literal.value),
                    _ => None,
                }
            }
            Statement::BlockStatement(block) if block.body.len() == 1 => {
                Self::boolean_return(&block.body[0])
            }
            _ => None,
        }
    }

    fn is_boolean_expression(expression: &Expression<'_>) -> bool {
        match unparenthesized(expression) {
            Expression::UnaryExpression(unary) => unary.operator == UnaryOperator::LogicalNot,
            Expression::BinaryExpression(binary) => matches!(
                binary.operator,
                BinaryOperator::Equality
                    | BinaryOperator::StrictEquality
                    | BinaryOperator::Inequality
                    | BinaryOperator::StrictInequality
                    | BinaryOperator::LessThan
                    | BinaryOperator::LessEqualThan
                    | BinaryOperator::GreaterThan
                    | BinaryOperator::GreaterEqualThan
                    | BinaryOperator::In
                    | BinaryOperator::Instanceof
            ),
            _ => false,
        }
    }

    fn is_condition_root(&self, expression: &LogicalExpression<'_>) -> bool {
        let span = expression.span();
        self.condition_roots
            .last()
            .is_some_and(|root| root.0 == span.start && root.1 == span.end)
    }

    fn check_logical_operand(
        &mut self,
        expression: &LogicalExpression<'_>,
        operand: &Expression<'_>,
    ) {
        let Expression::BooleanLiteral(literal) = unparenthesized(operand) else {
            return;
        };
        let (start, end) = Self::span_bounds(literal.span());
        let Some(issue) = self.take_issue(Rule::S1125, start, end, false) else {
            return;
        };
        let other = if expression.left.span() == operand.span() {
            &expression.right
        } else {
            &expression.left
        };
        let Some(other_text) = self.text(other.span()) else {
            return;
        };
        let replacement = match expression.operator {
            LogicalOperator::And => {
                if literal.value {
                    other_text.to_owned()
                } else {
                    "false".to_owned()
                }
            }
            LogicalOperator::Or => {
                if literal.value {
                    "true".to_owned()
                } else {
                    other_text.to_owned()
                }
            }
            LogicalOperator::Coalesce => return,
        };
        self.emit(
            issue,
            candidate(
                "s1125-remove-boolean",
                "Remove the unnecessary boolean literal",
                [(
                    expression.span().start as usize,
                    expression.span().end as usize,
                    replacement,
                )],
            ),
        );
    }

    fn check_unary_boolean(&mut self, expression: &UnaryExpression<'_>) {
        if expression.operator != UnaryOperator::LogicalNot {
            return;
        }
        let Expression::BooleanLiteral(literal) = unparenthesized(&expression.argument) else {
            return;
        };
        let (start, end) = Self::span_bounds(literal.span());
        let Some(issue) = self.take_issue(Rule::S1125, start, end, false) else {
            return;
        };
        self.emit(
            issue,
            candidate(
                "s1125-remove-boolean",
                "Remove the unnecessary boolean literal",
                [(
                    expression.span().start as usize,
                    expression.span().end as usize,
                    if literal.value { "false" } else { "true" }.to_owned(),
                )],
            ),
        );
    }

    fn check_array_constructor(&mut self, expression: &NewExpression<'_>) {
        let Some(name) = identifier_name(&expression.callee) else {
            return;
        };
        let (start, end) = Self::span_bounds(expression.span());
        if name == "Array" {
            let Some(issue) = self.take_issue(Rule::S1528, start, end, false) else {
                return;
            };
            let args = expression
                .arguments
                .iter()
                .filter_map(|argument| self.text(argument.span()))
                .collect::<Vec<_>>();
            let (id, message, replacement) = match args.as_slice() {
                [] => (
                    "s1528-replace-with-literal",
                    "Replace with a literal",
                    "[]".to_owned(),
                ),
                [_one]
                    if expression
                        .arguments
                        .first()
                        .is_some_and(|argument| argument.as_expression().is_none()) =>
                {
                    // The pinned Array.from fixer blindly interpolates
                    // `...spread`, which is not a valid length expression.
                    // Withhold rather than inventing a non-equivalent literal
                    // rewrite for this unsupported syntax.
                    return;
                }
                [one] => (
                    "s1528-replace-with-array-from",
                    "Replace with \"Array.from()\"",
                    format!("Array.from({{length: {one}}})"),
                ),
                _ => (
                    "s1528-replace-with-literal",
                    "Replace with a literal",
                    format!("[{}]", args.join(", ")),
                ),
            };
            self.emit(issue, candidate(id, message, [(start, end, replacement)]));
            return;
        }

        if !matches!(name, "Boolean" | "Number" | "String") {
            return;
        }
        let Some(issue) = self.take_issue(Rule::S1533, start, end, false) else {
            return;
        };
        let Some(remove_end) = self.new_operator_end(expression) else {
            return;
        };
        self.emit(
            issue,
            candidate(
                "s1533-remove-new",
                "Remove \"new\" operator",
                [(start, remove_end, String::new())],
            ),
        );
    }

    fn new_operator_end(&self, expression: &NewExpression<'_>) -> Option<usize> {
        let start = expression.span.start as usize;
        let callee_start = expression.callee.span().start as usize;
        let new_token = self
            .token_between(start, callee_start, Kind::New)
            .or_else(|| {
                self.ctx
                    .tokens
                    .iter()
                    .find(|token| token.kind() == Kind::New && token.start() as usize == start)
            })?;
        let mut end = new_token.end() as usize;
        if let Some(next) = self
            .source()
            .get(end..callee_start)
            .and_then(|text| text.chars().next())
            && next.is_whitespace()
        {
            end += next.len_utf8();
        }
        Some(end)
    }

    fn check_type_wrapper(&mut self, ty: &TSType<'_>) {
        let TSType::TSTypeReference(reference) = ty else {
            return;
        };
        if reference.type_arguments.is_some() {
            return;
        }
        let TSTypeName::IdentifierReference(identifier) = &reference.type_name else {
            return;
        };
        let (id, message) = match identifier.name.as_str() {
            "Boolean" => (
                "s1533-replace-boolean-wrapper",
                "Replace \"Boolean\" with \"boolean\"",
            ),
            "Number" => (
                "s1533-replace-number-wrapper",
                "Replace \"Number\" with \"number\"",
            ),
            "String" => (
                "s1533-replace-string-wrapper",
                "Replace \"String\" with \"string\"",
            ),
            _ => return,
        };
        let (start, end) = Self::span_bounds(reference.span);
        let Some(issue) = self.take_issue(Rule::S1533, start, end, false) else {
            return;
        };
        self.emit(
            issue,
            candidate(
                id,
                message,
                [(start, end, identifier.name.to_ascii_lowercase())],
            ),
        );
    }

    fn check_comparison_inversion(&mut self, expression: &UnaryExpression<'_>) {
        if expression.operator != UnaryOperator::LogicalNot {
            return;
        }
        let Expression::BinaryExpression(binary) = unparenthesized(&expression.argument) else {
            return;
        };
        let inverted = match binary.operator {
            BinaryOperator::Equality => "!=",
            BinaryOperator::Inequality => "==",
            BinaryOperator::StrictEquality => "!==",
            BinaryOperator::StrictInequality => "===",
            BinaryOperator::GreaterThan => "<=",
            BinaryOperator::LessThan => ">=",
            BinaryOperator::GreaterEqualThan => "<",
            BinaryOperator::LessEqualThan => ">",
            _ => return,
        };
        let (start, end) = Self::span_bounds(expression.span());
        let Some(issue) = self.take_issue(Rule::S1940, start, end, false).or_else(|| {
            self.take_issue(
                Rule::S1940,
                binary.span().start as usize,
                binary.span().end as usize,
                true,
            )
        }) else {
            return;
        };
        let Some(left) = self.text(binary.left.span()) else {
            return;
        };
        let Some(right) = self.text(binary.right.span()) else {
            return;
        };
        let mut replacement = format!("{left} {inverted} {right}");
        if self.unary_depth > 0 {
            replacement = format!("({replacement})");
        }
        self.emit(
            issue,
            candidate(
                "s1940-invert-comparison",
                "Invert inner operation (apply if NaN is not expected)",
                [(start, end, replacement)],
            ),
        );
    }

    fn check_compound_assignment_unary(&mut self, unary: &UnaryExpression<'_>) {
        let (compound, unary_kind) = match unary.operator {
            UnaryOperator::UnaryPlus => ("+=", Kind::Plus),
            UnaryOperator::UnaryNegation => ("-=", Kind::Minus),
            UnaryOperator::LogicalNot => ("!=", Kind::Bang),
            _ => return,
        };
        let assignment_start = unary.span.start as usize;
        let Some(equal) = self
            .ctx
            .tokens
            .iter()
            .rev()
            .find(|token| token.kind() == Kind::Eq && token.end() as usize <= assignment_start)
        else {
            return;
        };
        let equal_start = equal.start() as usize;
        let equal_end = equal.end() as usize;
        if equal_end != assignment_start {
            return;
        }
        let Some(unary_token) = self.token_between(
            unary.span.start as usize,
            unary.argument.span().start as usize,
            unary_kind,
        ) else {
            return;
        };
        let unary_token_end = unary_token.end() as usize;
        if unary_token_end == unary.argument.span().start as usize {
            return;
        }
        let issue_start = equal_start;
        let issue_end = unary.span.start as usize + 1;
        let Some(issue) = self.take_issue(Rule::S2757, issue_start, issue_end, false) else {
            return;
        };
        self.emit(
            issue,
            candidate(
                "s2757-use-compound-assignment",
                "Replace with compound assignment operator",
                [(equal_start, unary_token_end, compound.to_owned())],
            ),
        );
    }

    fn check_dissimilar_equality(&mut self, expression: &BinaryExpression<'_>) {
        let (replacement, id, operator) = match expression.operator {
            BinaryOperator::StrictEquality => ("==", "s3403-use-loose-equality", "==="),
            BinaryOperator::StrictInequality => ("!=", "s3403-use-loose-inequality", "!=="),
            _ => return,
        };
        let Some((operator_start, operator_end)) = self.binary_operator_span(expression) else {
            return;
        };
        let Some(issue) = self
            .take_issue(Rule::S3403, operator_start, operator_end, false)
            .or_else(|| {
                self.take_issue(
                    Rule::S3403,
                    expression.span().start as usize,
                    expression.span().end as usize,
                    true,
                )
            })
        else {
            return;
        };
        self.emit(
            issue,
            candidate(
                id,
                if operator == "===" {
                    "Replace \"===\" with \"==\""
                } else {
                    "Replace \"!==\" with \"!=\""
                },
                [(operator_start, operator_end, replacement.to_owned())],
            ),
        );
    }

    fn check_size_comparison(&mut self, expression: &BinaryExpression<'_>) {
        if !matches!(
            expression.operator,
            BinaryOperator::LessThan | BinaryOperator::GreaterEqualThan
        ) {
            return;
        }
        let Some(member) = unparenthesized(&expression.left).as_member_expression() else {
            return;
        };
        if static_property_name(member) != Some("length")
            || !self.is_array_receiver(member.object())
        {
            return;
        }
        if !matches!(
            unparenthesized(&expression.right),
            Expression::NumericLiteral(number) if number.value == 0.0
        ) {
            return;
        }
        let (start, end) = Self::span_bounds(expression.span());
        let Some(issue) = self.take_issue(Rule::S3981, start, end, false) else {
            return;
        };
        let Some((operator_start, operator_end)) = self.binary_operator_span(expression) else {
            return;
        };
        let replacement = if expression.operator == BinaryOperator::LessThan {
            "=="
        } else {
            ">"
        };
        self.emit(
            issue,
            candidate(
                "s3981-fix-size-comparison",
                "Use the corrected collection size comparison",
                [(operator_start, operator_end, replacement.to_owned())],
            ),
        );
    }

    fn check_discarded_error(&mut self, expression: &NewExpression<'_>) {
        let (start, end) = Self::span_bounds(expression.span());
        let Some(issue) = self.take_issue(Rule::S3984, start, end, true) else {
            return;
        };
        let Some(callee) = self.text(expression.callee.span()) else {
            return;
        };
        if !(callee.ends_with("Error") || callee.ends_with("Exception")) {
            return;
        }
        self.emit(
            issue,
            candidate(
                "s3984-throw-error",
                "Throw this error",
                [(start, start, "throw ".to_owned())],
            ),
        );
    }

    fn is_array_receiver(&self, expression: &Expression<'_>) -> bool {
        match unparenthesized(expression) {
            Expression::ArrayExpression(_) => true,
            Expression::Identifier(identifier) => {
                let Some(reference_id) = identifier.reference_id.get() else {
                    return false;
                };
                let Some(symbol_id) = self
                    .semantic
                    .scoping()
                    .get_reference(reference_id)
                    .symbol_id()
                else {
                    return false;
                };
                if self.semantic.nodes().is_empty()
                    || self.semantic.scoping().symbol_is_mutated(symbol_id)
                {
                    return false;
                }
                matches!(
                    self.semantic.symbol_declaration(symbol_id).kind(),
                    AstKind::VariableDeclarator(declarator)
                        if declarator.init.as_ref().is_some_and(|init| {
                            matches!(unparenthesized(init), Expression::ArrayExpression(_))
                        })
                )
            }
            _ => false,
        }
    }

    fn check_in_operator(&mut self, expression: &BinaryExpression<'_>) {
        if expression.operator != BinaryOperator::In || !self.is_array_receiver(&expression.right) {
            return;
        }
        let left = unparenthesized(&expression.left);
        if matches!(left, Expression::NumericLiteral(_)) {
            return;
        }
        if matches!(
            left,
            Expression::StringLiteral(literal)
                if matches!(
                    literal.value.as_str(),
                    "indexOf"
                        | "lastIndexOf"
                        | "forEach"
                        | "map"
                        | "filter"
                        | "every"
                        | "some"
                )
        ) {
            return;
        }
        let (start, end) = Self::span_bounds(expression.span());
        let Some(issue) = self.take_issue(Rule::S4619, start, end, false) else {
            return;
        };
        let Some(left_text) = self.text(expression.left.span()).map(str::to_owned) else {
            return;
        };
        let Some(right_text) = self.text(expression.right.span()).map(str::to_owned) else {
            return;
        };
        let index_candidate = candidate(
            "s4619-use-index-of",
            "Replace with \"indexOf\" method",
            [(
                start,
                end,
                format!("{right_text}.indexOf({left_text}) > -1"),
            )],
        );
        let includes_candidate = candidate(
            "s4619-use-includes",
            "Replace with \"includes\" method",
            [(start, end, format!("{right_text}.includes({left_text})"))],
        );
        self.emit(issue, index_candidate);
        // Keep both upstream alternatives on the same original issue.
        self.out.push((issue.index, includes_candidate));
    }
}

impl<'a> Visit<'a> for Collector<'_, 'a> {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.check_if_boolean_return(it);
        let root = unparenthesized(&it.test).span();
        self.condition_roots.push((root.start, root.end));
        walk_if_statement(self, it);
        self.condition_roots.pop();
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        self.check_conditional_boolean_return(it);
        let root = unparenthesized(&it.test).span();
        self.condition_roots.push((root.start, root.end));
        walk_conditional_expression(self, it);
        self.condition_roots.pop();
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        self.check_boolean_binary(it);
        self.check_dissimilar_equality(it);
        self.check_size_comparison(it);
        self.check_in_operator(it);
        walk_binary_expression(self, it);
    }
    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        self.check_unary_boolean(it);
        self.check_comparison_inversion(it);
        self.unary_depth += 1;
        walk_unary_expression(self, it);
        self.unary_depth -= 1;
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.check_logical(it);
        walk_logical_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let Expression::UnaryExpression(unary) = &it.right {
            self.check_compound_assignment_unary(unary);
        }
        walk_assignment_expression(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        walk_variable_declarator(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        self.check_array_constructor(it);
        self.check_discarded_error(it);
        walk_new_expression(self, it);
    }

    fn visit_ts_type(&mut self, it: &TSType<'a>) {
        self.check_type_wrapper(it);
        oxc_ast_visit::walk::walk_ts_type(self, it);
    }
}
