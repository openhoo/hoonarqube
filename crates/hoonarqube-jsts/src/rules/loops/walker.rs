// Family walker for 'loops' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::expression::walker::call_property;
use crate::support::{
    IssueSink, LineIndex, RuleScope, assignment_target_name, binding_identifier_name, callee_name,
    identifier_name, is_identifier_byte, source_slice, unparenthesized, update_target_name,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    AssignmentExpression, BinaryOperator, BreakStatement, CallExpression, ContinueStatement,
    DoWhileStatement, Expression, ForInStatement, ForOfStatement, ForStatement, ForStatementInit,
    ReturnStatement, Statement, ThrowStatement, UpdateExpression, UpdateOperator, WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_assignment_expression, walk_call_expression, walk_do_while_statement,
    walk_for_in_statement, walk_for_of_statement, walk_while_statement,
};
use oxc_span::{GetSpan, Span};

pub(crate) fn check_loop_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = LoopFlowCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        frames: Vec::new(),
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Loop-shape rules in one traversal.
pub(crate) struct LoopFlowCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) source: &'a str,
    /// One frame per lexically enclosing visited loop.
    pub(crate) frames: Vec<LoopFrame>,
}

impl<'a> LoopFlowCollector<'a, '_> {
    pub(crate) fn push_frame(&mut self) {
        self.frames.push(LoopFrame::default());
    }

    pub(crate) fn pop_frame(&mut self) -> LoopFrame {
        self.frames.pop().unwrap_or_default()
    }

    /// Whether any enclosing loop declares `name` as its counter.
    pub(crate) fn inside_counter_scope(&self, name: &str) -> bool {
        self.frames
            .iter()
            .any(|frame| frame.counters.iter().any(|counter| counter == name))
    }

    pub(crate) fn note_jump(&mut self, terminator: bool) {
        if let Some(frame) = self.frames.last_mut() {
            frame.jumps += 1;
            frame.terminators |= terminator;
        }
    }

    pub(crate) fn flag_many_jumps(&mut self, jumps: u32, span: Span) {
        if jumps > 1 {
            self.sink.emit_span(
                RuleScope::Both,
                "S135",
                "Reduce the number of break and continue statements in this loop to at most one.",
                span,
            );
        }
    }

    /// Loop-exit checks shared by counted loops (`for`, `while`, `do`).
    pub(crate) fn finish_loop(&mut self, span: Span, endless: bool) {
        let frame = self.pop_frame();
        self.flag_many_jumps(frame.jumps, span);
        if endless && !frame.terminators {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S2189",
                "Refactor this loop; it currently loops forever.",
                span,
            );
        }
    }

    /// Name of the counter declared by the loop's init clause (`let i = 0`).
    pub(crate) fn counter_name(it: &ForStatement<'a>) -> Option<String> {
        match it.init.as_ref()? {
            ForStatementInit::VariableDeclaration(declaration) => {
                let declarator = declaration.declarations.first()?;
                binding_identifier_name(&declarator.id).map(str::to_string)
            }
            _ => None,
        }
    }

    /// Operator relating the counter to a bound in the loop test.
    pub(crate) fn test_bound_operator(
        test: Option<&Expression<'_>>,
        counter: &str,
    ) -> Option<BinaryOperator> {
        let Expression::BinaryExpression(binary) = unparenthesized(test?) else {
            return None;
        };
        let involves_counter = identifier_name(&binary.left) == Some(counter)
            || identifier_name(&binary.right) == Some(counter);
        involves_counter.then_some(binary.operator)
    }

    /// `S2251`: the update moves the counter away from the tested bound.
    pub(crate) fn check_counter_direction(
        &mut self,
        it: &ForStatement<'a>,
        counter: &str,
        operator: BinaryOperator,
    ) {
        let Some(Expression::UpdateExpression(update)) = it.update.as_ref().map(unparenthesized)
        else {
            return;
        };
        if update_target_name(update) != Some(counter) {
            return;
        }
        let conflicts = if update.operator == UpdateOperator::Increment {
            operator == BinaryOperator::GreaterThan
        } else {
            operator == BinaryOperator::LessThan
        };
        if conflicts {
            self.sink.emit_span(
                RuleScope::Both,
                "S2251",
                "The loop counter moves away from the bound tested by this loop condition.",
                update.span(),
            );
        }
    }

    /// `S1994`: the update clause never mentions the declared counter.
    pub(crate) fn check_counter_updated(&mut self, it: &ForStatement<'a>, counter: &str) {
        if let Some(update) = &it.update
            && !span_contains_word(self.source, update.span(), counter)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S1994",
                "Modify the loop counter in the update clause or remove the clause.",
                update.span(),
            );
        }
    }

    /// `S1751` constant-false form.
    pub(crate) fn check_constant_test(&mut self, test: Option<&Expression<'_>>, span: Span) {
        if is_constant_false(test) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1751",
                "This loop runs at most once; replace it with a conditional statement.",
                span,
            );
        }
    }

    /// `S1751` terminal-break form: a block body whose last statement is a
    /// bare break, provided no continue anywhere in the body can loop back
    /// to another iteration.
    pub(crate) fn check_single_iteration_body(&mut self, body: &Statement<'a>) {
        let Statement::BlockStatement(block) = body else {
            return;
        };
        if !matches!(block.body.last(), Some(Statement::BreakStatement(_))) {
            return;
        }
        let mut scanner = ContinueScanner::default();
        scanner.visit_statement(body);
        if scanner.found {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S1751",
            "This loop runs at most once; replace it with a conditional statement.",
            body.span(),
        );
    }
}

impl<'a> Visit<'a> for LoopFlowCollector<'a, '_> {
    fn visit_break_statement(&mut self, _it: &BreakStatement) {
        self.note_jump(true);
    }

    fn visit_continue_statement(&mut self, _it: &ContinueStatement) {
        self.note_jump(false);
    }

    fn visit_return_statement(&mut self, _it: &ReturnStatement) {
        if let Some(frame) = self.frames.last_mut() {
            frame.terminators = true;
        }
    }

    fn visit_throw_statement(&mut self, _it: &ThrowStatement) {
        if let Some(frame) = self.frames.last_mut() {
            frame.terminators = true;
        }
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let guard = callee_name(it).is_some_and(|name| name == "hasOwnProperty")
            || call_property(it).is_some_and(|(property, _)| property == "hasOwnProperty");
        if guard && let Some(frame) = self.frames.last_mut() {
            frame.has_own_guard = true;
        }
        walk_call_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let Some(name) = assignment_target_name(&it.left)
            && self.inside_counter_scope(name)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2310",
                "Remove this assignment of the loop counter inside the loop body.",
                it.span(),
            );
        }
        walk_assignment_expression(self, it);
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        if let Some(name) = update_target_name(it)
            && self.inside_counter_scope(name)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2310",
                "Remove this modification of the loop counter inside the loop body.",
                it.span(),
            );
        }
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(test) = &it.test
            && let Expression::BinaryExpression(binary) = unparenthesized(test)
            && matches!(
                binary.operator,
                BinaryOperator::Equality | BinaryOperator::Inequality
            )
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S888",
                "Use a strict comparison in this loop condition.",
                test.span(),
            );
        }
        if it.init.is_none() && it.update.is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S1264",
                "This for loop lacks init and update clauses; use a while loop instead.",
                it.span(),
            );
        }
        let counter = Self::counter_name(it);
        if let Some(counter_name) = counter.as_deref() {
            if let Some(operator) = Self::test_bound_operator(it.test.as_ref(), counter_name) {
                self.check_counter_direction(it, counter_name, operator);
            }
            self.check_counter_updated(it, counter_name);
        }
        let endless = it.test.is_none();
        self.push_frame();
        if let Some(counter_name) = &counter
            && let Some(frame) = self.frames.last_mut()
        {
            frame.counters.push(counter_name.clone());
        }
        self.visit_statement(&it.body);
        self.finish_loop(it.span(), endless);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.check_constant_test(Some(&it.test), it.span());
        self.check_single_iteration_body(&it.body);
        let endless = is_constant_true(Some(&it.test));
        self.push_frame();
        walk_while_statement(self, it);
        self.finish_loop(it.span(), endless);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.check_constant_test(Some(&it.test), it.span());
        self.check_single_iteration_body(&it.body);
        let endless = is_constant_true(Some(&it.test));
        self.push_frame();
        walk_do_while_statement(self, it);
        self.finish_loop(it.span(), endless);
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        match unparenthesized(&it.right) {
            Expression::ArrayExpression(_) => self.sink.emit_span(
                RuleScope::Both,
                "S4139",
                "Do not use for-in to iterate over an array.",
                it.right.span(),
            ),
            Expression::StringLiteral(_) => self.sink.emit_span(
                RuleScope::Both,
                "S4139",
                "Do not use for-in to iterate over a string.",
                it.right.span(),
            ),
            _ => {}
        }
        self.push_frame();
        walk_for_in_statement(self, it);
        let frame = self.pop_frame();
        if !frame.has_own_guard {
            self.sink.emit_span(
                RuleScope::Both,
                "S1535",
                "Guard this for-in loop with a hasOwnProperty check.",
                it.span(),
            );
        }
        self.flag_many_jumps(frame.jumps, it.span());
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        match unparenthesized(&it.right) {
            Expression::NumericLiteral(_) => self.sink.emit_span(
                RuleScope::Both,
                "S4138",
                "Do not use for-of to iterate over a number.",
                it.right.span(),
            ),
            Expression::ObjectExpression(_) => self.sink.emit_span(
                RuleScope::Both,
                "S4138",
                "Do not use for-of to iterate over an object literal.",
                it.right.span(),
            ),
            _ => {}
        }
        self.push_frame();
        walk_for_of_statement(self, it);
        let frame = self.pop_frame();
        self.flag_many_jumps(frame.jumps, it.span());
    }
}

/// Detects any `continue` below a loop body for the `S1751` exemption.
#[derive(Default)]
pub(crate) struct ContinueScanner {
    pub(crate) found: bool,
}

impl<'a> Visit<'a> for ContinueScanner {
    fn visit_continue_statement(&mut self, _it: &ContinueStatement<'a>) {
        self.found = true;
    }
}

/// Per-loop state collected while [`LoopFlowCollector`] walks one loop.
#[derive(Default)]
pub(crate) struct LoopFrame {
    /// Break/continue statements seen directly in this loop (`S135`).
    pub(crate) jumps: u32,
    /// Any break/return/throw seen anywhere below (`S2189`).
    pub(crate) terminators: bool,
    /// A `hasOwnProperty` reference was seen (`S1535`).
    pub(crate) has_own_guard: bool,
    /// Names of counters declared by this loop's init clause (`S2310`).
    pub(crate) counters: Vec<String>,
}

/// Whether `span`'s raw text contains `word` delimited by non-identifier
/// characters (used where the AST shape alone cannot tell which names an
/// arbitrary update expression references).
pub(crate) fn span_contains_word(source: &str, span: Span, word: &str) -> bool {
    let text = source_slice(source, span);
    let bytes = text.as_bytes();
    let mut search_from = 0;
    while let Some(offset) = text[search_from..].find(word) {
        let begin = search_from + offset;
        let end = begin + word.len();
        let before_ok = begin == 0 || !is_identifier_byte(bytes[begin - 1]);
        let after_ok = end == bytes.len() || !is_identifier_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        search_from = begin + 1;
    }
    false
}

/// Whether the expression is the boolean literal `false`.
pub(crate) fn is_constant_false(expression: Option<&Expression<'_>>) -> bool {
    matches!(
        expression.map(unparenthesized),
        Some(Expression::BooleanLiteral(literal)) if !literal.value
    )
}

/// Whether the expression is the boolean literal `true`.
pub(crate) fn is_constant_true(expression: Option<&Expression<'_>>) -> bool {
    match expression.map(unparenthesized) {
        Some(Expression::BooleanLiteral(literal)) => literal.value,
        _ => false,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_loop_rules(ctx.program, ctx.source, ctx.index, ctx.language)
}
