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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s888_flags_loose_equality_in_for_test() {
        let loose = js_keys("for (let i = 0; i == n; i++) {}\n");
        assert_eq!(count_key(&loose, "javascript:S888"), 1);

        let strict = js_keys("for (let i = 0; i === n; i++) {}\n");
        assert_eq!(count_key(&strict, "javascript:S888"), 0);
    }

    #[test]
    fn s1264_flags_init_and_update_less_for_loops() {
        let bare = js_keys("for (;;) {\n  break;\n}\n");
        assert_eq!(count_key(&bare, "javascript:S1264"), 1);

        let counted = js_keys("for (let i = 0; i < n; i++) {\n  f(i);\n}\n");
        assert_eq!(count_key(&counted, "javascript:S1264"), 0);
    }

    #[test]
    fn s2251_flags_counter_moving_away_from_bound() {
        let away = js_keys("for (let i = 0; i < n; i--) {}\n");
        assert_eq!(count_key(&away, "javascript:S2251"), 1);

        let towards = js_keys("for (let i = 0; i > n; i--) {}\n");
        assert_eq!(count_key(&towards, "javascript:S2251"), 0);

        let incrementing_up = js_keys("for (let i = 0; i < n; i++) {}\n");
        assert_eq!(count_key(&incrementing_up, "javascript:S2251"), 0);
    }

    #[test]
    fn s1994_flags_update_clause_not_touching_counter() {
        let other_counter = js_keys("let j = 0;\nfor (let i = 0; i < n; j++) {}\n");
        assert_eq!(count_key(&other_counter, "javascript:S1994"), 1);

        let compound_update = js_keys("for (let i = 0; i < n; i += 2) {}\n");
        assert_eq!(count_key(&compound_update, "javascript:S1994"), 0);
    }

    #[test]
    fn s2310_flags_counter_writes_inside_loop_body() {
        let assigned = js_keys("for (let i = 0; i < n; i++) {\n  i = 5;\n}\n");
        assert_eq!(count_key(&assigned, "javascript:S2310"), 1);

        let updated = js_keys("for (let i = 0; i < n; i++) {\n  i++;\n}\n");
        assert_eq!(count_key(&updated, "javascript:S2310"), 1);

        let other_variable = js_keys("for (let i = 0; i < n; i++) {\n  j = 5;\n}\n");
        assert_eq!(count_key(&other_variable, "javascript:S2310"), 0);
    }

    #[test]
    fn s135_flags_more_than_one_direct_exit_point() {
        let two_breaks =
            js_keys("while (a) {\n  if (b) {\n    break;\n  }\n  if (c) {\n    break;\n  }\n}\n");
        assert_eq!(count_key(&two_breaks, "javascript:S135"), 1);

        let one_break = js_keys("while (a) {\n  if (b) {\n    break;\n  }\n  f();\n}\n");
        assert_eq!(count_key(&one_break, "javascript:S135"), 0);

        // Breaks inside a nested loop count for the inner loop only.
        let nested = js_keys(
            "while (a) {\n  if (b) {\n    break;\n  }\n  while (c) {\n    if (d) {\n      break;\n    }\n    break;\n  }\n}\n",
        );
        assert_eq!(count_key(&nested, "javascript:S135"), 1);
        let inner_line = nested
            .iter()
            .find(|(key, _)| key == "javascript:S135")
            .map(|(_, line)| *line);
        assert_eq!(inner_line, Some(5));
    }

    #[test]
    fn s1751_flags_single_iteration_loops() {
        let constant_false = js_keys("while (false) {\n  f();\n}\n");
        assert_eq!(count_key(&constant_false, "javascript:S1751"), 1);

        let terminal_break = js_keys("while (x) {\n  f();\n  break;\n}\n");
        assert_eq!(count_key(&terminal_break, "javascript:S1751"), 1);

        let continue_keeps_iterations =
            js_keys("while (x) {\n  if (y) {\n    continue;\n  }\n  break;\n}\n");
        assert_eq!(count_key(&continue_keeps_iterations, "javascript:S1751"), 0);

        let ordinary = js_keys("while (x) {\n  f();\n}\n");
        assert_eq!(count_key(&ordinary, "javascript:S1751"), 0);
    }

    #[test]
    fn s2189_flags_endless_loops_without_terminators() {
        let forever = js_keys("while (true) {\n  f();\n}\n");
        assert_eq!(count_key(&forever, "javascript:S2189"), 1);

        let do_forever = js_keys("do {\n  f();\n} while (true);\n");
        assert_eq!(count_key(&do_forever, "javascript:S2189"), 1);

        let with_break = js_keys("while (true) {\n  break;\n}\n");
        assert_eq!(count_key(&with_break, "javascript:S2189"), 0);

        let with_return = js_keys("function f() {\n  for (;;) {\n    return 1;\n  }\n}\n");
        assert_eq!(count_key(&with_return, "javascript:S2189"), 0);

        // JS-only rule: TypeScript files are never flagged.
        let typescript = findings("while (true) {\n  f();\n}\n", JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S2189"), 0);
    }

    #[test]
    fn s1535_requires_hasownproperty_guard_in_for_in() {
        let bare = js_keys("for (const k in obj) {\n  f(k);\n}\n");
        assert_eq!(count_key(&bare, "javascript:S1535"), 1);

        let guarded =
            js_keys("for (const k in obj) {\n  if (obj.hasOwnProperty(k)) {\n    f(k);\n  }\n}\n");
        assert_eq!(count_key(&guarded, "javascript:S1535"), 0);
    }

    #[test]
    fn s4139_flags_for_in_over_arrays_and_strings() {
        let array = js_keys("for (const v in [\"a\", \"b\"]) {\n  f(v);\n}\n");
        assert_eq!(count_key(&array, "javascript:S4139"), 1);

        let string = js_keys("for (const v in \"ab\") {\n  f(v);\n}\n");
        assert_eq!(count_key(&string, "javascript:S4139"), 1);

        let object = js_keys("for (const v in obj) {\n  f(v);\n}\n");
        assert_eq!(count_key(&object, "javascript:S4139"), 0);
    }

    #[test]
    fn s4138_flags_for_of_over_non_iterables() {
        let object = js_keys("for (const v of { a: 1 }) {\n  f(v);\n}\n");
        assert_eq!(count_key(&object, "javascript:S4138"), 1);

        let number = js_keys("for (const v of 5) {\n  f(v);\n}\n");
        assert_eq!(count_key(&number, "javascript:S4138"), 1);

        let array = js_keys("for (const v of [1, 2]) {\n  f(v);\n}\n");
        assert_eq!(count_key(&array, "javascript:S4138"), 0);
    }
}
