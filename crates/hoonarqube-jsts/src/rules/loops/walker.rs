// Family walker for 'loops' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::shared::call_property;
use crate::support::{
    IssueSink, LineIndex, RuleScope, assignment_target_name, binding_identifier_name, callee_name,
    identifier_name, is_identifier_byte, source_slice, unparenthesized, update_target_name,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    AssignmentExpression, BinaryOperator, BreakStatement, CallExpression, ContinueStatement,
    DoWhileStatement, Expression, ForInStatement, ForOfStatement, ForStatement, ForStatementInit,
    ReturnStatement, Statement, SwitchCase, ThrowStatement, UpdateExpression, UpdateOperator,
    WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_assignment_expression, walk_call_expression, walk_do_while_statement,
    walk_for_in_statement, walk_for_of_statement, walk_switch_case, walk_while_statement,
};
use oxc_span::{GetSpan, Span};

fn check_loop_rules(
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
        case_depth: 0,
        break_targets: Vec::new(),
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Construct that the nearest enclosing unlabeled `break` would exit.
#[derive(Clone, Copy, PartialEq)]
enum BreakTarget {
    /// An iteration statement: the break counts as a loop jump/terminator.
    Loop,
    /// A switch case consequent: the break only ends the case.
    Case,
}

/// Loop-shape rules in one traversal.
struct LoopFlowCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    /// One frame per lexically enclosing visited loop.
    frames: Vec<LoopFrame>,
    /// Nesting depth of switch cases; unlabeled breaks inside them target
    /// the switch, not the loop.
    case_depth: u32,
    /// Innermost-last stack of enclosing constructs an unlabeled `break`
    /// can target; the nearest entry decides loop jump vs case-break.
    break_targets: Vec<BreakTarget>,
}

impl<'a> LoopFlowCollector<'a, '_> {
    fn push_frame(&mut self) {
        self.frames.push(LoopFrame::default());
    }

    fn pop_frame(&mut self) -> LoopFrame {
        self.frames.pop().unwrap_or_default()
    }

    /// Whether any enclosing loop declares `name` as its counter.
    fn inside_counter_scope(&self, name: &str) -> bool {
        self.frames
            .iter()
            .any(|frame| frame.counters.iter().any(|counter| counter == name))
    }

    fn note_jump(&mut self, terminator: bool) {
        if let Some(frame) = self.frames.last_mut() {
            frame.jumps += 1;
            frame.terminators |= terminator;
        }
    }

    fn flag_many_jumps(&mut self, jumps: u32, span: Span) {
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
    fn finish_loop(&mut self, span: Span, endless: bool) {
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
    fn counter_name(it: &ForStatement<'a>) -> Option<String> {
        match it.init.as_ref()? {
            ForStatementInit::VariableDeclaration(declaration) => {
                let declarator = declaration.declarations.first()?;
                binding_identifier_name(&declarator.id).map(str::to_string)
            }
            _ => None,
        }
    }

    /// Operator relating the counter to a bound in the loop test.
    fn test_bound_operator(test: Option<&Expression<'_>>, counter: &str) -> Option<BinaryOperator> {
        let Expression::BinaryExpression(binary) = unparenthesized(test?) else {
            return None;
        };
        let involves_counter = identifier_name(&binary.left) == Some(counter)
            || identifier_name(&binary.right) == Some(counter);
        involves_counter.then_some(binary.operator)
    }

    /// `S2251`: the update moves the counter away from the tested bound.
    fn check_counter_direction(
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
    fn check_counter_updated(&mut self, it: &ForStatement<'a>, counter: &str) {
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
    fn check_constant_test(&mut self, test: Option<&Expression<'_>>, span: Span) {
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
    fn check_single_iteration_body(&mut self, body: &Statement<'a>) {
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
    fn visit_break_statement(&mut self, it: &BreakStatement) {
        if it.label.is_none() {
            // An unlabeled break exits the innermost enclosing breakable.
            // It counts as a loop jump/terminator only when that nearest
            // target is a loop; against a nearer switch case it is a
            // case-break and stays unaccounted.
            if self.break_targets.last() == Some(&BreakTarget::Loop) {
                self.note_jump(true);
            }
            return;
        }
        if self.case_depth > 0 {
            // Labeled breaks under a switch case may still target the
            // loop, so they keep the frame conservative without counting
            // as a loop jump.
            if let Some(frame) = self.frames.last_mut() {
                frame.terminators = true;
            }
            return;
        }
        self.note_jump(true);
    }

    fn visit_continue_statement(&mut self, _it: &ContinueStatement) {
        self.note_jump(false);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        self.case_depth += 1;
        self.break_targets.push(BreakTarget::Case);
        walk_switch_case(self, it);
        self.break_targets.pop();
        self.case_depth -= 1;
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
            // CE-parity: documented scope covers `==`/`!=`; the captured
            // engine additionally rejects the strict variants (oracle-js
            // `s888_good.js` fires on `i === n`). Documented exception kept:
            // tests against `null` are ignored. The step-by-one exception is
            // intentionally NOT implemented because the captured engine does
            // not honor it either (it flags `i === n` with an `i++` update).
            && let Some(operator_text) = loop_equality_operator_text(binary.operator)
            && !matches!(unparenthesized(&binary.left), Expression::NullLiteral(_))
            && !matches!(unparenthesized(&binary.right), Expression::NullLiteral(_))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S888",
                &format!("Replace '{operator_text}' operator with <=, >=, < or >."),
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
        self.break_targets.push(BreakTarget::Loop);
        if let Some(counter_name) = &counter
            && let Some(frame) = self.frames.last_mut()
        {
            frame.counters.push(counter_name.clone());
        }
        self.visit_statement(&it.body);
        self.break_targets.pop();
        self.finish_loop(it.span(), endless);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.check_constant_test(Some(&it.test), it.span());
        self.check_single_iteration_body(&it.body);
        let endless = is_constant_true(Some(&it.test));
        self.push_frame();
        self.break_targets.push(BreakTarget::Loop);
        walk_while_statement(self, it);
        self.break_targets.pop();
        self.finish_loop(it.span(), endless);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.check_constant_test(Some(&it.test), it.span());
        self.check_single_iteration_body(&it.body);
        let endless = is_constant_true(Some(&it.test));
        self.push_frame();
        self.break_targets.push(BreakTarget::Loop);
        walk_do_while_statement(self, it);
        self.break_targets.pop();
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
        self.break_targets.push(BreakTarget::Loop);
        walk_for_in_statement(self, it);
        self.break_targets.pop();
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
        self.break_targets.push(BreakTarget::Loop);
        walk_for_of_statement(self, it);
        self.break_targets.pop();
        let frame = self.pop_frame();
        self.flag_many_jumps(frame.jumps, it.span());
    }
}

/// Detects any `continue` below a loop body for the `S1751` exemption.
#[derive(Default)]
struct ContinueScanner {
    found: bool,
}

impl<'a> Visit<'a> for ContinueScanner {
    fn visit_continue_statement(&mut self, _it: &ContinueStatement<'a>) {
        self.found = true;
    }
}

/// Per-loop state collected while [`LoopFlowCollector`] walks one loop.
#[derive(Default)]
struct LoopFrame {
    /// Break/continue statements seen directly in this loop (`S135`).
    jumps: u32,
    /// Any break/return/throw seen anywhere below (`S2189`).
    terminators: bool,
    /// A `hasOwnProperty` reference was seen (`S1535`).
    has_own_guard: bool,
    /// Names of counters declared by this loop's init clause (`S2310`).
    counters: Vec<String>,
}

/// Whether `span`'s raw text contains `word` delimited by non-identifier
/// characters (used where the AST shape alone cannot tell which names an
/// arbitrary update expression references).
fn span_contains_word(source: &str, span: Span, word: &str) -> bool {
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
        search_from = begin + word.len();
    }
    false
}

/// Whether the expression is the boolean literal `false`.
fn is_constant_false(expression: Option<&Expression<'_>>) -> bool {
    matches!(
        expression.map(unparenthesized),
        Some(Expression::BooleanLiteral(literal)) if !literal.value
    )
}

/// Whether the expression is the boolean literal `true`.
fn is_constant_true(expression: Option<&Expression<'_>>) -> bool {
    match expression.map(unparenthesized) {
        Some(Expression::BooleanLiteral(literal)) => literal.value,
        _ => false,
    }
}

/// Operator text for the equality operators covered by `S888`, `None` for
/// every other operator.
fn loop_equality_operator_text(operator: BinaryOperator) -> Option<&'static str> {
    match operator {
        BinaryOperator::Equality => Some("=="),
        BinaryOperator::Inequality => Some("!="),
        BinaryOperator::StrictEquality => Some("==="),
        BinaryOperator::StrictInequality => Some("!=="),
        _ => None,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_loop_rules(ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s888_flags_loose_and_strict_equality_in_for_test() {
        let loose = js_keys("for (let i = 0; i == n; i++) {}\n");
        assert_eq!(count_key(&loose, "javascript:S888"), 1);

        // CE-parity pin: strict equality in a loop condition is equally
        // dangerous and flagged identically by the captured engine.
        let strict = js_keys("for (let i = 0; i === n; i++) {}\n");
        assert_eq!(count_key(&strict, "javascript:S888"), 1);
    }

    #[test]
    fn s888_flags_inequality_but_exempt_tests_against_null() {
        let inequality = js_keys("for (let i = 0; i != n; i += 2) {}\n");
        assert_eq!(count_key(&inequality, "javascript:S888"), 1);

        // Documented exception: comparisons against `null` are ignored.
        let null_test = js_keys("for (let i = 0; arr[i] != null; i++) {}\n");
        assert_eq!(count_key(&null_test, "javascript:S888"), 0);

        let strict_null_test = js_keys("for (let i = 0; arr[i] !== null; i++) {}\n");
        assert_eq!(count_key(&strict_null_test, "javascript:S888"), 0);
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
    fn s1994_multibyte_counter_embedded_in_longer_update_identifier() {
        let embedded = js_keys("for (let \u{3a9} = 0; \u{3a9} < 9; x\u{3a9}++) {}\n");
        assert_eq!(count_key(&embedded, "javascript:S1994"), 1);

        let touched = js_keys("for (let \u{e9} = 0; \u{e9} < 9; \u{e9}++) {}\n");
        assert_eq!(count_key(&touched, "javascript:S1994"), 0);
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
    #[test]
    fn s888_empty_init_for_with_loose_test_still_flags_lte_passes() {
        let loose = js_keys("for (; i == n;) {\n  f();\n}\n");
        assert_eq!(count_key(&loose, "javascript:S888"), 1);

        let lte = js_keys("for (let i = 0; i <= n; i++) {}\n");
        assert_eq!(count_key(&lte, "javascript:S888"), 0);
    }

    #[test]
    fn s1264_nested_counted_loops_and_while_forms_pass() {
        let nested = js_keys(
            "for (let i = 0; i < n; i++) {\n  for (let j = 0; j < m; j++) {\n    f(i, j);\n  }\n}\n",
        );
        assert_eq!(count_key(&nested, "javascript:S1264"), 0);

        let while_form = js_keys("while (a) {\n  break;\n}\n");
        assert_eq!(count_key(&while_form, "javascript:S1264"), 0);
    }

    #[test]
    fn s2251_increment_away_from_bound_flags_towards_decrement_passes() {
        let towards = js_keys("for (let i = n; i > 0; i--) {}\n");
        assert_eq!(count_key(&towards, "javascript:S2251"), 0);

        let upward_away = js_keys("for (let i = 0; i > n; i++) {}\n");
        assert_eq!(count_key(&upward_away, "javascript:S2251"), 1);
    }

    #[test]
    fn s1994_prefix_update_on_other_counter_flags_compound_self_update_passes() {
        let prefix_other = js_keys("let j = 0;\nfor (let i = 0; i < n; --j) {}\n");
        assert_eq!(count_key(&prefix_other, "javascript:S1994"), 1);

        let subtract_self = js_keys("for (let i = 0; i < n; i -= 1) {}\n");
        assert_eq!(count_key(&subtract_self, "javascript:S1994"), 0);
    }

    #[test]
    fn s2310_compound_assignment_to_counter_flags_other_target_passes() {
        let compound = js_keys("for (let i = 0; i < n; i++) {\n  i += 2;\n}\n");
        assert_eq!(count_key(&compound, "javascript:S2310"), 1);

        let other_target =
            js_keys("let total = 0;\nfor (let i = 0; i < n; i++) {\n  total += i;\n}\n");
        assert_eq!(count_key(&other_target, "javascript:S2310"), 0);
    }

    #[test]
    fn s135_counts_continue_like_break_but_return_is_not_counted() {
        let continues_only = js_keys(
            "while (a) {\n  if (b) {\n    continue;\n  }\n  if (c) {\n    continue;\n  }\n}\n",
        );
        assert_eq!(count_key(&continues_only, "javascript:S135"), 1);

        // A bare `return` is not one of the counted direct exit points here.
        let with_return = js_keys("function f(a) {\n  while (a) {\n    return 1;\n  }\n}\n");
        assert_eq!(count_key(&with_return, "javascript:S135"), 0);

        let mixed = js_keys(
            "function f(a, b) {\n  while (a) {\n    if (b) {\n      break;\n    }\n    continue;\n  }\n}\n",
        );
        assert_eq!(count_key(&mixed, "javascript:S135"), 1);
    }

    #[test]
    fn s1751_for_loop_terminal_break_uncovered_conditional_guard_passes() {
        // This subset flags single-iteration `while` forms only.
        let early_break = js_keys("for (let i = 0; i < n; i++) {\n  f(i);\n  break;\n}\n");
        assert_eq!(count_key(&early_break, "javascript:S1751"), 0);

        let conditional_break = js_keys("while (x) {\n  if (y) {\n    break;\n  }\n  f();\n}\n");
        assert_eq!(count_key(&conditional_break, "javascript:S1751"), 0);
    }

    #[test]
    fn s2189_conditional_break_terminates_endless_loop() {
        let guarded = js_keys("while (true) {\n  if (done) {\n    break;\n  }\n  f();\n}\n");
        assert_eq!(count_key(&guarded, "javascript:S2189"), 0);
    }

    #[test]
    fn s1535_bare_for_in_flags_even_without_body_use() {
        let bare = js_keys("for (const k in obj) {}\n");
        assert_eq!(count_key(&bare, "javascript:S1535"), 1);
    }

    #[test]
    fn s4139_for_of_over_array_does_not_trigger_for_in_rule() {
        let for_of = js_keys("for (const v of ['a', 'b']) {\n  f(v);\n}\n");
        assert_eq!(count_key(&for_of, "javascript:S4139"), 0);
    }

    #[test]
    fn s4138_string_iterable_passes() {
        let chars = js_keys("for (const ch of 'ab') {\n  f(ch);\n}\n");
        assert_eq!(count_key(&chars, "javascript:S4138"), 0);
    }

    #[test]
    fn switch_case_breaks_are_not_loop_jumps_or_terminators() {
        let trigger = js_keys(
            "for (const item of items) {\n  if (!item.ok) continue;\n  switch (item.kind) {\n    case 'a':\n      handleA(item);\n      break;\n    case 'b':\n      handleB(item);\n      break;\n  }\n}\n",
        );
        assert_eq!(count_key(&trigger, "javascript:S135"), 0);

        // An endless while whose only exit is an unlabeled switch break no
        // longer counts that break as a loop terminator...
        let endless =
            js_keys("while (true) {\n  switch (x) {\n    case 1:\n      break;\n  }\n}\n");
        assert_eq!(count_key(&endless, "javascript:S2189"), 1);
        assert_eq!(count_key(&endless, "javascript:S135"), 0);

        // ...while a labeled break targeting the loop still terminates it.
        let labeled = js_keys(
            "outer: while (true) {\n  switch (x) {\n    case 1:\n      break outer;\n  }\n}\n",
        );
        assert_eq!(count_key(&labeled, "javascript:S2189"), 0);
    }

    #[test]
    fn unlabeled_breaks_of_loops_nested_in_cases_are_loop_jumps_and_terminators() {
        // The innermost matching target of the bare `break` is the loop,
        // not the enclosing case, so it terminates the endless loop.
        let terminator = js_keys(
            "switch (x) {\n  case 1:\n    while (true) {\n      break;\n    }\n    break;\n}\n",
        );
        assert_eq!(count_key(&terminator, "javascript:S2189"), 0);

        // Such breaks also count toward the loop's jump budget (S135),
        // while the trailing case-level break stays unaccounted.
        let two_breaks = js_keys(
            "switch (x) {\n  case 1:\n    while (a) {\n      if (b) {\n        break;\n      }\n      if (c) {\n        break;\n      }\n    }\n    break;\n}\n",
        );
        assert_eq!(count_key(&two_breaks, "javascript:S135"), 1);
    }
}
