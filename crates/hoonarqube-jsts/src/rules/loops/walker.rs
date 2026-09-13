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
    ArrowFunctionExpression, AssignmentExpression, BinaryOperator, BreakStatement, CallExpression,
    ComputedMemberExpression, ContinueStatement, DoWhileStatement, Expression, ForInStatement,
    ForOfStatement, ForStatement, ForStatementInit, Function, IdentifierReference,
    MethodDefinition, ReturnStatement, Statement, StaticBlock, SwitchCase, ThisExpression,
    ThrowStatement, UnaryExpression, UnaryOperator, UpdateExpression, UpdateOperator,
    VariableDeclarationKind, VariableDeclarator, WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_call_expression,
    walk_computed_member_expression, walk_do_while_statement, walk_for_in_statement,
    walk_for_of_statement, walk_function, walk_identifier_reference, walk_static_block,
    walk_switch_case, walk_this_expression, walk_unary_expression, walk_update_expression,
    walk_variable_declarator, walk_while_statement,
};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;

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

    /// Control-flow jumps in a nested function cannot terminate an enclosing
    /// loop, but loops inside that function still need their own analysis.
    fn with_function_boundary(&mut self, walk: impl FnOnce(&mut Self)) {
        let frames = std::mem::take(&mut self.frames);
        let case_depth = self.case_depth;
        let break_targets = std::mem::take(&mut self.break_targets);
        self.case_depth = 0;
        walk(self);
        self.frames = frames;
        self.case_depth = case_depth;
        self.break_targets = break_targets;
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
            let keyword_len = ["while", "for", "do"]
                .into_iter()
                .find(|keyword| source_slice(self.source, span).starts_with(keyword))
                .map_or(0, str::len);
            let keyword_span = Span::new(
                span.start,
                span.start
                    .saturating_add(u32::try_from(keyword_len).unwrap_or_default()),
            );
            self.sink.emit_span(
                RuleScope::Both,
                "S135",
                "Reduce the total number of \"break\" and \"continue\" statements in this loop to use one at most.",
                keyword_span,
            );
        }
    }

    /// Loop-exit checks shared by counted loops (`for`, `while`, `do`).
    fn finish_loop(&mut self, span: Span, endless: bool) {
        let frame = self.pop_frame();
        self.flag_many_jumps(frame.jumps, span);
        if endless && !frame.terminators {
            let keyword_len = ["while", "for", "do"]
                .into_iter()
                .find(|keyword| source_slice(self.source, span).starts_with(keyword))
                .map_or(0, str::len);
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S2189",
                "Correct this loop's end condition to not be invariant.",
                Span::new(
                    span.start,
                    span.start
                        .saturating_add(u32::try_from(keyword_len).unwrap_or_default()),
                ),
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
            let direction = match update.operator {
                UpdateOperator::Increment => "incremented",
                UpdateOperator::Decrement => "decremented",
            };
            self.sink.emit_span(
                RuleScope::Both,
                "S2251",
                &format!("\"{counter}\" is {direction} and will never reach its stop condition."),
                update.span(),
            );
        }
    }

    /// `S1994`: the update clause never mentions the declared counter.
    fn check_counter_updated(&mut self, it: &ForStatement<'a>, counter: &str) {
        if let Some(update) = &it.update
            && !span_contains_word(self.source, update.span(), counter)
        {
            let tested = it.test.as_ref().map_or_else(
                || vec![counter],
                |test| identifier_tokens(source_slice(self.source, test.span())),
            );
            let updated = identifier_tokens(source_slice(self.source, update.span()));
            self.sink.emit_span(
                RuleScope::Both,
                "S1994",
                &format!(
                    "This loop's stop condition tests \"{}\" but the incrementer updates \"{}\".",
                    tested.join(", "),
                    updated.join(", ")
                ),
                Span::new(it.span.start, it.span.start.saturating_add(3)),
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

    /// `S4138`: a `.length`-bounded counter whose body only reads the same
    /// collection by counter index is a simple iteration that `for...of`
    /// expresses directly.
    fn check_simple_indexed_loop(&mut self, it: &ForStatement<'a>) {
        let Some(shape) = indexed_loop_shape(it, self.source) else {
            return;
        };
        let mut scan = IndexedBodyScan::new(&shape, self.source);
        scan.visit_statement(&it.body);
        if indexed_body_convertible(&shape, &scan) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4138",
                "Expected a \"for-of\" loop instead of a \"for\" loop with this simple iteration.",
                it.span(),
            );
        }
    }
}

/// The simple indexed-loop shape: one counter declared at `0`, tested
/// against `< reference.length`, and stepped by exactly one.
struct IndexedLoop {
    counter: String,
    /// Byte text of the collection reference in the test (`arr`,
    /// `this.items`); body reads must index this exact reference.
    collection_text: String,
    /// Root name the collection resolves from (`arr`, `this` in
    /// `this.items`).
    collection_root: String,
    /// `let`/`const` counters cannot leak a post-loop value, which keeps
    /// the unused-counter form convertible.
    block_scoped: bool,
}

/// Decomposes a `for` statement into the simple indexed-loop shape, or
/// `None` when any clause deviates.
fn indexed_loop_shape(it: &ForStatement<'_>, source: &str) -> Option<IndexedLoop> {
    let ForStatementInit::VariableDeclaration(declaration) = it.init.as_ref()? else {
        return None;
    };
    if declaration.declarations.len() != 1 {
        return None;
    }
    let declarator = declaration.declarations.first()?;
    let counter = binding_identifier_name(&declarator.id)?;
    let initializer = declarator.init.as_ref().map(unparenthesized)?;
    let Expression::NumericLiteral(zero) = initializer else {
        return None;
    };
    if zero.value != 0.0 {
        return None;
    }
    let test = unparenthesized(it.test.as_ref()?);
    let Expression::BinaryExpression(binary) = test else {
        return None;
    };
    if binary.operator != BinaryOperator::LessThan || identifier_name(&binary.left) != Some(counter)
    {
        return None;
    }
    let Expression::StaticMemberExpression(length) = unparenthesized(&binary.right) else {
        return None;
    };
    if length.property.name != "length" || !plain_collection_reference(&length.object) {
        return None;
    }
    let Expression::UpdateExpression(update) = unparenthesized(it.update.as_ref()?) else {
        return None;
    };
    if update.operator != UpdateOperator::Increment || update_target_name(update) != Some(counter) {
        return None;
    }
    Some(IndexedLoop {
        counter: counter.to_string(),
        collection_text: source_slice(source, length.object.span()).to_string(),
        collection_root: collection_root_name(&length.object)?,
        block_scoped: declaration.kind != VariableDeclarationKind::Var,
    })
}

/// Whether the expression is a plain collection reference: an identifier,
/// `this`, or a static member chain over such a base.
fn plain_collection_reference(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::Identifier(_) | Expression::ThisExpression(_) => true,
        Expression::StaticMemberExpression(member) => plain_collection_reference(&member.object),
        _ => false,
    }
}

/// Root name of a plain collection reference (`arr`, `this` in
/// `this.items`).
fn collection_root_name(expression: &Expression<'_>) -> Option<String> {
    match unparenthesized(expression) {
        Expression::Identifier(identifier) => Some(identifier.name.as_str().to_string()),
        Expression::ThisExpression(_) => Some("this".to_string()),
        Expression::StaticMemberExpression(member) => collection_root_name(&member.object),
        _ => None,
    }
}

/// Body facts for the `S4138` indexed-loop check: where the counter and
/// the collection root are referenced, where writes happen, and whether
/// anything defers or mutates beyond a plain element read.
struct IndexedBodyScan<'shape> {
    shape: &'shape IndexedLoop,
    source: &'shape str,
    function_depth: u32,
    /// Spans of `collection[counter]` computed members in this iteration.
    read_spans: Vec<Span>,
    /// Spans of the counter identifier inside those reads.
    index_spans: Vec<Span>,
    /// Spans of every counter identifier reference in the body.
    counter_refs: Vec<Span>,
    /// Spans of every reference to the collection root.
    root_refs: Vec<Span>,
    /// Spans whose contents are written: assignment targets, update
    /// arguments, and `delete` operands.
    write_spans: Vec<Span>,
    /// The collection itself is called as a method receiver.
    collection_called: bool,
    /// The collection root is referenced inside a nested function.
    deferred_reference: bool,
    /// The body declares a name shadowing the counter or collection root.
    shadowed: bool,
}

impl<'shape> IndexedBodyScan<'shape> {
    fn new(shape: &'shape IndexedLoop, source: &'shape str) -> Self {
        Self {
            shape,
            source,
            function_depth: 0,
            read_spans: Vec::new(),
            index_spans: Vec::new(),
            counter_refs: Vec::new(),
            root_refs: Vec::new(),
            write_spans: Vec::new(),
            collection_called: false,
            deferred_reference: false,
            shadowed: false,
        }
    }
}

impl<'a> Visit<'a> for IndexedBodyScan<'_> {
    fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
        if it.name.as_str() == self.shape.counter {
            self.counter_refs.push(it.span());
        }
        if it.name.as_str() == self.shape.collection_root {
            self.root_refs.push(it.span());
            self.deferred_reference |= self.function_depth > 0;
        }
        walk_identifier_reference(self, it);
    }

    fn visit_this_expression(&mut self, it: &ThisExpression) {
        if self.shape.collection_root == "this" {
            self.root_refs.push(it.span());
            self.deferred_reference |= self.function_depth > 0;
        }
        walk_this_expression(self, it);
    }

    fn visit_computed_member_expression(&mut self, it: &ComputedMemberExpression<'a>) {
        if self.function_depth == 0
            && source_slice(self.source, it.object.span()) == self.shape.collection_text
            && identifier_name(&it.expression) == Some(self.shape.counter.as_str())
        {
            self.read_spans.push(it.span());
            self.index_spans.push(it.expression.span());
        }
        walk_computed_member_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        self.write_spans.push(it.left.span());
        walk_assignment_expression(self, it);
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        self.write_spans.push(it.argument.span());
        walk_update_expression(self, it);
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        if it.operator == UnaryOperator::Delete {
            self.write_spans.push(it.argument.span());
        }
        walk_unary_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::StaticMemberExpression(member) = unparenthesized(&it.callee)
            && source_slice(self.source, member.object.span()) == self.shape.collection_text
        {
            self.collection_called = true;
        }
        walk_call_expression(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(name) = binding_identifier_name(&it.id)
            && (name == self.shape.counter || name == self.shape.collection_root)
        {
            self.shadowed = true;
        }
        walk_variable_declarator(self, it);
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        self.function_depth += 1;
        walk_function(self, it, flags);
        self.function_depth -= 1;
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.function_depth += 1;
        walk_arrow_function_expression(self, it);
        self.function_depth -= 1;
    }
}

/// Whether the scanned body keeps the loop safely expressible as
/// `for...of`: every counter reference is exactly an element-read index,
/// no element read is written through, the collection is neither called
/// nor assigned, and an unused counter cannot leak.
fn indexed_body_convertible(shape: &IndexedLoop, scan: &IndexedBodyScan<'_>) -> bool {
    if scan.collection_called || scan.deferred_reference || scan.shadowed {
        return false;
    }
    let written = |span: Span| {
        scan.write_spans
            .iter()
            .any(|write| write.contains_inclusive(span))
    };
    if scan.read_spans.iter().copied().any(written) || scan.root_refs.iter().copied().any(written) {
        return false;
    }
    if scan.counter_refs.iter().any(|reference| {
        !scan
            .index_spans
            .iter()
            .any(|index| index.start == reference.start && index.end == reference.end)
    }) {
        return false;
    }
    !scan.counter_refs.is_empty() || shape.block_scoped
}

fn identifier_tokens(source: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let bytes = source.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !is_identifier_byte(bytes[cursor]) || bytes[cursor].is_ascii_digit() {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while cursor < bytes.len() && is_identifier_byte(bytes[cursor]) {
            cursor += 1;
        }
        let name = &source[start..cursor];
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

impl<'a> Visit<'a> for LoopFlowCollector<'a, '_> {
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        self.with_function_boundary(|collector| walk_function(collector, it, flags));
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.with_function_boundary(|collector| walk_arrow_function_expression(collector, it));
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.with_function_boundary(|collector| walk_static_block(collector, it));
    }

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
                &format!("Remove this assignment of \"{name}\"."),
                it.left.span(),
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
                &format!("Remove this assignment of \"{name}\"."),
                it.argument.span(),
            );
        }
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.check_simple_indexed_loop(it);
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
                &format!(
                    "Replace '{operator_text}' operator with one of '<=', '>=', '<', or '>' comparison operators."
                ),
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
                "Use \"for...of\" to iterate over this \"Array\".",
                Span::new(it.span.start, it.span.start.saturating_add(3)),
            ),
            Expression::StringLiteral(_) => self.sink.emit_span(
                RuleScope::Both,
                "S4139",
                "Use \"for...of\" to iterate over this \"String\".",
                Span::new(it.span.start, it.span.start.saturating_add(3)),
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
                "Restrict what this loop acts on by testing each property.",
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

    fn visit_function(&mut self, _it: &Function<'a>, _flags: ScopeFlags) {}
    fn visit_arrow_function_expression(&mut self, _it: &ArrowFunctionExpression<'a>) {}
    fn visit_method_definition(&mut self, _it: &MethodDefinition<'a>) {}
    fn visit_static_block(&mut self, _it: &StaticBlock<'a>) {}
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
    fn method_computed_keys_stay_in_outer_loop_context() {
        let source = "for (let i = 0; i < n; i++) {\n  class C { [i = 1]() {} }\n}\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S2310"), 1);
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

    #[test]
    fn nested_function_jumps_do_not_terminate_or_exempt_outer_loops() {
        let endless = js_keys("while (true) {\n  const callback = () => { return; };\n}\n");
        assert_eq!(count_key(&endless, "javascript:S2189"), 1);

        let terminal = js_keys(
            "while (true) {\n  const callback = () => { while (ready) { continue; } };\n  break;\n}\n",
        );
        assert_eq!(count_key(&terminal, "javascript:S1751"), 1);
    }

    #[test]
    fn s4138_flags_simple_length_bounded_indexed_loops() {
        // #250: a `.length`-bounded counter whose body only reads the same
        // collection by counter index converts to `for...of`.
        let counter_index = js_keys("for (var i = 0; i < arr.length; i++) {\n  use(arr[i]);\n}\n");
        assert_eq!(count_key(&counter_index, "javascript:S4138"), 1);

        let element_chain =
            js_keys("for (let i = 0; i < items.length; i++) {\n  total += items[i].size;\n}\n");
        assert_eq!(count_key(&element_chain, "javascript:S4138"), 1);

        let member_collection =
            js_keys("for (let i = 0; i < this.items.length; i++) {\n  use(this.items[i]);\n}\n");
        assert_eq!(count_key(&member_collection, "javascript:S4138"), 1);

        // An unused block-scoped counter is a pure iteration (pinned
        // markdown-it emphasis loop), while a leaked `var` counter changes
        // its post-loop value under the conversion.
        let unused_let =
            js_keys("for (let i = 0; i < scanned.length; i++) {\n  push('text');\n}\n");
        assert_eq!(count_key(&unused_let, "javascript:S4138"), 1);

        let unused_var =
            js_keys("for (var i = 0; i < scanned.length; i++) {\n  push('text');\n}\n");
        assert_eq!(count_key(&unused_var, "javascript:S4138"), 0);

        let typed = ts_keys(
            "for (let i = 0; i < bytes.length; i++) {\n  out += String.fromCharCode(bytes[i]);\n}\n",
        );
        assert_eq!(count_key(&typed, "typescript:S4138"), 1);
    }

    #[test]
    fn s4138_unsafe_indexed_loops_stay_clean() {
        // Bound is not a `.length` member of a plain reference.
        let numeric_bound = js_keys("for (let i = 0; i < 10; i++) {\n  use(arr[i]);\n}\n");
        assert_eq!(count_key(&numeric_bound, "javascript:S4138"), 0);

        let computed_bound =
            js_keys("for (let i = 0; i < parts[0].length; i++) {\n  use(parts[0][i]);\n}\n");
        assert_eq!(count_key(&computed_bound, "javascript:S4138"), 0);

        // Counter reassigned, referenced outside the index position, or
        // stepped by other than one.
        let counter_mutated = js_keys("for (let i = 0; i < arr.length; i++) {\n  i = 5;\n}\n");
        assert_eq!(count_key(&counter_mutated, "javascript:S4138"), 0);

        let counter_elsewhere =
            js_keys("for (let i = 0; i < arr.length; i++) {\n  use(i, arr[i]);\n}\n");
        assert_eq!(count_key(&counter_elsewhere, "javascript:S4138"), 0);

        let step_two = js_keys("for (let i = 0; i < arr.length; i += 2) {\n  use(arr[i]);\n}\n");
        assert_eq!(count_key(&step_two, "javascript:S4138"), 0);

        // Elements written through the index, or the collection itself
        // grown/mutated, change under the conversion.
        let element_write = js_keys("for (let i = 0; i < arr.length; i++) {\n  arr[i] = 0;\n}\n");
        assert_eq!(count_key(&element_write, "javascript:S4138"), 0);

        let collection_mutated =
            js_keys("for (let i = 0; i < arr.length; i++) {\n  arr.push(i);\n}\n");
        assert_eq!(count_key(&collection_mutated, "javascript:S4138"), 0);

        // Deferred reads and writes inside closures are not provable.
        let deferred_read =
            js_keys("for (let i = 0; i < arr.length; i++) {\n  queue(() => arr[i]);\n}\n");
        assert_eq!(count_key(&deferred_read, "javascript:S4138"), 0);

        let deferred_mutation =
            js_keys("for (let i = 0; i < arr.length; i++) {\n  queue(() => arr.pop());\n}\n");
        assert_eq!(count_key(&deferred_mutation, "javascript:S4138"), 0);

        // Indexing a different collection, inclusive bounds, and shadowing
        // declarations stay clean.
        let other_collection =
            js_keys("for (let i = 0; i < arr.length; i++) {\n  use(other[i]);\n}\n");
        assert_eq!(count_key(&other_collection, "javascript:S4138"), 0);

        let inclusive = js_keys("for (let i = 0; i <= arr.length; i++) {\n  use(arr[i]);\n}\n");
        assert_eq!(count_key(&inclusive, "javascript:S4138"), 0);

        let shadowed =
            js_keys("for (let i = 0; i < arr.length; i++) {\n  let i = 1;\n  use(i);\n}\n");
        assert_eq!(count_key(&shadowed, "javascript:S4138"), 0);
    }

    #[test]
    fn s4138_reports_pinned_project_indexed_loops() {
        // #250: verbatim sources of express@53d4a0d6, axios@18e7dfed,
        // zod@46da9572, and markdown-it@3c51991c (all MIT). SonarQube
        // 26.8.0.126808 (Sonar way) reports exactly these loops; line and
        // column numbers match the pinned files.
        let sites = |report: &hoonarqube_ir::FileReport| -> Vec<(u32, u32)> {
            report
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S4138"))
                .map(|issue| (issue.range.start.line, issue.range.start.column))
                .collect()
        };

        let express = js(include_str!(
            "../../../fixtures/shapes/express-application.js"
        ));
        assert_eq!(sites(&express), vec![(324, 4), (498, 2)]);

        let axios = js(include_str!("../../../fixtures/shapes/axios-cookies.js"));
        assert_eq!(sites(&axios), vec![(39, 8)]);

        let util = ts(include_str!("../../../fixtures/shapes/zod-util.ts"));
        assert_eq!(sites(&util), vec![(1072, 2)]);

        let block = ts(include_str!(
            "../../../fixtures/shapes/markdown-it-parser_block.ts"
        ));
        assert_eq!(sites(&block), vec![(51, 4)]);

        let core = ts(include_str!(
            "../../../fixtures/shapes/markdown-it-parser_core.ts"
        ));
        assert_eq!(sites(&core), vec![(42, 4)]);

        let inline = ts(include_str!(
            "../../../fixtures/shapes/markdown-it-parser_inline.ts"
        ));
        assert_eq!(sites(&inline), vec![(78, 4), (82, 4)]);

        let quotes = ts(include_str!(
            "../../../fixtures/shapes/markdown-it-smartquotes.ts"
        ));
        assert_eq!(sites(&quotes), vec![(66, 2)]);

        let emphasis = ts(include_str!(
            "../../../fixtures/shapes/markdown-it-emphasis.ts"
        ));
        assert_eq!(sites(&emphasis), vec![(19, 2)]);
    }
}
