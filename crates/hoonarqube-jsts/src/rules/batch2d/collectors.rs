// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::expression::walker::{call_property, is_equality_operator};
use crate::rules::react_jsx::walker::duplicated_key_name;
use crate::rules::statement_sequences::s1488_scan_statement_sequence::statement_ends_with_jump;
use crate::support::ast::constructor_name;
use crate::support::{
    IssueSink, LineIndex, RuleScope, assignment_target_name, binding_identifier_name,
    identifier_name, member_object, member_root_name, member_rooted_at, property_key_name,
    statement_as_expression, static_property_name, to_u32, unparenthesized,
};
use oxc_ast::ast::RegExpFlags;
use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, AssignmentOperator, BinaryExpression,
    BinaryOperator, BlockStatement, BreakStatement, CallExpression, Class, ClassElement,
    ConditionalExpression, ContinueStatement, Declaration, DoWhileStatement, ExportDeclaration,
    Expression, ForInStatement, ForOfStatement, ForStatement, FormalParameters, Function,
    FunctionBody, IfStatement, LogicalExpression, LogicalOperator, MemberExpression,
    MethodDefinition, MethodDefinitionKind, NewExpression, ObjectExpression, ObjectPropertyKind,
    PropertyKind, ReturnStatement, SimpleAssignmentTarget, Statement, StaticBlock, SwitchStatement,
    TryStatement, UnaryExpression, UnaryOperator, VariableDeclarationKind, WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_block_statement;
use oxc_ast_visit::walk::walk_function_body;
use oxc_ast_visit::walk::walk_program;
use oxc_ast_visit::walk::walk_static_block;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_binary_expression,
    walk_break_statement, walk_call_expression, walk_class, walk_conditional_expression,
    walk_continue_statement, walk_declaration, walk_do_while_statement, walk_export_declaration,
    walk_expression, walk_for_in_statement, walk_for_of_statement, walk_for_statement,
    walk_formal_parameters, walk_if_statement, walk_logical_expression, walk_member_expression,
    walk_method_definition, walk_new_expression, walk_object_expression, walk_switch_statement,
    walk_try_statement, walk_unary_expression, walk_while_statement,
};
use oxc_span::{GetSpan, Span};
use std::collections::BTreeSet;

/// `S3776`: functions exceeding this cognitive complexity are flagged
/// (frozen catalog default of the `threshold` parameter).
pub(crate) const MAX_COGNITIVE_COMPLEXITY: u32 = 15;

/// `S1541`: functions exceeding this cyclomatic complexity are flagged
/// (frozen catalog default of `maximumFunctionComplexityThreshold`).
pub(crate) const MAX_CYCLOMATIC_COMPLEXITY: u32 = 10;

/// `S3796`: array methods whose callbacks are expected to return values.
/// `forEach` is deliberately absent — its callbacks legitimately produce
/// nothing, so they never carry a missing-return defect.
pub(crate) const ARRAY_CALLBACK_METHODS: [&str; 10] = [
    "every",
    "filter",
    "find",
    "findIndex",
    "flatMap",
    "map",
    "reduce",
    "reduceRight",
    "some",
    "sort",
];

/// Collects `return` statements outside nested functions, split into
/// value-carrying and bare returns (`S3796`, `S3801`, `S6635`).
#[derive(Default)]
pub(crate) struct ReturnMixScanner {
    pub(crate) valued_spans: Vec<Span>,
    pub(crate) bare_spans: Vec<Span>,
}

impl<'a> Visit<'a> for ReturnMixScanner {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if it.argument.is_some() {
            self.valued_spans.push(it.span());
        } else {
            self.bare_spans.push(it.span());
        }
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, _it: &MethodDefinition<'a>) {}

    fn visit_static_block(&mut self, _it: &StaticBlock<'a>) {}
}

/// Whether one function body carries no value-returning statement outside
/// nested functions (`S3796`).
pub(crate) fn lacks_valued_return(body: &FunctionBody<'_>) -> bool {
    let mut scanner = ReturnMixScanner::default();
    scanner.visit_function_body(body);
    scanner.valued_spans.is_empty()
}

/// Computes the cognitive (`S3776`) and cyclomatic (`S1541`) complexity of
/// one function unit. Nesting weights follow the Sonar model: control-flow
/// structures add `1 + nesting`, `else if` chains stay flat, logical
/// operators count once per consecutive sequence of the same operator, and
/// nested function units are excluded entirely.
#[derive(Default)]
pub(crate) struct ComplexityWalker {
    pub(crate) cognitive: u32,
    pub(crate) cyclomatic: u32,
    pub(crate) nesting: u32,
    /// Operator of the logical chain currently walked; entering a chain (or
    /// switching operators mid-chain) adds one increment.
    pub(crate) logic_chain: Option<LogicalOperator>,
}

impl<'a> Visit<'a> for ComplexityWalker {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.process_if(it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.enter_nested(|walker| walk_for_statement(walker, it));
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.enter_nested(|walker| walk_for_in_statement(walker, it));
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.enter_nested(|walker| walk_for_of_statement(walker, it));
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.enter_nested(|walker| walk_while_statement(walker, it));
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.enter_nested(|walker| walk_do_while_statement(walker, it));
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        self.cognitive += 1 + self.nesting;
        let tested_cases =
            u32::try_from(it.cases.iter().filter(|case| case.test.is_some()).count())
                .unwrap_or(u32::MAX);
        self.cyclomatic += tested_cases;
        self.enter_nested(|walker| walk_switch_statement(walker, it));
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        for statement in &it.block.body {
            self.visit_statement(statement);
        }
        if let Some(handler) = &it.handler {
            self.cognitive += 1 + self.nesting;
            self.cyclomatic += 1;
            let saved = self.nesting;
            self.nesting += 1;
            self.visit_catch_clause(handler);
            self.nesting = saved;
        }
        if let Some(finalizer) = &it.finalizer {
            for statement in &finalizer.body {
                self.visit_statement(statement);
            }
        }
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        self.cognitive += 1 + self.nesting;
        self.cyclomatic += 1;
        self.visit_expression(&it.test);
        let saved = self.nesting;
        self.nesting += 1;
        walk_conditional_expression(self, it);
        self.nesting = saved;
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        if self.logic_chain != Some(it.operator) {
            self.cognitive += 1;
            self.cyclomatic += 1;
        }
        let saved_chain = self.logic_chain;
        self.logic_chain = Some(it.operator);
        walk_logical_expression(self, it);
        self.logic_chain = saved_chain;
    }

    fn visit_break_statement(&mut self, it: &BreakStatement<'a>) {
        if it.label.is_some() {
            self.cognitive += 1;
        }
        walk_break_statement(self, it);
    }

    fn visit_continue_statement(&mut self, it: &ContinueStatement<'a>) {
        if it.label.is_some() {
            self.cognitive += 1;
        }
        walk_continue_statement(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, _it: &MethodDefinition<'a>) {}

    fn visit_static_block(&mut self, _it: &StaticBlock<'a>) {}
}

impl ComplexityWalker {
    /// One `if` increment; `else if` links are processed flat so a chained
    /// conditional adds no extra nesting weight.
    fn process_if(&mut self, it: &IfStatement<'_>) {
        self.cognitive += 1 + self.nesting;
        self.cyclomatic += 1;
        self.visit_expression(&it.test);
        let saved = self.nesting;
        self.nesting += 1;
        self.visit_statement(&it.consequent);
        self.nesting = saved;
        if let Some(Statement::IfStatement(inner)) = &it.alternate {
            self.process_if(inner);
        } else if let Some(alternate) = &it.alternate {
            self.nesting += 1;
            self.visit_statement(alternate);
            self.nesting = saved;
        }
    }

    /// Walks one loop-like construct: `1 + nesting` increments with all
    /// contents nested one level deeper.
    fn enter_nested(&mut self, walk_children: impl FnOnce(&mut Self)) {
        self.cognitive += 1 + self.nesting;
        self.cyclomatic += 1;
        let saved = self.nesting;
        self.nesting += 1;
        walk_children(self);
        self.nesting = saved;
    }
}

/// `S3776`, `S1541`, `S3801`, and `S3796` in one traversal. Every function
/// unit is measured on entry; nested units are measured separately when the
/// descent reaches them.
pub(crate) struct FunctionMetricsCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for FunctionMetricsCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            let exempt = function.generator;
            self.analyze_function(function, function.span(), exempt, |collector| {
                walk_expression(collector, it);
            });
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            let exempt = function.generator;
            self.analyze_function(function, function.span(), exempt, |collector| {
                walk_declaration(collector, it);
            });
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        let exempt = it.kind != MethodDefinitionKind::Method || it.value.generator;
        self.analyze_function(&it.value, it.value.span(), exempt, |collector| {
            walk_method_definition(collector, it);
        });
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        if let Some(body) = it.body.as_function_body() {
            self.report_unit(body, it.span(), false);
        } else {
            self.report_expression_unit(it.body.to_expression(), it.span());
        }
        walk_arrow_function_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // `S3796`: array-method callbacks without any value-returning
        // statement (JavaScript-only).
        if let Some((property, _member)) = call_property(it)
            && ARRAY_CALLBACK_METHODS.contains(&property)
            && let Some(callback) = it.arguments.first().and_then(argument_expression)
        {
            let missing = match callback {
                Expression::FunctionExpression(function) => function
                    .body
                    .as_ref()
                    .is_some_and(|body| lacks_valued_return(body)),
                Expression::ArrowFunctionExpression(arrow) => arrow
                    .body
                    .as_function_body()
                    .is_some_and(lacks_valued_return),
                _ => false,
            };
            if missing {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S3796",
                    "Add the missing \"return\" statement to this function.",
                    callback.span(),
                );
            }
        }
        walk_call_expression(self, it);
    }
}

impl FunctionMetricsCollector<'_> {
    /// Measures one function-like unit, then descends into its subtree.
    fn analyze_function(
        &mut self,
        function: &Function<'_>,
        anchor: Span,
        exempt_mixed_returns: bool,
        walk_children: impl FnOnce(&mut Self),
    ) {
        if let Some(body) = &function.body {
            self.report_unit(body, anchor, exempt_mixed_returns);
        }
        walk_children(self);
    }

    /// Emits the threshold findings for one measured unit.
    fn report_complexity(&mut self, walker: &ComplexityWalker, anchor: Span) {
        if walker.cognitive > MAX_COGNITIVE_COMPLEXITY {
            self.sink.emit_span(
                RuleScope::Both,
                "S3776",
                &format!(
                    "Refactor this function to reduce its Cognitive Complexity from {} to the {} allowed.",
                    walker.cognitive, MAX_COGNITIVE_COMPLEXITY
                ),
                anchor,
            );
        }
        if walker.cyclomatic > MAX_CYCLOMATIC_COMPLEXITY {
            self.sink.emit_span(
                RuleScope::Both,
                "S1541",
                &format!(
                    "The Cyclomatic Complexity of this function is {} which is greater than {} authorized.",
                    walker.cyclomatic, MAX_CYCLOMATIC_COMPLEXITY
                ),
                anchor,
            );
        }
    }

    /// Measures a statement-list unit; `mixed` carries precomputed return
    /// information when the caller wants `S3801` checked.
    fn report_unit(&mut self, body: &FunctionBody<'_>, anchor: Span, exempt_mixed_returns: bool) {
        // Cyclomatic complexity starts at 1 (the single entry path).
        let mut walker = ComplexityWalker {
            cyclomatic: 1,
            ..ComplexityWalker::default()
        };
        for statement in &body.statements {
            walker.visit_statement(statement);
        }
        self.report_complexity(&walker, anchor);
        if !exempt_mixed_returns {
            self.check_mixed_returns(body, anchor);
        }
    }

    /// Measures an expression-bodied arrow (no `S3801`: it always yields).
    fn report_expression_unit(&mut self, expression: &Expression<'_>, anchor: Span) {
        let mut walker = ComplexityWalker {
            cyclomatic: 1,
            ..ComplexityWalker::default()
        };
        walker.visit_expression(expression);
        self.report_complexity(&walker, anchor);
    }

    /// `S3801`: a function mixing valued and bare returns flags each bare
    /// return; a function returning values but also falling off the end is
    /// flagged at the function itself.
    fn check_mixed_returns(&mut self, body: &FunctionBody<'_>, anchor: Span) {
        let mut scanner = ReturnMixScanner::default();
        scanner.visit_function_body(body);
        let falls_off_end = !body
            .statements
            .last()
            .is_some_and(|last| statement_ends_with_jump(last));
        if !scanner.valued_spans.is_empty() && !scanner.bare_spans.is_empty() {
            for span in &scanner.bare_spans {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3801",
                    "Remove this return statement or make it return a value.",
                    *span,
                );
            }
        } else if !scanner.valued_spans.is_empty() && falls_off_end {
            self.sink.emit_span(
                RuleScope::Both,
                "S3801",
                "Make this function consistently return a value.",
                anchor,
            );
        }
    }
}

/// Finds `super(...)` calls anywhere in a subtree.
#[derive(Default)]
pub(crate) struct SuperCallScanner {
    pub(crate) spans: Vec<Span>,
}

impl<'a> Visit<'a> for SuperCallScanner {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::CallExpression(call) = it
            && matches!(call.callee, Expression::Super(_))
        {
            self.spans.push(call.span());
        }
        walk_expression(self, it);
    }
}

/// Detects any `this` reference in a subtree.
#[derive(Default)]
pub(crate) struct ThisUseScanner {
    pub(crate) found: bool,
}

impl<'a> Visit<'a> for ThisUseScanner {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if matches!(it, Expression::ThisExpression(_)) {
            self.found = true;
        }
        walk_expression(self, it);
    }
}

/// Tracks reads and writes of one expected accessor field (`S4275`).
pub(crate) struct FieldAccessScanner<'n> {
    pub(crate) field: &'n str,
    pub(crate) read: bool,
    pub(crate) written: bool,
}

impl<'a> Visit<'a> for FieldAccessScanner<'_> {
    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if matches!(member_object(it), Expression::ThisExpression(_))
            && static_property_name(it) == Some(self.field)
        {
            self.read = true;
        }
        walk_member_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let Some(SimpleAssignmentTarget::StaticMemberExpression(member)) =
            it.left.as_simple_assignment_target()
            && matches!(member.object, Expression::ThisExpression(_))
            && matches!(member.object, Expression::ThisExpression(_))
            && member.property.name == self.field
        {
            self.written = true;
        }
        walk_assignment_expression(self, it);
    }
}

/// Constructor and accessor rules over class bodies (`S3854`, `S6635`,
/// `S4275`) plus object-literal accessors (`S4275`).
pub(crate) struct ClassAccessorCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for ClassAccessorCollector<'_> {
    fn visit_class(&mut self, it: &Class<'a>) {
        let heritage = it.heritage.is_some();
        for element in &it.body.body {
            if let ClassElement::MethodDefinition(method) = element {
                match method.kind {
                    MethodDefinitionKind::Constructor => {
                        self.check_constructor(method, heritage);
                    }
                    MethodDefinitionKind::Get | MethodDefinitionKind::Set => {
                        self.check_accessor(
                            property_key_name(&method.key),
                            method.key.span(),
                            method.kind == MethodDefinitionKind::Set,
                            method.value.body.as_deref(),
                        );
                    }
                    MethodDefinitionKind::Method => {}
                }
            }
        }
        walk_class(self, it);
    }

    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        for property in &it.properties {
            if let ObjectPropertyKind::ObjectProperty(inner) = property
                && inner.kind != PropertyKind::Init
                && let Expression::FunctionExpression(function) = &inner.value
                && let Some(body) = function.body.as_deref()
            {
                self.check_accessor(
                    property_key_name(&inner.key),
                    inner.key.span(),
                    inner.kind == PropertyKind::Set,
                    Some(body),
                );
            }
        }
        walk_object_expression(self, it);
    }
}

impl ClassAccessorCollector<'_> {
    /// `S3854`: missing, duplicated, conditional, or late `super()` calls;
    /// also `S6635`: constructors returning values.
    fn check_constructor(&mut self, method: &MethodDefinition<'_>, heritage: bool) {
        let Some(body) = &method.value.body else {
            return;
        };
        // `S6635` applies with or without a base class.
        let mut returns = ReturnMixScanner::default();
        returns.visit_function_body(body);
        for span in &returns.valued_spans {
            self.sink.emit_span(
                RuleScope::Both,
                "S6635",
                "Remove this return value; constructors should not return anything.",
                *span,
            );
        }
        if !heritage {
            return;
        }

        // Split the calls into direct top-level statements and nested
        // (conditional) ones; only the top-level ones can be "first".
        let mut top_level_spans: Vec<Span> = Vec::new();
        let mut nested_spans: Vec<Span> = Vec::new();
        for statement in &body.statements {
            if is_super_call_statement(statement) {
                if let Statement::ExpressionStatement(expr) = statement
                    && let Expression::CallExpression(call) = unparenthesized(&expr.expression)
                {
                    top_level_spans.push(call.span());
                }
            } else {
                let mut scanner = SuperCallScanner::default();
                scanner.visit_statement(statement);
                nested_spans.extend(scanner.spans);
            }
        }

        if top_level_spans.is_empty() && nested_spans.is_empty() {
            self.sink.emit_span(
                RuleScope::Both,
                "S3854",
                "Add a \"super()\" call in this constructor.",
                method.key.span(),
            );
            return;
        }
        for span in &nested_spans {
            self.sink.emit_span(
                RuleScope::Both,
                "S3854",
                "Move this call of super() to the first statement of this constructor.",
                *span,
            );
        }
        for span in top_level_spans.iter().skip(1) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3854",
                "Remove this duplicated call to super().",
                *span,
            );
        }
        // `this` must not be touched before the first `super()` call.
        if let Some(first) = top_level_spans.first() {
            for statement in &body.statements {
                if is_super_call_statement(statement) {
                    break;
                }
                let mut scanner = ThisUseScanner::default();
                scanner.visit_statement(statement);
                if scanner.found {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3854",
                        "Call super() before accessing \"this\".",
                        statement.span(),
                    );
                    break;
                }
            }
            let _ = first;
        }
    }

    /// `S4275`: accessors should touch the field their name declares.
    fn check_accessor(
        &mut self,
        name: Option<&str>,
        key_span: Span,
        is_setter: bool,
        body: Option<&FunctionBody<'_>>,
    ) {
        let (Some(name), Some(body)) = (name, body) else {
            return;
        };
        let mut scanner = FieldAccessScanner {
            field: name,
            read: false,
            written: false,
        };
        scanner.visit_function_body(body);
        let satisfied = if is_setter {
            scanner.written
        } else {
            scanner.read
        };
        if !satisfied {
            let message = if is_setter {
                format!("Verify that this setter assigns the \"{name}\" field.")
            } else {
                format!("Verify that this getter accesses the \"{name}\" field.")
            };
            self.sink
                .emit_span(RuleScope::Both, "S4275", &message, key_span);
        }
    }
}

pub(crate) fn is_super_call_statement(statement: &Statement<'_>) -> bool {
    matches!(statement, Statement::ExpressionStatement(expr)
        if matches!(unparenthesized(&expr.expression), Expression::CallExpression(call)
            if matches!(call.callee, Expression::Super(_))))
}

/// `S3972` (`else`/`catch`/`finally` sharing the closing brace's line) and
/// `S3973` (unbraced single-statement bodies indented deeper than their
/// head statement).
pub(crate) struct KeywordPlacementCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) source: &'a str,
    pub(crate) index: &'index LineIndex,
}

impl<'a> Visit<'a> for KeywordPlacementCollector<'a, '_> {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        if let Some(alternate) = &it.alternate {
            self.check_keyword_line(it.consequent.span(), alternate.span(), "else");
            self.check_unbraced_indent(it.span(), alternate);
        }
        self.check_unbraced_indent(it.span(), &it.consequent);
        walk_if_statement(self, it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_for_statement(self, it);
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_for_in_statement(self, it);
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_for_of_statement(self, it);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_while_statement(self, it);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_do_while_statement(self, it);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        if let Some(handler) = &it.handler {
            self.check_keyword_line(it.block.span(), handler.span(), "catch");
        }
        let after_catch = it.handler.as_ref().map_or(it.block.span(), |h| h.span());
        if let Some(finalizer) = &it.finalizer {
            self.check_keyword_line(after_catch, finalizer.span(), "finally");
        }
        walk_try_statement(self, it);
    }
}

impl KeywordPlacementCollector<'_, '_> {
    /// `S3972`: the keyword joining two blocks (`else`, `catch`, `finally`)
    /// must start on its own line after the preceding closing brace; a
    /// keyword sharing the brace's line is flagged.
    fn check_keyword_line(&mut self, previous: Span, following: Span, keyword: &str) {
        let gap = &self.source[previous.end as usize..following.start as usize];
        if !gap.contains('\n') {
            let anchor = gap
                .find(keyword)
                .map_or(following.start, |at| previous.end + to_u32(at));
            self.sink.emit_span(
                RuleScope::Both,
                "S3972",
                "Move this keyword onto its own line after the closing brace.",
                Span::new(anchor, anchor + to_u32(keyword.len())),
            );
        }
    }

    /// `S3973`: an unbraced body starting on a later line must be indented
    /// strictly deeper than its head statement.
    fn check_unbraced_indent(&mut self, head: Span, body: &Statement<'_>) {
        if matches!(
            body,
            Statement::BlockStatement(_) | Statement::EmptyStatement(_)
        ) {
            return;
        }
        let head_start = self.index.pos(head.start);
        let body_start = self.index.pos(body.span().start);
        if body_start.line > head_start.line && body_start.column <= head_start.column {
            self.sink.emit_span(
                RuleScope::Both,
                "S3973",
                "Indent this statement deeper than its parent statement.",
                body.span(),
            );
        }
    }
}

/// `S4619` (`in` on arrays), `S4634` (immediately-settling promise
/// executors), `S6671` (rejecting literals), and `S4822` (await-less
/// promise calls inside `try` blocks).
pub(crate) struct PromiseFlowCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) array_bindings: BTreeSet<String>,
}

impl<'a> Visit<'a> for PromiseFlowCollector<'_> {
    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        if it.operator == BinaryOperator::In {
            let flagged = match unparenthesized(&it.right) {
                Expression::ArrayExpression(_) => true,
                Expression::Identifier(identifier) => {
                    self.array_bindings.contains(identifier.name.as_str())
                }
                _ => false,
            };
            if flagged {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4619",
                    "Use \"includes\" or \"indexOf\" instead of the \"in\" operator on this array.",
                    it.span(),
                );
            }
        }
        walk_binary_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if identifier_name(&it.callee) == Some("Promise")
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && promise_executor_settles_immediately(argument)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4634",
                "Refactor this promise executor; it resolves or rejects immediately.",
                it.span(),
            );
        }
        walk_new_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // `S6671`: rejecting with a plain literal value.
        let rejects = identifier_name(&it.callee) == Some("reject")
            || it.callee.as_member_expression().is_some_and(|member| {
                static_property_name(member) == Some("reject")
                    && member_rooted_at(member, "Promise")
            });
        if rejects
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && is_plain_literal(argument)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6671",
                "Reject this promise with an \"Error\" object instead of a literal value.",
                it.span(),
            );
        }
        walk_call_expression(self, it);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        // `S4822`: await-less promise-producing calls escape the catch.
        for statement in &it.block.body {
            let Some(expression) = statement_as_expression(statement) else {
                continue;
            };
            if matches!(expression, Expression::AwaitExpression(_)) {
                continue;
            }
            if let Expression::CallExpression(call) = unparenthesized(expression) {
                let promise_api = identifier_name(&call.callee) == Some("fetch")
                    || call
                        .callee
                        .as_member_expression()
                        .is_some_and(|member| static_property_name(member) == Some("then"));
                if promise_api {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S4822",
                        "Await this promise; otherwise its failure bypasses the \"catch\".",
                        statement.span(),
                    );
                }
            }
        }
        walk_try_statement(self, it);
    }
}

/// Whether every top-level statement of the executor immediately calls its
/// own resolve/reject parameter.
pub(crate) fn settles_immediately(body: &FunctionBody<'_>, param: &str) -> bool {
    !body.statements.is_empty()
        && body.statements.iter().all(|statement| {
            statement_as_expression(statement).is_some_and(|expression| {
                matches!(unparenthesized(expression), Expression::CallExpression(call)
                    if identifier_name(&call.callee) == Some(param))
            })
        })
}

/// Whether a `new Promise` executor argument settles the promise without
/// doing any asynchronous work: every block statement is an immediate call
/// of its own resolve/reject parameter, or (for expression-bodied arrows)
/// the whole body is that call.
pub(crate) fn promise_executor_settles_immediately(argument: &Expression<'_>) -> bool {
    match argument {
        Expression::FunctionExpression(function) => {
            let Some(body) = function.body.as_deref() else {
                return false;
            };
            let Some(param) = function
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern))
            else {
                return false;
            };
            settles_immediately(body, param)
        }
        Expression::ArrowFunctionExpression(arrow) => {
            let Some(param) = arrow
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern))
            else {
                return false;
            };
            match arrow.body.as_function_body() {
                Some(body) => settles_immediately(body, param),
                None => matches!(arrow.body.to_expression(), Expression::CallExpression(call)
                    if identifier_name(&call.callee) == Some(param)),
            }
        }
        _ => false,
    }
}

/// `S1067`: conditions carrying more boolean operators than this are
/// flagged (frozen catalog default of the `max` parameter).
pub(crate) const MAX_CONDITION_OPERATORS: usize = 3;

/// Counts `&&`, `||`, and `!` operators in one condition, excluding
/// conditions of nested function units.
#[derive(Default)]
pub(crate) struct ConditionOperatorScanner {
    pub(crate) count: usize,
}

impl<'a> Visit<'a> for ConditionOperatorScanner {
    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.count += 1;
        walk_logical_expression(self, it);
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        if it.operator == UnaryOperator::LogicalNot {
            self.count += 1;
        }
        walk_unary_expression(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }
}

/// `S1534`, `S1536`, `S6861`, and `S1067` in one traversal.
pub(crate) struct DuplicationCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for DuplicationCollector<'a> {
    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        // `S1534`: duplicated data-property keys (accessor pairs are legal).
        let mut seen: Vec<&str> = Vec::new();
        for property in &it.properties {
            let ObjectPropertyKind::ObjectProperty(inner) = property else {
                continue;
            };
            if inner.kind != PropertyKind::Init
                || inner.kind == PropertyKind::Init && inner.shorthand
            {
                // Shorthand properties cannot collide with their own binding.
                continue;
            }
            let Some(name) = duplicated_key_name(&inner.key) else {
                continue;
            };
            if seen.contains(&name) {
                self.emit_duplicate_key(&format!("\"{name}\""), inner.key.span());
            } else {
                seen.push(name);
            }
        }
        walk_object_expression(self, it);
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        // `S1534`: duplicated class members; getters and setters pair up, so
        // each accessor kind is tracked separately.
        let mut plain: Vec<&str> = Vec::new();
        let mut getters: Vec<&str> = Vec::new();
        let mut setters: Vec<&str> = Vec::new();
        for element in &it.body.body {
            match element {
                ClassElement::MethodDefinition(method) => {
                    let Some(name) = property_key_name(&method.key) else {
                        continue;
                    };
                    match method.kind {
                        MethodDefinitionKind::Get => {
                            self.flag_duplicate(&mut getters, name, method.key.span());
                        }
                        MethodDefinitionKind::Set => {
                            self.flag_duplicate(&mut setters, name, method.key.span());
                        }
                        _ => self.flag_duplicate(&mut plain, name, method.key.span()),
                    }
                }
                ClassElement::PropertyDefinition(definition) => {
                    if let Some(name) = property_key_name(&definition.key) {
                        self.flag_duplicate(&mut plain, name, definition.key.span());
                    }
                }
                _ => {}
            }
        }
        walk_class(self, it);
    }

    fn visit_formal_parameters(&mut self, it: &FormalParameters<'a>) {
        // `S1536`: duplicate parameter names (JavaScript-only).
        let mut seen: Vec<&str> = Vec::new();
        for item in &it.items {
            let Some(name) = binding_identifier_name(&item.pattern) else {
                continue;
            };
            if seen.contains(&name) {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S1536",
                    &format!("Rename this parameter; \"{name}\" is already used."),
                    item.pattern.span(),
                );
            } else {
                seen.push(name);
            }
        }
        walk_formal_parameters(self, it);
    }

    fn visit_export_declaration(&mut self, it: &ExportDeclaration<'a>) {
        // `S6861`: mutable bindings must not be exported.
        if let Declaration::VariableDeclaration(variable) = &it.declaration
            && variable.kind != VariableDeclarationKind::Const
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6861",
                "Do not export mutable bindings.",
                it.span(),
            );
        }
        walk_export_declaration(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.check_condition_operators(&it.test);
        walk_if_statement(self, it);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.check_condition_operators(&it.test);
        walk_while_statement(self, it);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.check_condition_operators(&it.test);
        walk_do_while_statement(self, it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(test) = &it.test {
            self.check_condition_operators(test);
        }
        walk_for_statement(self, it);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        self.check_condition_operators(&it.test);
        walk_conditional_expression(self, it);
    }
}

impl DuplicationCollector<'_> {
    fn flag_duplicate<'name>(&mut self, seen: &mut Vec<&'name str>, name: &'name str, span: Span) {
        if seen.contains(&name) {
            self.emit_duplicate_key(&format!("\"{name}\""), span);
        } else {
            seen.push(name);
        }
    }

    fn emit_duplicate_key(&mut self, name: &str, span: Span) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1534",
            &format!("Rename or remove this duplicated {name} key."),
            span,
        );
    }

    /// `S1067`: conditions with more operators than the catalog maximum.
    fn check_condition_operators(&mut self, test: &Expression<'_>) {
        let mut scanner = ConditionOperatorScanner::default();
        scanner.visit_expression(test);
        if scanner.count > MAX_CONDITION_OPERATORS {
            self.sink.emit_span(
                RuleScope::Both,
                "S1067",
                &format!(
                    "This condition uses {} boolean operators; simplify it to at most {}.",
                    scanner.count, MAX_CONDITION_OPERATORS
                ),
                test.span(),
            );
        }
    }
}

pub(crate) fn is_plain_literal(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::TemplateLiteral(_)
    )
}

/// Whether an expression is entirely string literals joined by `+`
/// (`S3512`).
pub(crate) fn is_pure_string_concat(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
            is_pure_string_concat(&binary.left) && is_pure_string_concat(&binary.right)
        }
        Expression::StringLiteral(_) => true,
        _ => false,
    }
}

/// Identifier compared against `null`/`undefined` by one side of an `&&`
/// guard (`S6582`).
pub(crate) fn null_guard_target<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    let Expression::BinaryExpression(binary) = unparenthesized(expression) else {
        return None;
    };
    if !is_equality_operator(binary.operator) {
        return None;
    }
    let is_nullish = |expression: &Expression<'_>| {
        matches!(expression, Expression::NullLiteral(_))
            || identifier_name(expression) == Some("undefined")
    };
    match (&binary.left, &binary.right) {
        (Expression::Identifier(identifier), other)
        | (other, Expression::Identifier(identifier))
            if is_nullish(other) =>
        {
            Some(&identifier.name)
        }
        _ => None,
    }
}

/// Detects member accesses rooted at one identifier (`S6582` right-hand
/// usage probe).
#[derive(Default)]
pub(crate) struct RootedMemberScanner<'n> {
    pub(crate) root: &'n str,
    pub(crate) found: bool,
}

impl<'a> Visit<'a> for RootedMemberScanner<'_> {
    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if member_root_name(it) == Some(self.root) {
            self.found = true;
        }
        walk_member_expression(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }
}

/// The plain `=` assignment expression of an expression statement, if any
/// (`S3514`).
pub(crate) fn swap_assignment<'a>(
    statement: &'a Statement<'a>,
) -> Option<&'a AssignmentExpression<'a>> {
    match statement {
        Statement::ExpressionStatement(expression_statement) => {
            match unparenthesized(&expression_statement.expression) {
                Expression::AssignmentExpression(assignment)
                    if assignment.operator == AssignmentOperator::Assign =>
                {
                    Some(assignment)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

pub(crate) fn function_params_shadow_arguments(params: &FormalParameters<'_>) -> bool {
    params
        .items
        .iter()
        .any(|item| binding_identifier_name(&item.pattern) == Some("arguments"))
}

/// The `temp = saved` seed of a swap triple: either a plain assignment
/// statement or a single-declarator declaration (`let t = a;`) with plain
/// identifier sides (`S3514`).
pub(crate) fn swap_seed<'a>(statement: &'a Statement<'a>) -> Option<(&'a str, &'a str)> {
    match statement {
        Statement::ExpressionStatement(expression_statement) => {
            match unparenthesized(&expression_statement.expression) {
                Expression::AssignmentExpression(assignment)
                    if assignment.operator == AssignmentOperator::Assign =>
                {
                    Some((
                        assignment_target_name(&assignment.left)?,
                        identifier_name(&assignment.right)?,
                    ))
                }
                _ => None,
            }
        }
        Statement::VariableDeclaration(declaration) => {
            let [declarator] = declaration.declarations.as_slice() else {
                return None;
            };
            let name = binding_identifier_name(&declarator.id)?;
            Some((name, identifier_name(declarator.init.as_ref()?)?))
        }
        _ => None,
    }
}

impl<'a> Visit<'a> for EsIdiomCollector<'a> {
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        self.scan_swap_triples(&it.body);
        walk_program(self, it);
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.scan_swap_triples(&it.body);
        walk_block_statement(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.scan_swap_triples(&it.statements);
        walk_function_body(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            let shadowed = function_params_shadow_arguments(&function.params);
            self.arguments_shadowed.push(shadowed);
            walk_expression(self, it);
            self.arguments_shadowed.pop();
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            let shadowed = function_params_shadow_arguments(&function.params);
            self.arguments_shadowed.push(shadowed);
            walk_declaration(self, it);
            self.arguments_shadowed.pop();
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        let shadowed = function_params_shadow_arguments(&it.value.params);
        self.arguments_shadowed.push(shadowed);
        walk_method_definition(self, it);
        self.arguments_shadowed.pop();
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.arguments_shadowed.push(false);
        walk_static_block(self, it);
        self.arguments_shadowed.pop();
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        let shadowed = function_params_shadow_arguments(&it.params);
        self.arguments_shadowed.push(shadowed);
        walk_arrow_function_expression(self, it);
        self.arguments_shadowed.pop();
    }

    fn visit_identifier_reference(&mut self, it: &oxc_ast::ast::IdentifierReference<'a>) {
        // `S3513`: direct `arguments` reads where no parameter shadows it.
        if it.name == "arguments" && !self.arguments_shadowed.iter().any(|&shadowed| shadowed) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3513",
                "Use rest parameters instead of \"arguments\".",
                it.span(),
            );
        }
    }

    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        let mut non_shorthand_seen = false;
        for property in &it.properties {
            let ObjectPropertyKind::ObjectProperty(inner) = property else {
                continue;
            };
            if inner.kind != PropertyKind::Init {
                continue;
            }
            if inner.shorthand {
                // `S3499`: shorthand properties come first.
                if non_shorthand_seen {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3499",
                        "Write this shorthand property before the non-shorthand properties.",
                        inner.span(),
                    );
                }
            } else {
                non_shorthand_seen = true;
                // `S3498`: `{ a: a }` should use the shorthand form.
                if let (Some(key), Some(value)) =
                    (property_key_name(&inner.key), identifier_name(&inner.value))
                    && key == value
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3498",
                        "Use the shorthand syntax for this property.",
                        inner.span(),
                    );
                }
            }
        }
        walk_object_expression(self, it);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        // `S3358`: ternaries nested in consequent or alternate positions.
        for branch in [&it.consequent, &it.alternate] {
            if let Expression::ConditionalExpression(nested) = unparenthesized(branch) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3358",
                    "Refactor this nested ternary expression.",
                    nested.span(),
                );
            }
        }
        walk_conditional_expression(self, it);
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        // `S3512`: record pure string-concat roots; containment filtering
        // happens after the traversal.
        if it.operator == BinaryOperator::Addition
            && is_pure_string_concat(&it.left)
            && is_pure_string_concat(&it.right)
        {
            self.concat_roots.push(it.span());
        }
        walk_binary_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        // `S3523`: the `Function` constructor (JavaScript-only); overlaps
        // the `S1523` finding on purpose — separate catalog rule keys.
        if constructor_name(it) == Some("Function") {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3523",
                "Remove this use of the \"Function\" constructor.",
                it.callee.span(),
            );
        }
        walk_new_expression(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        // `S4158`: operations on empty array literals always do nothing.
        if matches!(
            unparenthesized(member_object(it)),
            Expression::ArrayExpression(array) if array.elements.is_empty()
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4158",
                "Review this operation; it always targets an empty array.",
                it.span(),
            );
        }
        walk_member_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // `S6594`: `.match(/…/g)` prefers `.matchAll` or `.exec`.
        if let Some((property, _member)) = call_property(it)
            && property == "match"
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && let Expression::RegExpLiteral(literal) = argument
            && literal.regex.flags.contains(RegExpFlags::G)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6594",
                "Prefer \".matchAll\" or \".exec\" over \".match\" for this global regex.",
                it.span(),
            );
        }
        walk_call_expression(self, it);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        // `S6582`: `x !== null && x.member` rewrites to optional chaining.
        if it.operator == LogicalOperator::And
            && let Some(root) = null_guard_target(&it.left)
        {
            let mut scanner = RootedMemberScanner { root, found: false };
            scanner.visit_expression(&it.right);
            if scanner.found {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6582",
                    "Use optional chaining (\"?.\") instead of this null check.",
                    it.span(),
                );
            }
        }
        walk_logical_expression(self, it);
    }
}

impl EsIdiomCollector<'_> {
    /// `S3514`: consecutive `t = a; … ; a = t` statements hide a swap that
    /// destructuring expresses directly.
    fn scan_swap_triples(&mut self, statements: &[Statement<'_>]) {
        for window in statements.windows(3) {
            // First saves `saved` into `temp`, either through an assignment
            // or a single declarator; the third restores it.
            let Some((temp, saved)) = swap_seed(&window[0]) else {
                continue;
            };
            let Some(third) = swap_assignment(&window[2]) else {
                continue;
            };
            if identifier_name(&third.right) != Some(temp) {
                continue;
            }
            let Some(counterpart) = assignment_target_name(&third.left) else {
                continue;
            };
            let Some(middle) = swap_assignment(&window[1]) else {
                continue;
            };
            let links_saved_to_counterpart = (assignment_target_name(&middle.left) == Some(saved)
                && identifier_name(&middle.right) == Some(counterpart))
                || (assignment_target_name(&middle.left) == Some(counterpart)
                    && identifier_name(&middle.right) == Some(saved));
            if counterpart != temp && links_saved_to_counterpart {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3514",
                    "Swap these variables with destructuring instead of this temporary.",
                    window[0].span(),
                );
            }
        }
    }
}
