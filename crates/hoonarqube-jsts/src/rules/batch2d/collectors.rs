// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::rules::shared::duplicated_key_name;
use crate::support::IssueSink;
use crate::support::LineIndex;
use crate::support::binding_identifier_name;
use crate::support::member_object;
use crate::support::member_root_name;
use crate::support::property_key_name;
use crate::support::static_property_name;
use crate::support::unparenthesized;
use oxc_ast::ast::ArrowFunctionExpression;
use oxc_ast::ast::AssignmentExpression;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_ast::ast::BlockStatement;
use oxc_ast::ast::BreakStatement;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Class;
use oxc_ast::ast::ClassElement;
use oxc_ast::ast::ConditionalExpression;
use oxc_ast::ast::ContinueStatement;
use oxc_ast::ast::Declaration;
use oxc_ast::ast::DoWhileStatement;
use oxc_ast::ast::ExportDeclaration;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ForInStatement;
use oxc_ast::ast::ForOfStatement;
use oxc_ast::ast::ForStatement;
use oxc_ast::ast::FormalParameters;
use oxc_ast::ast::Function;
use oxc_ast::ast::FunctionBody;
use oxc_ast::ast::IfStatement;
use oxc_ast::ast::LogicalExpression;
use oxc_ast::ast::LogicalOperator;
use oxc_ast::ast::MemberExpression;
use oxc_ast::ast::MethodDefinition;
use oxc_ast::ast::MethodDefinitionKind;
use oxc_ast::ast::NewExpression;
use oxc_ast::ast::ObjectExpression;
use oxc_ast::ast::ObjectPropertyKind;
use oxc_ast::ast::PropertyKind;
use oxc_ast::ast::ReturnStatement;
use oxc_ast::ast::SimpleAssignmentTarget;
use oxc_ast::ast::Statement;
use oxc_ast::ast::StaticBlock;
use oxc_ast::ast::SwitchStatement;
use oxc_ast::ast::TryStatement;
use oxc_ast::ast::UnaryExpression;
use oxc_ast::ast::UnaryOperator;
use oxc_ast::ast::WhileStatement;
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

/// Computes the cognitive (`S3776`) and cyclomatic (`S1541`) complexity of
/// one function unit. Nesting weights follow the Sonar model: control-flow
/// structures add `1 + nesting`, `else if` chains stay flat, and nested
/// function units are excluded entirely. Logical operators are counted once
/// per consecutive sequence of the same operator for cognitive complexity,
/// while every occurrence adds a cyclomatic decision point.
#[derive(Default)]
pub(crate) struct ComplexityWalker {
    pub(crate) cognitive: u32,
    pub(crate) cyclomatic: u32,
    nesting: u32,
    /// Operator of the logical chain currently walked; entering a chain (or
    /// switching operators mid-chain) adds one cognitive increment only.
    logic_chain: Option<LogicalOperator>,
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
        // One structural increment here; `enter_nested` would double-count
        // the switch head and add a spurious cyclomatic point beyond the
        // case clauses that SonarQube's JS/TS definition counts.
        self.cognitive += 1 + self.nesting;
        let tested_cases = it.cases.iter().filter(|case| case.test.is_some()).count();
        self.cyclomatic += u32::try_from(tested_cases).unwrap_or(u32::MAX);
        let saved = self.nesting;
        self.nesting += 1;
        walk_switch_statement(self, it);
        self.nesting = saved;
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
        self.cyclomatic += 1;
        if self.logic_chain != Some(it.operator) {
            self.cognitive += 1;
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
        self.check_s3796_call_expression(it);
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

/// `S3972` (`else`/`catch`/`finally` sharing the closing brace's line) and
/// `S3973` (unbraced single-statement bodies indented deeper than their
/// head statement).
pub(crate) struct KeywordPlacementCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) source: &'a str,
    pub(crate) index: &'index LineIndex<'index>,
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

/// `S4619` (`in` on arrays), `S4634` (immediately-settling promise
/// executors), `S6671` (rejecting literals), and `S4822` (await-less
/// promise calls inside `try` blocks).
pub(crate) struct PromiseFlowCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) array_bindings: BTreeSet<String>,
}

impl<'a> Visit<'a> for PromiseFlowCollector<'_> {
    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        self.check_s4619_binary_expression(it);
        walk_binary_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        self.check_s4634_new_expression(it);
        walk_new_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_s6671_call_expression(it);
        walk_call_expression(self, it);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        self.check_s4822_try_statement(it);
        walk_try_statement(self, it);
    }
}

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
        self.check_s1536_formal_parameters(it);
        walk_formal_parameters(self, it);
    }

    fn visit_export_declaration(&mut self, it: &ExportDeclaration<'a>) {
        self.check_s6861_export_declaration(it);
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
}

/// Whether an expression is entirely string literals joined by `+`
/// (`S3512`).
fn is_pure_string_concat(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
            is_pure_string_concat(&binary.left) && is_pure_string_concat(&binary.right)
        }
        Expression::StringLiteral(_) => true,
        _ => false,
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

fn function_params_shadow_arguments(params: &FormalParameters<'_>) -> bool {
    params
        .items
        .iter()
        .any(|item| binding_identifier_name(&item.pattern) == Some("arguments"))
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
        self.check_s3513_identifier_reference(it);
    }

    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        self.check_s3498_s3499_object_expression(it);
        walk_object_expression(self, it);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        self.check_s3358_conditional_expression(it);
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
        self.check_s3523_new_expression(it);
        walk_new_expression(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        self.check_s4158_member_expression(it);
        walk_member_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_s6594_call_expression(it);
        walk_call_expression(self, it);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.check_s6582_logical_expression(it);
        walk_logical_expression(self, it);
    }
}
