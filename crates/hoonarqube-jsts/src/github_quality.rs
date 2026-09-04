//! High-confidence CodeQL-compatible JavaScript/TypeScript quality checks.
//!
//! This module intentionally contains only checks whose published `CodeQL`
//! semantics can be decided from the tolerant Oxc AST and the file-local
//! scope model.  Checks requiring DOM extraction, inferred types, SSA/dataflow,
//! or control-flow dominance stay out of this entry point.

use std::collections::HashMap;

use hoonarqube_ir::{FlowLocation, Issue, IssueFlow};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BinaryExpression,
    BinaryOperator, BindingIdentifier, BindingPattern, BlockStatement, Class, Comment, Expression,
    ForInStatement, ForOfStatement, ForStatement, ForStatementLeft, Function, FunctionBody,
    JSXOpeningElement, LabeledStatement, MemberExpression, MethodDefinition, NewExpression,
    ObjectExpression, ObjectPropertyKind, PropertyKind, SimpleAssignmentTarget, Statement,
    StaticBlock, SwitchCase, SwitchStatement, UpdateExpression, UpdateOperator, VariableDeclarator,
    WithStatement, YieldExpression,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_binary_expression,
    walk_block_statement, walk_class, walk_expression_statement, walk_for_in_statement,
    walk_for_of_statement, walk_for_statement, walk_formal_parameters, walk_function,
    walk_jsx_opening_element, walk_labeled_statement, walk_member_expression,
    walk_method_definition, walk_new_expression, walk_object_expression, walk_program,
    walk_static_block, walk_switch_case, walk_switch_statement, walk_update_expression,
    walk_variable_declarator, walk_with_statement, walk_yield_expression,
};
use oxc_parser::Parser;
use oxc_span::{ContentEq, GetSpan, SourceType, Span};
use oxc_syntax::scope::ScopeFlags;

use crate::JstsLanguage;
use crate::engine::scope_model::{TbKind, TbModel, build_tb_model};
use crate::rules::shared::duplicated_key_name;
use crate::support::{
    LineIndex, identifier_name, member_object, sort_issues, span_issue, static_property_name,
    unparenthesized,
};

/// Run the high-confidence CodeQL-compatible JavaScript/TypeScript quality checks
/// on a bounded worker stack. Oxc's visitor implementations recurse with AST
/// depth, so this boundary is part of the public API's safety contract.
///
/// # Panics
///
/// Panics if the worker thread cannot be spawned or if analysis panics.
#[must_use]
pub fn analyze_github_quality(source: &str, language: JstsLanguage) -> Vec<Issue> {
    std::thread::scope(|scope| {
        crate::run_on_analyzer_stack(
            scope,
            "hoonarqube-jsts-github-quality",
            "failed to start JS/TS GitHub quality worker",
            move || analyze_github_quality_inner(source, language),
        )
    })
}

fn analyze_github_quality_inner(source: &str, language: JstsLanguage) -> Vec<Issue> {
    let allocator = Allocator::default();
    // First parse in the language's unambiguous non-TSX grammar. If JSX is
    // present, retry with JSX enabled; this preserves `.ts` angle-bracket
    // assertions/type parameters while still accepting TSX/JSX from core's
    // two-variant language API.
    let base_source_type = match language {
        JstsLanguage::JavaScript => SourceType::unambiguous(),
        JstsLanguage::TypeScript => SourceType::ts(),
    };
    let parsed = Parser::new(&allocator, source, base_source_type).parse();
    let parsed = if parsed.diagnostics.errors().next().is_some() {
        Parser::new(&allocator, source, base_source_type.with_jsx(true)).parse()
    } else {
        parsed
    };
    if parsed.diagnostics.errors().next().is_some() {
        return Vec::new();
    }

    let index = LineIndex::new(source);
    let model = build_tb_model(&parsed.program);
    let mut collector = QualityCollector::new(source, &index, parsed.program.source_type, &model);
    collector.emit_conditional_comments(&parsed.program.comments);
    collector.emit_const_assignments(&model);
    collector.visit_program(&parsed.program);
    sort_issues(&mut collector.issues);
    collector.issues.dedup();
    debug_assert!(
        collector
            .issues
            .iter()
            .all(|issue| crate::GITHUB_QUALITY_RULE_IDS.contains(&issue.rule_key.as_str()))
    );
    collector.issues
}

/// One lexical scope relevant to the special `arguments` binding.
#[derive(Clone, Copy)]
enum ArgumentsScope {
    Function { has_binding: bool },
    Block { has_binding: bool },
}

#[derive(Clone, Copy)]
enum FunctionKind {
    Regular,
    Generator,
}

impl FunctionKind {
    fn from_bool(generator: bool) -> Self {
        if generator {
            Self::Generator
        } else {
            Self::Regular
        }
    }
}

#[derive(Clone, Copy)]
enum FunctionBodyState {
    Ambient,
    Empty,
    NonEmpty,
}

struct FunctionContext {
    strict: bool,
    generator: FunctionKind,
    body: FunctionBodyState,
    underscore_accessed: bool,
}

struct QualityCollector<'src, 'index, 'model> {
    source: &'src str,
    index: &'index LineIndex<'src>,
    model: &'model TbModel<'src>,
    program_source_type: SourceType,
    functions: Vec<FunctionContext>,
    strict_stack: Vec<bool>,
    arguments_scopes: Vec<ArgumentsScope>,
    binary_stack: Vec<Span>,
    forced_strict: usize,
    useless_member: Option<Span>,
    issues: Vec<Issue>,
}

impl<'src, 'index, 'model> QualityCollector<'src, 'index, 'model> {
    fn new(
        source: &'src str,
        index: &'index LineIndex<'src>,
        program_source_type: SourceType,
        model: &'model TbModel<'src>,
    ) -> Self {
        Self {
            source,
            index,
            model,
            program_source_type,
            functions: Vec::new(),
            strict_stack: Vec::new(),
            arguments_scopes: Vec::new(),
            binary_stack: Vec::new(),
            forced_strict: 0,
            useless_member: None,
            issues: Vec::new(),
        }
    }
    fn emit(&mut self, id: &str, message: impl Into<String>, span: Span) {
        self.issues
            .push(span_issue(self.index, format!("js/{id}"), message, span));
    }
    fn emit_related(
        &mut self,
        id: &str,
        message: impl Into<String>,
        span: Span,
        related_message: impl Into<String>,
        related_span: Span,
    ) {
        let mut issue = span_issue(self.index, format!("js/{id}"), message, span);
        issue.flows.push(IssueFlow {
            locations: vec![FlowLocation::in_primary_file(
                related_message,
                self.index.range(related_span),
            )],
        });
        self.issues.push(issue);
    }

    fn current_strict(&self) -> bool {
        self.strict_stack
            .last()
            .copied()
            .unwrap_or_else(|| self.program_source_type.is_strict())
    }

    fn current_function(&self) -> Option<&FunctionContext> {
        self.functions.last()
    }

    fn push_function(
        &mut self,
        generator: FunctionKind,
        body: FunctionBodyState,
        directives_strict: bool,
        has_arguments_binding: bool,
    ) {
        let strict = self.current_strict() || directives_strict || self.forced_strict > 0;
        self.strict_stack.push(strict);
        self.functions.push(FunctionContext {
            strict,
            generator,
            body,
            underscore_accessed: false,
        });
        self.arguments_scopes.push(ArgumentsScope::Function {
            has_binding: has_arguments_binding,
        });
    }

    fn pop_function(&mut self) {
        self.functions.pop();
        self.strict_stack.pop();
        self.arguments_scopes.pop();
    }
    fn has_arguments_binding(&self) -> bool {
        self.arguments_scopes
            .iter()
            .rev()
            .find_map(|scope| match scope {
                ArgumentsScope::Function { has_binding }
                | ArgumentsScope::Block { has_binding } => (*has_binding).then_some(true),
            })
            .unwrap_or(false)
    }

    fn emit_arguments_redefinition(&mut self, span: Span) {
        if !self.functions.is_empty() && self.has_arguments_binding() {
            self.emit("arguments-redefinition", "Redefinition of arguments.", span);
        }
    }

    fn first_line_span(&self, span: Span) -> Span {
        let start = usize::try_from(span.start)
            .unwrap_or(self.source.len())
            .min(self.source.len());
        let end = self.source[start..]
            .find('\n')
            .map_or(self.source.len(), |offset| start + offset);
        Span::new(span.start, u32::try_from(end).unwrap_or(u32::MAX))
    }

    fn emit_conditional_comments(&mut self, comments: &[Comment]) {
        for comment in comments {
            let start = usize::try_from(comment.content_span().start)
                .unwrap_or(self.source.len())
                .min(self.source.len());
            let end = usize::try_from(comment.content_span().end)
                .unwrap_or(self.source.len())
                .min(self.source.len());
            if self
                .source
                .get(start..end)
                .is_some_and(|text| text.trim().starts_with("@cc_on"))
            {
                self.emit(
                    "conditional-comment",
                    "Do not use conditional comments.",
                    comment.span,
                );
            }
        }
    }

    fn emit_const_assignments(&mut self, model: &crate::engine::scope_model::TbModel<'_>) {
        for binding in &model.bindings {
            if binding.kind != TbKind::Const {
                continue;
            }
            for write in &binding.writes {
                self.emit(
                    "assignment-to-constant",
                    format!(
                        "Assignment to variable {}, which is declared constant.",
                        binding.name
                    ),
                    *write,
                );
            }
        }
    }
    fn check_parameters(&mut self, params: &oxc_ast::ast::FormalParameters<'_>) {
        let Some(function) = self.current_function() else {
            return;
        };
        if function.strict || !matches!(function.body, FunctionBodyState::NonEmpty) {
            return;
        }
        let underscore_accessed = function.underscore_accessed;
        let mut bound = Vec::new();
        for parameter in &params.items {
            let bindings = binding_identifiers(&parameter.pattern);
            let simple_underscore = bindings.len() == 1
                && bindings[0].0 == "_"
                && simple_binding_name(&parameter.pattern) == Some("_");
            for (name, span) in bindings {
                bound.push((name, span, simple_underscore && !underscore_accessed));
            }
        }
        if let Some(rest) = &params.rest {
            for (name, span) in binding_identifiers(&rest.rest.argument) {
                bound.push((name, span, false));
            }
        }
        let mut last = HashMap::new();
        for (index, (name, _, _)) in bound.iter().enumerate() {
            last.insert(*name, index);
        }
        for (index, (name, span, dummy)) in bound.iter().enumerate() {
            let Some(&last_index) = last.get(name) else {
                continue;
            };
            if index < last_index && !dummy {
                self.emit_related(
                    "duplicate-parameter-name",
                    "This parameter has the same name as another parameter of the same function.",
                    *span,
                    "another parameter",
                    bound[last_index].1,
                );
            }
        }
    }

    fn check_object_properties(&mut self, object: &ObjectExpression<'_>) {
        for (index, property_kind) in object.properties.iter().enumerate() {
            let ObjectPropertyKind::ObjectProperty(property) = property_kind else {
                continue;
            };
            if property.kind != PropertyKind::Init || property.computed {
                continue;
            }
            let Some(name) = duplicated_key_name(&property.key) else {
                continue;
            };
            let duplicate = object.properties[..index].iter().rev().find_map(|prior| {
                let ObjectPropertyKind::ObjectProperty(prior) = prior else {
                    return None;
                };
                (prior.kind == PropertyKind::Init
                    && !prior.computed
                    && duplicated_key_name(&prior.key) == Some(name)
                    && prior.value.content_eq(&property.value))
                .then_some(prior)
            });
            if let Some(first) = duplicate {
                self.emit_related(
                    "duplicate-property",
                    "This property is duplicated in a later property.",
                    first.span(),
                    "in a later property",
                    property.span(),
                );
            }
        }
    }

    fn check_switch(&mut self, statement: &SwitchStatement<'_>) {
        for (index, case) in statement.cases.iter().enumerate() {
            let Some(test) = &case.test else {
                continue;
            };
            let Some(first_span) = statement.cases[..index]
                .iter()
                .filter_map(|prior| prior.test.as_ref().map(GetSpan::span))
                .find(|first_span| {
                    statement.cases[..index]
                        .iter()
                        .filter_map(|prior| prior.test.as_ref())
                        .any(|prior| prior.span() == *first_span && prior.content_eq(test))
                })
            else {
                continue;
            };
            let first_text = source_text(self.source, first_span).trim().to_owned();
            self.emit_related(
                "duplicate-switch-case",
                format!("This case label is a duplicate of {first_text}."),
                test.span(),
                first_text,
                first_span,
            );
        }
    }

    fn check_case_labels(&mut self, case: &SwitchCase<'_>) {
        let case_column = self.index.pos(case.span.start).column;
        let mut scan = CaseLabelScan {
            index: self.index,
            case_column,
            labels: Vec::new(),
        };
        for statement in &case.consequent {
            scan.visit_statement(statement);
        }
        for label in scan.labels {
            self.emit(
                "label-in-switch",
                "Non-case labels in switch statements are confusing.",
                label,
            );
        }
    }

    fn check_loop_orientation(&mut self, loop_: &ForStatement<'_>) {
        let Some(counter) = loop_counter(loop_) else {
            return;
        };
        let Some((bound_direction, _)) = loop_bound(loop_.test.as_ref(), &counter) else {
            return;
        };
        let Some(update_direction) = loop_update(loop_.update.as_ref(), &counter) else {
            return;
        };
        if bound_direction != update_direction {
            self.emit(
                "inconsistent-loop-direction",
                format!(
                    "This loop counts {update_direction}, but its variable is bounded {bound_direction}."
                ),
                loop_.span,
            );
        }
    }

    fn check_unused_index(&mut self, loop_: &ForStatement<'_>) {
        let Some(counter) = loop_counter(loop_) else {
            return;
        };
        let Some(test) = loop_.test.as_ref().and_then(unparenthesized_binary) else {
            return;
        };
        let Some(array) = array_length_bound(test, &counter) else {
            return;
        };
        let counter_binding = [&test.left, &test.right]
            .into_iter()
            .find_map(|expression| {
                (identifier_name(expression) == Some(counter.as_str()))
                    .then(|| binding_id_for_expression(self.model, expression, &counter))
                    .flatten()
            });
        let array_binding = test.right.as_member_expression().and_then(|member| {
            (static_property_name(member) == Some("length"))
                .then(|| binding_id_for_expression(self.model, member_object(member), &array))
                .flatten()
        });
        let mut scan = IndexAccessScan {
            model: self.model,
            array: &array,
            array_binding,
            counter: &counter,
            counter_binding,
            has_access: false,
            all_integer_constant: true,
            variable_access: false,
        };
        scan.visit_statement(&loop_.body);
        if scan.has_access && !scan.variable_access && scan.all_integer_constant {
            self.emit(
                "unused-index-variable",
                format!("Index variable {counter} is never used to access elements of {array}."),
                test.span(),
            );
        }
    }

    fn check_shift(&mut self, expression: &BinaryExpression<'_>) {
        if !matches!(
            expression.operator,
            BinaryOperator::ShiftLeft
                | BinaryOperator::ShiftRight
                | BinaryOperator::ShiftRightZeroFill
        ) {
            return;
        }
        let Expression::NumericLiteral(value) = unparenthesized(&expression.right) else {
            return;
        };
        if value.value.is_finite() && value.value.fract() == 0.0 && value.value > 31.0 {
            self.emit("shift-out-of-range", "Shift out of range.", expression.span);
        }
    }

    fn check_whitespace(&mut self, expression: &BinaryExpression<'_>) {
        let Some(outer_gap) = operator_gap(self.source, expression) else {
            return;
        };
        if self.binary_stack.is_empty()
            && expression.operator == BinaryOperator::BitwiseOR
            && matches!(
                unparenthesized(&expression.right),
                Expression::NumericLiteral(value) if value.value == 0.0
            )
        {
            return;
        }
        for (child, right_child) in [(&expression.left, false), (&expression.right, true)] {
            let Expression::BinaryExpression(inner) = unparenthesized(child) else {
                continue;
            };
            if !interesting_nesting(inner, expression, right_child) {
                continue;
            }
            let Some(inner_gap) = operator_gap(self.source, inner) else {
                continue;
            };
            if inner_gap > outer_gap {
                self.emit(
                    "whitespace-contradicts-precedence",
                    "Whitespace around nested operators contradicts precedence.",
                    expression.span,
                );
                break;
            }
        }
    }
}

impl<'a> Visit<'a> for QualityCollector<'_, '_, '_> {
    fn visit_program(&mut self, program: &oxc_ast::ast::Program<'a>) {
        walk_program(self, program);
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        let body = match &function.body {
            None => FunctionBodyState::Ambient,
            Some(body) if body.statements.is_empty() => FunctionBodyState::Empty,
            Some(_) => FunctionBodyState::NonEmpty,
        };
        let directives_strict = function
            .body
            .as_ref()
            .is_some_and(|body| has_use_strict_directive(body));
        let underscore_accessed = function
            .body
            .as_ref()
            .is_some_and(|body| body_references_name(body, "_"));
        self.push_function(
            FunctionKind::from_bool(function.generator),
            body,
            directives_strict,
            true,
        );
        if let Some(context) = self.functions.last_mut() {
            context.underscore_accessed = underscore_accessed;
        }
        walk_function(self, function, flags);
        self.pop_function();
    }

    fn visit_arrow_function_expression(&mut self, function: &ArrowFunctionExpression<'a>) {
        let body = if function
            .body
            .as_function_body()
            .is_some_and(|body| body.statements.is_empty())
        {
            FunctionBodyState::Empty
        } else {
            FunctionBodyState::NonEmpty
        };
        let explicit_arguments = binding_identifiers_in_parameters(&function.params)
            .iter()
            .any(|(name, _)| *name == "arguments");
        let var_arguments = function
            .body
            .as_function_body()
            .is_some_and(body_has_var_arguments);
        self.push_function(
            FunctionKind::Regular,
            body,
            false,
            explicit_arguments || var_arguments,
        );
        if let Some(context) = self.functions.last_mut() {
            context.underscore_accessed = function
                .body
                .as_function_body()
                .is_some_and(|body| body_references_name(body, "_"));
        }
        walk_arrow_function_expression(self, function);
        self.pop_function();
    }

    fn visit_block_statement(&mut self, block: &BlockStatement<'a>) {
        self.arguments_scopes.push(ArgumentsScope::Block {
            has_binding: block_has_lexical_arguments(block),
        });
        walk_block_statement(self, block);
        self.arguments_scopes.pop();
    }

    fn visit_formal_parameters(&mut self, params: &oxc_ast::ast::FormalParameters<'a>) {
        self.check_parameters(params);
        let ambient = self
            .current_function()
            .is_some_and(|function| matches!(function.body, FunctionBodyState::Ambient));
        for (name, span) in binding_identifiers_in_parameters(params) {
            if name == "arguments" && !ambient {
                self.emit_arguments_redefinition(span);
            }
        }
        walk_formal_parameters(self, params);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        for (name, span) in binding_identifiers(&declarator.id) {
            if name == "arguments" && !self.functions.is_empty() {
                self.emit("arguments-redefinition", "Redefinition of arguments.", span);
            }
        }
        walk_variable_declarator(self, declarator);
    }

    fn visit_assignment_expression(&mut self, expression: &AssignmentExpression<'a>) {
        for span in assignment_target_arguments(&expression.left) {
            self.emit_arguments_redefinition(span);
        }
        walk_assignment_expression(self, expression);
    }

    fn visit_update_expression(&mut self, expression: &UpdateExpression<'a>) {
        if let SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) = &expression.argument
            && identifier.name.as_str() == "arguments"
        {
            self.emit_arguments_redefinition(identifier.span);
        }
        walk_update_expression(self, expression);
    }

    fn visit_object_expression(&mut self, object: &ObjectExpression<'a>) {
        self.check_object_properties(object);
        walk_object_expression(self, object);
    }

    fn visit_with_statement(&mut self, statement: &WithStatement<'a>) {
        self.emit(
            "with-statement",
            "Do not use 'with'.",
            self.first_line_span(statement.span),
        );
        walk_with_statement(self, statement);
    }

    fn visit_switch_statement(&mut self, statement: &SwitchStatement<'a>) {
        self.check_switch(statement);
        walk_switch_statement(self, statement);
    }
    fn visit_switch_case(&mut self, case: &SwitchCase<'a>) {
        self.check_case_labels(case);
        walk_switch_case(self, case);
    }

    fn visit_for_in_statement(&mut self, loop_: &ForInStatement<'a>) {
        for span in for_head_assignment_arguments(&loop_.left) {
            self.emit_arguments_redefinition(span);
        }
        walk_for_in_statement(self, loop_);
    }

    fn visit_for_of_statement(&mut self, loop_: &ForOfStatement<'a>) {
        for span in for_head_assignment_arguments(&loop_.left) {
            self.emit_arguments_redefinition(span);
        }
        walk_for_of_statement(self, loop_);
    }

    fn visit_for_statement(&mut self, loop_: &ForStatement<'a>) {
        self.check_loop_orientation(loop_);
        self.check_unused_index(loop_);
        walk_for_statement(self, loop_);
    }

    fn visit_binary_expression(&mut self, expression: &BinaryExpression<'a>) {
        self.check_shift(expression);
        self.check_whitespace(expression);
        self.binary_stack.push(expression.span);
        walk_binary_expression(self, expression);
        self.binary_stack.pop();
    }

    fn visit_yield_expression(&mut self, expression: &YieldExpression<'a>) {
        if let Some(function) = self.current_function()
            && matches!(function.body, FunctionBodyState::NonEmpty)
            && !matches!(function.generator, FunctionKind::Generator)
        {
            self.emit(
                "yield-outside-generator",
                "This yield expression is contained in a function which is not marked as a generator.",
                expression.span,
            );
        }
        walk_yield_expression(self, expression);
    }

    fn visit_member_expression(&mut self, member: &MemberExpression<'a>) {
        walk_member_expression(self, member);
    }

    fn visit_expression_statement(&mut self, statement: &oxc_ast::ast::ExpressionStatement<'a>) {
        let saved = self.useless_member;
        self.useless_member = statement
            .expression
            .as_member_expression()
            .map(GetSpan::span);
        walk_expression_statement(self, statement);
        self.useless_member = saved;
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        self.forced_strict += 1;
        walk_class(self, class);
        self.forced_strict -= 1;
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
        self.forced_strict += 1;
        walk_method_definition(self, method);
        self.forced_strict -= 1;
    }

    fn visit_static_block(&mut self, block: &StaticBlock<'a>) {
        self.forced_strict += 1;
        walk_static_block(self, block);
        self.forced_strict -= 1;
    }

    fn visit_jsx_opening_element(&mut self, opening: &JSXOpeningElement<'a>) {
        // JSX is intentionally not assigned the HTML CodeQL ID here: Oxc has
        // no standalone HTML extractor and cannot reproduce CodeQL's DOM
        // string/data-flow value model.
        walk_jsx_opening_element(self, opening);
    }

    fn visit_new_expression(&mut self, expression: &NewExpression<'a>) {
        walk_new_expression(self, expression);
    }
}

fn has_use_strict_directive(body: &FunctionBody<'_>) -> bool {
    body.directives
        .iter()
        .any(|directive| directive.directive.as_str() == "use strict")
}

fn binding_identifiers<'a>(pattern: &'a BindingPattern<'a>) -> Vec<(&'a str, Span)> {
    struct Scanner<'a> {
        bindings: Vec<(&'a str, Span)>,
    }
    impl<'a> Visit<'a> for Scanner<'a> {
        fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
            self.bindings
                .push((identifier.name.as_str(), identifier.span));
        }
    }
    let mut scanner = Scanner {
        bindings: Vec::new(),
    };
    scanner.visit_binding_pattern(pattern);
    scanner.bindings
}

fn binding_identifiers_in_parameters<'a>(
    params: &'a oxc_ast::ast::FormalParameters<'a>,
) -> Vec<(&'a str, Span)> {
    let mut bindings = Vec::new();
    for parameter in &params.items {
        bindings.extend(binding_identifiers(&parameter.pattern));
    }
    if let Some(rest) = &params.rest {
        bindings.extend(binding_identifiers(&rest.rest.argument));
    }
    bindings
}

fn body_references_name(body: &FunctionBody<'_>, wanted: &str) -> bool {
    struct Scanner<'a> {
        wanted: &'a str,
        found: bool,
    }
    impl<'a> Visit<'a> for Scanner<'_> {
        fn visit_identifier_reference(
            &mut self,
            reference: &oxc_ast::ast::IdentifierReference<'a>,
        ) {
            self.found |= reference.name.as_str() == self.wanted;
        }

        fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
        fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
        fn visit_method_definition(&mut self, _: &MethodDefinition<'a>) {}
    }
    let mut scanner = Scanner {
        wanted,
        found: false,
    };
    for statement in &body.statements {
        scanner.visit_statement(statement);
    }
    scanner.found
}

fn body_has_var_arguments(body: &FunctionBody<'_>) -> bool {
    struct Scanner {
        found: bool,
    }
    impl<'a> Visit<'a> for Scanner {
        fn visit_variable_declaration(
            &mut self,
            declaration: &oxc_ast::ast::VariableDeclaration<'a>,
        ) {
            if declaration.kind == oxc_ast::ast::VariableDeclarationKind::Var
                && declaration.declarations.iter().any(|declarator| {
                    binding_identifiers(&declarator.id)
                        .iter()
                        .any(|(name, _)| *name == "arguments")
                })
            {
                self.found = true;
            }
            oxc_ast_visit::walk::walk_variable_declaration(self, declaration);
        }
        fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
        fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
        fn visit_method_definition(&mut self, _: &MethodDefinition<'a>) {}
    }
    let mut scanner = Scanner { found: false };
    for statement in &body.statements {
        scanner.visit_statement(statement);
    }
    scanner.found
}

fn block_has_lexical_arguments(block: &BlockStatement<'_>) -> bool {
    block.body.iter().any(|statement| match statement {
        Statement::VariableDeclaration(declaration)
            if declaration.kind != oxc_ast::ast::VariableDeclarationKind::Var =>
        {
            declaration.declarations.iter().any(|declarator| {
                binding_identifiers(&declarator.id)
                    .iter()
                    .any(|(name, _)| *name == "arguments")
            })
        }
        Statement::FunctionDeclaration(function) => function
            .id
            .as_ref()
            .is_some_and(|identifier| identifier.name.as_str() == "arguments"),
        Statement::ClassDeclaration(class) => class
            .id
            .as_ref()
            .is_some_and(|identifier| identifier.name.as_str() == "arguments"),
        _ => false,
    })
}

fn assignment_target_arguments<'a>(target: &'a AssignmentTarget<'a>) -> Vec<Span> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(identifier)
            if identifier.name.as_str() == "arguments" =>
        {
            vec![identifier.span]
        }
        AssignmentTarget::ArrayAssignmentTarget(array) => array
            .elements
            .iter()
            .flatten()
            .flat_map(|element| assignment_target_maybe_default_arguments(element))
            .chain(
                array
                    .rest
                    .as_ref()
                    .into_iter()
                    .flat_map(|rest| assignment_target_arguments(&rest.target)),
            )
            .collect(),
        AssignmentTarget::ObjectAssignmentTarget(object) => object
            .properties
            .iter()
            .flat_map(|property| match property {
                oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(
                    property,
                ) if property.binding.name.as_str() == "arguments" => {
                    vec![property.binding.span]
                }
                oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyProperty(
                    property,
                ) => assignment_target_maybe_default_arguments(&property.binding),
                oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(_) => {
                    Vec::new()
                }
            })
            .chain(
                object
                    .rest
                    .as_ref()
                    .into_iter()
                    .flat_map(|rest| assignment_target_arguments(&rest.target)),
            )
            .collect(),
        _ => Vec::new(),
    }
}
fn for_head_assignment_arguments(left: &ForStatementLeft<'_>) -> Vec<Span> {
    left.as_assignment_target()
        .map_or_else(Vec::new, assignment_target_arguments)
}

fn assignment_target_maybe_default_arguments<'a>(
    target: &'a oxc_ast::ast::AssignmentTargetMaybeDefault<'a>,
) -> Vec<Span> {
    match target {
        oxc_ast::ast::AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(target) => {
            assignment_target_arguments(&target.binding)
        }
        target => target
            .as_assignment_target()
            .map_or_else(Vec::new, assignment_target_arguments),
    }
}

fn simple_binding_name<'a>(pattern: &'a BindingPattern<'a>) -> Option<&'a str> {
    match pattern {
        BindingPattern::BindingIdentifier(identifier) => Some(identifier.name.as_str()),
        _ => None,
    }
}

fn source_text(source: &str, span: Span) -> &str {
    let start = usize::try_from(span.start).unwrap_or(0);
    let end = usize::try_from(span.end).unwrap_or(source.len());
    source.get(start..end.min(source.len())).unwrap_or_default()
}
fn loop_counter<'a>(loop_: &'a ForStatement<'a>) -> Option<String> {
    let Expression::UpdateExpression(update) = unparenthesized(loop_.update.as_ref()?) else {
        return None;
    };
    update_target_name(update).map(str::to_owned)
}

fn loop_bound<'a>(
    test: Option<&'a Expression<'a>>,
    counter: &str,
) -> Option<(&'static str, &'a Expression<'a>)> {
    let Expression::BinaryExpression(binary) = unparenthesized(test?) else {
        return None;
    };
    match binary.operator {
        BinaryOperator::LessThan | BinaryOperator::LessEqualThan
            if identifier_name(&binary.left) == Some(counter) =>
        {
            Some(("upward", &binary.right))
        }
        BinaryOperator::GreaterThan | BinaryOperator::GreaterEqualThan
            if identifier_name(&binary.left) == Some(counter) =>
        {
            Some(("downward", &binary.right))
        }
        BinaryOperator::LessThan | BinaryOperator::LessEqualThan
            if identifier_name(&binary.right) == Some(counter) =>
        {
            Some(("downward", &binary.left))
        }
        BinaryOperator::GreaterThan | BinaryOperator::GreaterEqualThan
            if identifier_name(&binary.right) == Some(counter) =>
        {
            Some(("upward", &binary.left))
        }
        _ => None,
    }
}

fn loop_update<'a>(update: Option<&'a Expression<'a>>, counter: &str) -> Option<&'static str> {
    match unparenthesized(update?) {
        Expression::UpdateExpression(update) if update_target_name(update) == Some(counter) => {
            match update.operator {
                UpdateOperator::Increment => Some("upward"),
                UpdateOperator::Decrement => Some("downward"),
            }
        }
        _ => None,
    }
}

fn update_target_name<'a>(update: &'a UpdateExpression<'a>) -> Option<&'a str> {
    match &update.argument {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) => {
            Some(identifier.name.as_str())
        }
        _ => None,
    }
}

fn unparenthesized_binary<'a>(expression: &'a Expression<'a>) -> Option<&'a BinaryExpression<'a>> {
    match unparenthesized(expression) {
        Expression::BinaryExpression(binary) => Some(binary),
        _ => None,
    }
}

fn array_length_bound<'a>(test: &'a BinaryExpression<'a>, counter: &str) -> Option<String> {
    if !matches!(
        test.operator,
        BinaryOperator::LessThan | BinaryOperator::LessEqualThan
    ) || identifier_name(&test.left) != Some(counter)
    {
        return None;
    }
    let member = test.right.as_member_expression()?;
    if static_property_name(member) != Some("length") {
        return None;
    }
    identifier_name(member_object(member)).map(str::to_owned)
}

struct IndexAccessScan<'a, 'model> {
    model: &'model TbModel<'a>,
    array: &'a str,
    array_binding: Option<usize>,
    counter: &'a str,
    counter_binding: Option<usize>,
    has_access: bool,
    all_integer_constant: bool,
    variable_access: bool,
}

impl<'a> Visit<'a> for IndexAccessScan<'a, '_> {
    fn visit_member_expression(&mut self, member: &MemberExpression<'a>) {
        if let MemberExpression::ComputedMemberExpression(computed) = member
            && identifier_name(&computed.object) == Some(self.array)
            && binding_matches(self.model, &computed.object, self.array, self.array_binding)
        {
            self.has_access = true;
            if identifier_name(&computed.expression) == Some(self.counter)
                && binding_matches(
                    self.model,
                    &computed.expression,
                    self.counter,
                    self.counter_binding,
                )
            {
                self.variable_access = true;
                self.all_integer_constant = false;
            } else if !is_integer_index(unparenthesized(&computed.expression)) {
                self.all_integer_constant = false;
            }
        }
        oxc_ast_visit::walk::walk_member_expression(self, member);
    }

    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
    fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
}
fn binding_id_for_expression(
    model: &TbModel<'_>,
    expression: &Expression<'_>,
    wanted: &str,
) -> Option<usize> {
    let Expression::Identifier(identifier) = unparenthesized(expression) else {
        return None;
    };
    (identifier.name.as_str() == wanted).then(|| {
        model.bindings.iter().enumerate().find_map(|(id, binding)| {
            (binding.name == wanted && binding.reads.iter().any(|span| *span == identifier.span))
                .then_some(id)
        })
    })?
}

fn binding_matches(
    model: &TbModel<'_>,
    expression: &Expression<'_>,
    wanted: &str,
    expected: Option<usize>,
) -> bool {
    match (
        expected,
        binding_id_for_expression(model, expression, wanted),
    ) {
        (Some(expected), Some(actual)) => expected == actual,
        (None, None) => identifier_name(expression) == Some(wanted),
        _ => false,
    }
}

fn is_integer_index(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::NumericLiteral(value) => value.value.is_finite() && value.value.fract() == 0.0,
        Expression::UnaryExpression(unary)
            if matches!(
                unary.operator,
                oxc_ast::ast::UnaryOperator::UnaryPlus | oxc_ast::ast::UnaryOperator::UnaryNegation
            ) =>
        {
            is_integer_index(&unary.argument)
        }
        _ => false,
    }
}
struct CaseLabelScan<'i, 's> {
    index: &'i LineIndex<'s>,
    case_column: u32,
    labels: Vec<Span>,
}

impl<'a> Visit<'a> for CaseLabelScan<'_, '_> {
    fn visit_labeled_statement(&mut self, statement: &LabeledStatement<'a>) {
        if self.index.pos(statement.span.start).column == self.case_column {
            self.labels.push(statement.label.span);
        }
        walk_labeled_statement(self, statement);
    }
}

fn interesting_nesting(
    inner: &BinaryExpression<'_>,
    outer: &BinaryExpression<'_>,
    inner_is_right: bool,
) -> bool {
    let same_associative = inner.operator == outer.operator
        && matches!(
            inner.operator,
            BinaryOperator::Addition
                | BinaryOperator::Multiplication
                | BinaryOperator::BitwiseAnd
                | BinaryOperator::BitwiseOR
                | BinaryOperator::BitwiseXOR
        );
    let special_associative = !inner_is_right
        && ((inner.operator == BinaryOperator::Multiplication
            && outer.operator == BinaryOperator::Division)
            || (inner.operator == BinaryOperator::Division
                && outer.operator == BinaryOperator::Remainder)
            || (inner.operator == BinaryOperator::Addition
                && outer.operator == BinaryOperator::Subtraction));
    let comparison = matches!(
        outer.operator,
        BinaryOperator::LessThan
            | BinaryOperator::LessEqualThan
            | BinaryOperator::GreaterThan
            | BinaryOperator::GreaterEqualThan
            | BinaryOperator::In
            | BinaryOperator::Instanceof
            | BinaryOperator::Equality
            | BinaryOperator::Inequality
            | BinaryOperator::StrictEquality
            | BinaryOperator::StrictInequality
    );
    let arithmetic_or_shift = matches!(
        inner.operator,
        BinaryOperator::Addition
            | BinaryOperator::Subtraction
            | BinaryOperator::Multiplication
            | BinaryOperator::Division
            | BinaryOperator::Remainder
            | BinaryOperator::Exponential
            | BinaryOperator::ShiftLeft
            | BinaryOperator::ShiftRight
            | BinaryOperator::ShiftRightZeroFill
    );
    let harmless = comparison && arithmetic_or_shift;
    !(same_associative || special_associative || harmless)
}
fn operator_gap(source: &str, expression: &BinaryExpression<'_>) -> Option<usize> {
    let left_end = usize::try_from(expression.left.span().end).ok()?;
    let right_start = usize::try_from(expression.right.span().start).ok()?;
    let gap = source.get(left_end..right_start)?;
    Some(
        gap.chars()
            .filter(|character| character.is_whitespace())
            .count(),
    )
}

#[cfg(test)]
mod tests {
    use super::analyze_github_quality;
    use crate::JstsLanguage;

    fn ids(source: &str, language: JstsLanguage) -> Vec<String> {
        analyze_github_quality(source, language)
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect()
    }

    #[test]
    fn reports_local_syntax_and_scope_rules() {
        let source = concat!(
            "function f(x, x) {\n",
            "  with (obj) { value; }\n",
            "  arguments = value;\n",
            "  for (let i = 0; i < xs.length; --i) xs[0];\n",
            "  value = 1 << 40;\n",
            "}\n",
            "const answer = 1; answer = 2;\n",
            "switch (x) { case 1: break; case 1: break; }\n",
        );
        let found = ids(source, JstsLanguage::JavaScript);
        for id in [
            "js/duplicate-parameter-name",
            "js/with-statement",
            "js/arguments-redefinition",
            "js/inconsistent-loop-direction",
            "js/unused-index-variable",
            "js/shift-out-of-range",
            "js/assignment-to-constant",
            "js/duplicate-switch-case",
        ] {
            assert!(
                found.iter().any(|candidate| candidate == id),
                "missing {id}: {found:?}"
            );
        }
    }

    #[test]
    fn keeps_clean_shadowed_and_generator_cases_clean() {
        let source = concat!(
            "function outer(value) {\n",
            "  { let value = 1; value = 2; }\n",
            "  function* inner(x) { yield x; }\n",
            "  for (let i = 0; i < xs.length; ++i) xs[i];\n",
            "}\n",
        );
        assert!(ids(source, JstsLanguage::JavaScript).is_empty());
    }

    #[test]
    fn conditional_comments_are_reported_and_malformed_source_is_ignored() {
        let found = ids("/*@cc_on @*/\n", JstsLanguage::JavaScript);
        assert_eq!(found, vec!["js/conditional-comment"]);
        assert!(ids("function ( {", JstsLanguage::JavaScript).is_empty());
    }

    #[test]
    fn typescript_uses_the_same_official_query_ids() {
        let found = ids("const n: number = 1; n = 2;\n", JstsLanguage::TypeScript);
        assert!(found.iter().any(|id| id == "js/assignment-to-constant"));
    }
    #[test]
    fn structural_duplicates_preserve_literal_values_and_ignore_comments() {
        let different_literals = "const object = { key: 'a b', key: 'ab' };";
        assert!(
            !ids(different_literals, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-property")
        );

        let same_expression = "const object = { key: value /* comment */, key: value };";
        assert!(
            ids(same_expression, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-property")
        );

        let cases = "switch (value) { case 'a b': break; case 'ab': break; }";
        assert!(
            !ids(cases, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-switch-case")
        );
    }

    #[test]
    fn unused_index_requires_every_access_to_be_an_integer_constant() {
        let dynamic = "for (let i = 0; i < values.length; ++i) { values[0]; values[getIndex()]; }";
        assert!(
            !ids(dynamic, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/unused-index-variable")
        );
        let constants = "for (let i = 0; i < values.length; ++i) { values[0]; values[1]; }";
        assert!(
            ids(constants, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/unused-index-variable")
        );
    }

    #[test]
    fn arguments_and_duplicate_parameters_follow_lexical_bindings() {
        let arrow = "const f = () => { arguments = 1; };";
        assert!(
            !ids(arrow, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let destructured = "function f([arguments]) { arguments = 1; }";
        assert!(
            ids(destructured, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let accessed_dummy = "function f(_, _) { return _; }";
        assert!(
            ids(accessed_dummy, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-parameter-name")
        );
        let arrow_local = "const f = () => { let arguments = 1; };";
        assert!(
            ids(arrow_local, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let for_of = "function f() { for ([arguments] of values) {} }";
        assert!(
            ids(for_of, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let for_in = "function f() { for ({arguments} in values) {} }";
        assert!(
            ids(for_in, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let ambient = "declare function f(arguments: string[]): string;";
        assert!(
            !ids(ambient, JstsLanguage::TypeScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let nested_dummy = "function f(_, _) { function g(_) { return _; } }";
        assert!(
            !ids(nested_dummy, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-parameter-name")
        );
    }
    #[test]
    fn shorthand_duplicates_and_shadowed_indexes_use_identity() {
        let shorthand = "const x = value; const object = { x, x };";
        assert_eq!(
            ids(shorthand, JstsLanguage::JavaScript)
                .iter()
                .filter(|id| *id == "js/duplicate-property")
                .count(),
            1
        );

        let shadowed = "for (let i = 0; i < values.length; ++i) { let i = 1; values[0]; }";
        assert!(
            ids(shadowed, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/unused-index-variable")
        );
        let used = "for (let i = 0; i < values.length; ++i) { values[i]; }";
        assert!(
            !ids(used, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/unused-index-variable")
        );
    }

    #[test]
    fn whitespace_zero_gap_and_loop_update_forms_are_exact() {
        let spaced = "const value = a+b * c;";
        assert!(
            ids(spaced, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/whitespace-contradicts-precedence")
        );
        let compound_update = "for (let i = 0; i < values.length; i += 1) values[0];";
        assert!(
            !ids(compound_update, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/inconsistent-loop-direction")
        );
    }
}
