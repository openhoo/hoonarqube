//! High-confidence CodeQL-compatible JavaScript/TypeScript quality checks.
//!
//! This module intentionally contains only checks whose published `CodeQL`
//! semantics can be decided from the tolerant Oxc AST and the file-local
//! scope model.  Checks requiring DOM extraction, inferred types, SSA/dataflow,
//! or control-flow dominance stay out of this entry point.

use std::collections::{HashMap, HashSet};

use hoonarqube_ir::{FlowLocation, Issue, IssueFlow};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BinaryExpression,
    BinaryOperator, BindingIdentifier, BindingPattern, BlockStatement, BreakStatement, Class,
    Comment, ConditionalExpression, ContinueStatement, DebuggerStatement, DoWhileStatement,
    Expression, ForInStatement, ForOfStatement, ForStatement, ForStatementInit, ForStatementLeft,
    Function, FunctionBody, JSXOpeningElement, LabeledStatement, LogicalExpression,
    MemberExpression, MethodDefinition, MethodDefinitionKind, NewExpression, ObjectExpression,
    ObjectProperty, ObjectPropertyKind, PropertyKey, PropertyKind, ReturnStatement,
    SimpleAssignmentTarget, Statement, StaticBlock, SwitchCase, SwitchStatement, ThrowStatement,
    TryStatement, UnaryOperator, UpdateExpression, UpdateOperator, VariableDeclarator,
    WithStatement, YieldExpression,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_binary_expression,
    walk_block_statement, walk_break_statement, walk_class, walk_continue_statement,
    walk_debugger_statement, walk_expression_statement, walk_for_in_statement,
    walk_for_of_statement, walk_formal_parameters, walk_function, walk_jsx_opening_element,
    walk_labeled_statement, walk_member_expression, walk_method_definition, walk_new_expression,
    walk_object_expression, walk_program, walk_return_statement, walk_static_block,
    walk_switch_case, walk_switch_statement, walk_throw_statement, walk_try_statement,
    walk_update_expression, walk_variable_declaration, walk_variable_declarator,
    walk_with_statement, walk_yield_expression,
};
use oxc_parser::{Kind, Parser, Token, config::TokensParserConfig};
use oxc_span::{ContentEq, GetSpan, SourceType, Span};
use oxc_syntax::scope::ScopeFlags;

use crate::JstsLanguage;
use crate::engine::scope_model::{TbKind, TbModel, build_tb_model, github_dead_stores};
use crate::rules::shared::duplicated_key_name;
use crate::support::{
    LineIndex, identifier_name, member_object, module_export_name_name, property_key_name,
    sort_issues, span_issue, static_property_name, unparenthesized,
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
    let parsed = Parser::new(&allocator, source, base_source_type)
        .with_config(TokensParserConfig)
        .parse();
    let parsed = if parsed.diagnostics.errors().next().is_some() {
        Parser::new(&allocator, source, base_source_type.with_jsx(true))
            .with_config(TokensParserConfig)
            .parse()
    } else {
        parsed
    };
    if parsed.diagnostics.errors().next().is_some() {
        return Vec::new();
    }

    let index = LineIndex::new(source);
    let model = build_tb_model(&parsed.program);
    let mut collector = QualityCollector::new(
        source,
        &index,
        parsed.program.source_type,
        &model,
        parsed.tokens.as_slice(),
        parsed.program.comments.as_slice(),
    );
    collector.emit_conditional_comments(&parsed.program.comments);
    collector.emit_const_assignments(&model);
    collector.emit_useless_assignments(&parsed.program);
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

struct QualityCollector<'src, 'index, 'model, 'tok> {
    source: &'src str,
    index: &'index LineIndex<'src>,
    model: &'model TbModel<'src>,
    program_source_type: SourceType,
    functions: Vec<FunctionContext>,
    strict_stack: Vec<bool>,
    arguments_scopes: Vec<ArgumentsScope>,
    binary_stack: Vec<Span>,
    forced_strict: usize,
    issues: Vec<Issue>,
    /// Parser tokens, for semicolon-boundary decisions (`SemicolonInsertion`).
    tokens: &'tok [Token],
    /// Parsed comments, for JSDoc-declaration suppression (`ExprHasNoEffect`).
    comments: &'tok [Comment],
    /// One open `StmtContainer` per enclosing function-like node or script.
    asi_containers: Vec<AsiContainer>,
    /// Declaration spans of `for` heads, which are not ASI subjects.
    for_head_spans: Vec<Span>,
    /// Truthiness refinements from dominating guards, innermost frame last.
    refinements: Vec<HashMap<usize, bool>>,
    /// Whether the current point sits inside an if/loop/ternary condition.
    conditional_depth: u32,
    /// Declarator bindings whose single initializer is a constant literal.
    symbolic_inits: HashSet<usize>,
    /// Property names with a getter in this file; their reads may run code.
    getter_names: HashSet<String>,
    /// Spans of first statements of `try` bodies (`ExprHasNoEffect` exclusion).
    try_first_spans: Vec<Span>,
    /// Number of top-level statements, for the config-object exclusions.
    program_stmt_count: usize,
    /// Whether the file declares any function-like node.
    file_has_function: bool,
}

/// One statement recorded for the `SemicolonInsertion` container analysis.
struct AsiStmt {
    span: Span,
    /// Whether the statement's last token is an explicit semicolon.
    explicit: bool,
}

/// One `CodeQL StmtContainer`: a function body or the whole script.
struct AsiContainer {
    is_function: bool,
    stmts: Vec<AsiStmt>,
}

impl<'src, 'index, 'model, 'tok> QualityCollector<'src, 'index, 'model, 'tok> {
    fn new(
        source: &'src str,
        index: &'index LineIndex<'src>,
        program_source_type: SourceType,
        model: &'model TbModel<'src>,
        tokens: &'tok [Token],
        comments: &'tok [Comment],
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
            issues: Vec::new(),
            tokens,
            comments,
            asi_containers: Vec::new(),
            for_head_spans: Vec::new(),
            refinements: Vec::new(),
            conditional_depth: 0,
            symbolic_inits: HashSet::new(),
            getter_names: HashSet::new(),
            try_first_spans: Vec::new(),
            program_stmt_count: 0,
            file_has_function: false,
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

    /// Drops a trailing statement terminator from a span: oxc extends some
    /// statement-level expressions across the final `;`, while the reference
    /// query anchors on the expression itself.
    fn strip_statement_terminator(&self, span: Span) -> Span {
        let mut end = usize::try_from(span.end)
            .unwrap_or(self.source.len())
            .min(self.source.len());
        while end > span.start as usize {
            let last = self.source.as_bytes()[end - 1];
            if last == b';' || last.is_ascii_whitespace() {
                end -= 1;
            } else {
                break;
            }
        }
        Span::new(span.start, u32::try_from(end).unwrap_or(span.end))
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

    /// Visits a truthiness-checked condition: the whole test sits in a
    /// conditional position, so every operand of nested logical expressions
    /// is checked against the current refinements.
    fn visit_condition(&mut self, test: &Expression<'_>) {
        self.report_refined_condition(test);
        self.conditional_depth += 1;
        self.visit_expression(test);
        self.conditional_depth -= 1;
    }

    /// Marks a `for`-head declaration so it is not recorded as an ASI
    /// subject; returns whether a guard was pushed.
    fn push_for_head_guard(&mut self, left: &ForStatementLeft<'_>) -> bool {
        match left {
            ForStatementLeft::VariableDeclaration(declaration) => {
                self.for_head_spans.push(declaration.span());
                true
            }
            _ => false,
        }
    }

    fn binding_id_for_decl(&self, span: Span) -> Option<usize> {
        self.model
            .bindings
            .iter()
            .position(|binding| binding.decl == span)
    }

    fn invalidate_refinements_of(&mut self, binding: usize) {
        for frame in &mut self.refinements {
            frame.remove(&binding);
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

    fn duplicate_property_name<'a>(property: &ObjectProperty<'a>) -> Option<&'a str> {
        if property.computed {
            if let PropertyKey::StringLiteral(literal) = &property.key {
                return Some(literal.value.as_str());
            }
            return None;
        }
        duplicated_key_name(&property.key)
    }

    fn check_object_properties(&mut self, object: &ObjectExpression<'_>) {
        for (index, property_kind) in object.properties.iter().enumerate() {
            let ObjectPropertyKind::ObjectProperty(property) = property_kind else {
                continue;
            };
            if property.kind != PropertyKind::Init {
                continue;
            }
            let Some(name) = Self::duplicate_property_name(property) else {
                continue;
            };
            let duplicate = object.properties[..index].iter().rev().find_map(|prior| {
                let ObjectPropertyKind::ObjectProperty(prior) = prior else {
                    return None;
                };
                (prior.kind == PropertyKind::Init
                    && Self::duplicate_property_name(prior) == Some(name)
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

    // --- js/automatic-semicolon-insertion ---

    /// Records one ASI-subject statement into the innermost container.
    fn record_asi_statement(&mut self, span: Span) {
        let explicit = self.last_token_is_semicolon(span);
        if let Some(container) = self.asi_containers.last_mut() {
            container.stmts.push(AsiStmt { span, explicit });
        }
    }

    /// Whether the statement span's last token is an explicit semicolon.
    fn last_token_is_semicolon(&self, span: Span) -> bool {
        let end = self.tokens.partition_point(|token| token.end() <= span.end);
        let last = self.tokens[..end].iter().rev().find(|token| {
            token.kind() != Kind::Eof && token.start() >= span.start && token.end() <= span.end
        });
        last.is_some_and(|token| token.kind() == Kind::Semicolon)
    }

    /// The statement's span restricted to its last line (`LastLineOf`).
    fn last_line_span(&self, span: Span) -> Span {
        let end = usize::try_from(span.end)
            .unwrap_or(self.source.len())
            .min(self.source.len());
        let line_start = self.source[..end]
            .rfind(['\n', '\r', '\u{2028}', '\u{2029}'])
            .map_or(0, |index| index + 1);
        Span::new(
            span.start.max(u32::try_from(line_start).unwrap_or(0)),
            span.end,
        )
    }

    fn push_asi_container(&mut self, is_function: bool) {
        self.asi_containers.push(AsiContainer {
            is_function,
            stmts: Vec::new(),
        });
    }

    /// Judges one finished container: with at least 90% explicit semicolons,
    /// every statement relying on ASI is a consistency deviation.
    fn pop_asi_container(&mut self) {
        let Some(container) = self.asi_containers.pop() else {
            return;
        };
        let total = container.stmts.len();
        if total == 0 {
            return;
        }
        let inserted = container.stmts.iter().filter(|stmt| !stmt.explicit).count();
        let percent = (total - inserted) * 100 / total;
        if percent < 90 {
            return;
        }
        let kind = if container.is_function {
            "function"
        } else {
            "script"
        };
        let message = format!(
            "Avoid automated semicolon insertion ({percent}% of all statements in the \
             enclosing {kind} have an explicit semicolon)."
        );
        for stmt in container.stmts.iter().filter(|stmt| !stmt.explicit) {
            self.emit(
                "automatic-semicolon-insertion",
                &message,
                self.last_line_span(stmt.span),
            );
        }
    }

    // --- js/trivial-conditional ---

    /// Checks one expression sitting in a truthiness-checking position.
    fn report_refined_condition(&mut self, expression: &Expression<'_>) {
        let Some(identifier) = identifier_name(expression) else {
            return;
        };
        let Some(binding) = binding_id_for_expression(self.model, expression, identifier) else {
            return;
        };
        let Some(value) = self
            .refinements
            .iter()
            .rev()
            .find_map(|frame| frame.get(&binding).copied())
        else {
            return;
        };
        if self.is_symbolic_constant(binding) {
            return;
        }
        self.emit(
            "trivial-conditional",
            format!(
                "This use of variable '{identifier}' always evaluates to {}.",
                if value { "true" } else { "false" }
            ),
            unparenthesized(expression).span(),
        );
    }

    /// Constants keep their meaning, so guarding on them never makes a
    /// re-check useless (`const` declarations and single literal inits).
    fn is_symbolic_constant(&self, binding: usize) -> bool {
        let Some(entry) = self.model.bindings.get(binding) else {
            return false;
        };
        entry.kind == TbKind::Const
            || (entry.writes.is_empty() && self.symbolic_inits.contains(&binding))
    }

    /// Truthiness implications a guard test establishes for its branches.
    fn implications(&self, expression: &Expression<'_>, want: bool) -> HashMap<usize, bool> {
        let mut out = HashMap::new();
        self.collect_implications(expression, want, &mut out);
        out
    }

    fn collect_implications(
        &self,
        expression: &Expression<'_>,
        want: bool,
        out: &mut HashMap<usize, bool>,
    ) {
        let inner = unparenthesized(expression);
        // `a.b` being truthy implies the root identifier `a` is truthy; a
        // falsy member access implies nothing about `a`.
        if want && let Some(member) = inner.as_member_expression() {
            let mut object = member_object(member);
            while let Some(nested) = unparenthesized(object).as_member_expression() {
                object = member_object(nested);
            }
            if let Some(name) = identifier_name(object)
                && let Some(binding) = binding_id_for_expression(self.model, object, name)
            {
                out.insert(binding, true);
            }
        }
        match inner {
            Expression::Identifier(identifier) => {
                if let Some(binding) =
                    binding_id_for_expression(self.model, expression, identifier.name.as_str())
                {
                    out.insert(binding, want);
                }
            }
            Expression::LogicalExpression(logical) => match logical.operator {
                oxc_ast::ast::LogicalOperator::And if want => {
                    self.collect_implications(&logical.left, true, out);
                    self.collect_implications(&logical.right, true, out);
                }
                oxc_ast::ast::LogicalOperator::Or if !want => {
                    self.collect_implications(&logical.left, false, out);
                    self.collect_implications(&logical.right, false, out);
                }
                _ => {}
            },
            Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::LogicalNot => {
                self.collect_implications(&unary.argument, !want, out);
            }
            // `x instanceof T` being true implies `x` is truthy; being false
            // implies nothing (any non-null value may fail the check).
            Expression::BinaryExpression(binary)
                if want && binary.operator == BinaryOperator::Instanceof =>
            {
                self.collect_implications(&binary.left, true, out);
            }
            _ => {}
        }
    }

    /// A store to the binding invalidates every refinement of it.
    fn invalidate_binding_for_target(&mut self, target: &AssignmentTarget<'_>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(identifier) = target {
            self.invalidate_binding_named(identifier.name.as_str(), identifier.span);
        }
    }

    fn invalidate_binding_named(&mut self, name: &str, span: Span) {
        let Some(binding) = self.model.bindings.iter().position(|binding| {
            binding.name == name && (binding.writes.contains(&span) || binding.decl == span)
        }) else {
            return;
        };
        for frame in &mut self.refinements {
            frame.remove(&binding);
        }
    }

    // --- js/useless-assignment-to-local ---

    /// Reports the reference query's dead stores for the whole file.
    fn emit_useless_assignments(&mut self, program: &oxc_ast::ast::Program<'_>) {
        let exported = exported_binding_names(program);
        for dead in github_dead_stores(program, self.source) {
            if exported.contains(dead.name.as_str()) {
                continue;
            }
            let message = if dead.is_declarator && !dead.decl_is_var {
                format!(
                    "The initial value of {} is unused, since it is always overwritten.",
                    dead.name
                )
            } else {
                format!("The value assigned to {} here is unused.", dead.name)
            };
            self.emit("useless-assignment-to-local", message, dead.whole);
        }
    }

    // --- js/useless-expression ---

    /// Scans one expression tree for pure subexpressions in void contexts,
    /// reporting only the innermost non-compound nodes.
    fn scan_void_expression(&mut self, expression: &Expression<'_>, in_void: bool) {
        if !in_void {
            return;
        }
        match unparenthesized(expression) {
            // Compounds pass their own void context to the relevant children.
            Expression::SequenceExpression(sequence) => {
                for operand in &sequence.expressions {
                    self.scan_void_expression(operand, true);
                }
            }
            Expression::LogicalExpression(logical) => {
                self.scan_void_expression(&logical.right, true);
            }
            Expression::ConditionalExpression(conditional) => {
                self.scan_conditional_void_branches(conditional);
            }
            // TS-only wrappers do not exist in the reference AST; look
            // straight through them.
            Expression::TSAsExpression(inner) => {
                self.scan_void_expression(&inner.expression, true);
            }
            Expression::TSSatisfiesExpression(inner) => {
                self.scan_void_expression(&inner.expression, true);
            }
            Expression::TSNonNullExpression(inner) => {
                self.scan_void_expression(&inner.expression, true);
            }
            Expression::ChainExpression(chain) => {
                if chain
                    .expression
                    .as_member_expression()
                    .is_some_and(|member| self.is_pure_member_expression(member))
                {
                    self.emit(
                        "useless-expression",
                        "This expression has no effect.",
                        self.first_line_span(chain.span()),
                    );
                }
            }
            other => {
                if self.is_pure_expression(other) {
                    self.emit(
                        "useless-expression",
                        "This expression has no effect.",
                        self.strip_statement_terminator(other.span()),
                    );
                }
            }
        }
    }

    /// Branches of a void-context conditional are void too, except the
    /// conventional `null`/`undefined`/`0`/`void` no-op branches.
    fn scan_conditional_void_branches(&mut self, conditional: &ConditionalExpression<'_>) {
        for branch in [&conditional.consequent, &conditional.alternate] {
            let no_op = match unparenthesized(branch) {
                Expression::NullLiteral(_) => true,
                Expression::Identifier(identifier) => identifier.name == "undefined",
                Expression::NumericLiteral(literal) => literal.value == 0.0,
                Expression::UnaryExpression(unary) => unary.operator == UnaryOperator::Void,
                _ => false,
            };
            if !no_op {
                self.scan_void_expression(branch, true);
            }
        }
    }

    /// Whether evaluating the expression can run arbitrary code. Mirrors the
    /// reference query's purity model with file-local knowledge: property
    /// reads stay pure unless this file defines a getter for the name.
    fn is_pure_expression(&self, expression: &Expression<'_>) -> bool {
        let inner = unparenthesized(expression);
        if let Some(member) = inner.as_member_expression() {
            return self.is_pure_member_expression(member);
        }
        match inner {
            Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::RegExpLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::ThisExpression(_)
            | Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_)
            | Expression::Identifier(_) => true,
            Expression::TemplateLiteral(template) => template.expressions.is_empty(),
            Expression::UnaryExpression(unary) => {
                !matches!(unary.operator, UnaryOperator::Void | UnaryOperator::Delete)
                    && self.is_pure_expression(&unary.argument)
            }
            Expression::BinaryExpression(binary) => {
                self.is_pure_expression(&binary.left) && self.is_pure_expression(&binary.right)
            }
            Expression::ObjectExpression(object) => object
                .properties
                .iter()
                .all(|property| self.is_pure_object_property(property)),
            Expression::ArrayExpression(array) => array.elements.iter().all(|element| {
                !element.is_spread()
                    && (element.is_elision()
                        || element
                            .as_expression()
                            .is_some_and(|expression| self.is_pure_expression(expression)))
            }),
            Expression::NewExpression(new) => Self::is_error_constructor(&new.callee),
            _ => false,
        }
    }

    fn is_pure_member_expression(&self, member: &MemberExpression<'_>) -> bool {
        if !self.is_pure_expression(member_object(member)) {
            return false;
        }
        match member {
            MemberExpression::ComputedMemberExpression(computed) => {
                self.is_pure_expression(&computed.expression)
            }
            member => {
                static_property_name(member).is_none_or(|name| !self.getter_names.contains(name))
            }
        }
    }

    fn is_pure_object_property(&self, property: &ObjectPropertyKind<'_>) -> bool {
        match property {
            ObjectPropertyKind::ObjectProperty(property) => {
                property.kind == PropertyKind::Init
                    && !property.computed
                    && self.is_pure_expression(&property.value)
            }
            ObjectPropertyKind::SpreadProperty(_) => false,
        }
    }

    /// `new Error(...)`, `new TypeError(...)`, and friends allocate without
    /// observable side effects, exactly like the reference query.
    fn is_error_constructor(callee: &Expression<'_>) -> bool {
        identifier_name(callee).is_some_and(|name| {
            name.ends_with("Error") && name.len() > "Error".len() || name == "Error"
        })
    }

    /// `x;`/`x.p;` preceded by a `JSDoc` tag comment reads as a declaration.
    fn has_attached_jsdoc_tag(&self, statement: &oxc_ast::ast::ExpressionStatement<'_>) -> bool {
        self.comments.iter().any(|comment| {
            comment.span.end <= statement.span().start
                && self.is_adjacent_jsdoc(comment.span, statement.span().start)
        })
    }

    fn is_adjacent_jsdoc(&self, comment: Span, statement_start: u32) -> bool {
        let start = usize::try_from(comment.end).unwrap_or(self.source.len());
        let end = usize::try_from(statement_start).unwrap_or(self.source.len());
        let Some(gap) = self.source.get(start..end.min(self.source.len())) else {
            return false;
        };
        gap.chars().filter(|character| *character == '\n').count() <= 1
            && gap.trim().is_empty()
            && self.source_text(comment).trim_start().starts_with("/*")
            && self.source_text(comment).contains('@')
    }

    fn source_text(&self, span: Span) -> &str {
        let start = usize::try_from(span.start).unwrap_or(0);
        let end = usize::try_from(span.end).unwrap_or(self.source.len());
        self.source
            .get(start..end.min(self.source.len()))
            .unwrap_or_default()
    }
}

impl<'a> Visit<'a> for QualityCollector<'_, '_, '_, '_> {
    fn visit_program(&mut self, program: &oxc_ast::ast::Program<'a>) {
        self.getter_names = collect_getter_names(program);
        self.program_stmt_count = program.body.len();
        self.file_has_function = program_has_function(program);
        self.push_asi_container(false);
        walk_program(self, program);
        self.pop_asi_container();
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
        // Refinements never cross a function boundary.
        let refinement_barrier = self.refinements.len();
        self.refinements.clear();
        self.push_asi_container(true);
        walk_function(self, function, flags);
        self.pop_asi_container();
        self.refinements.truncate(refinement_barrier);
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
        let refinement_barrier = self.refinements.len();
        self.refinements.clear();
        self.push_asi_container(true);
        walk_arrow_function_expression(self, function);
        self.pop_asi_container();
        self.refinements.truncate(refinement_barrier);
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
            if let Some(binding) = self.binding_id_for_decl(span) {
                self.invalidate_refinements_of(binding);
                if declarator.init.as_ref().is_some_and(is_constant_literal) {
                    self.symbolic_inits.insert(binding);
                }
            }
        }
        walk_variable_declarator(self, declarator);
    }

    fn visit_assignment_expression(&mut self, expression: &AssignmentExpression<'a>) {
        for span in assignment_target_arguments(&expression.left) {
            self.emit_arguments_redefinition(span);
        }
        self.invalidate_binding_for_target(&expression.left);
        walk_assignment_expression(self, expression);
    }

    fn visit_update_expression(&mut self, expression: &UpdateExpression<'a>) {
        if let SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) = &expression.argument
        {
            if identifier.name.as_str() == "arguments" {
                self.emit_arguments_redefinition(identifier.span);
            }
            self.invalidate_binding_named(identifier.name.as_str(), identifier.span);
        }
        walk_update_expression(self, expression);
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
        let pushed = self.push_for_head_guard(&loop_.left);
        walk_for_in_statement(self, loop_);
        if pushed {
            self.for_head_spans.pop();
        }
    }

    fn visit_for_of_statement(&mut self, loop_: &ForOfStatement<'a>) {
        for span in for_head_assignment_arguments(&loop_.left) {
            self.emit_arguments_redefinition(span);
        }
        let pushed = self.push_for_head_guard(&loop_.left);
        walk_for_of_statement(self, loop_);
        if pushed {
            self.for_head_spans.pop();
        }
    }

    fn visit_for_statement(&mut self, loop_: &ForStatement<'a>) {
        self.check_loop_orientation(loop_);
        self.check_unused_index(loop_);
        match &loop_.init {
            Some(ForStatementInit::VariableDeclaration(declaration)) => {
                self.for_head_spans.push(declaration.span());
                self.visit_variable_declaration(declaration);
                self.for_head_spans.pop();
            }
            Some(init) => self.visit_for_statement_init(init),
            None => {}
        }
        if let Some(test) = &loop_.test {
            self.visit_condition(test);
        }
        if let Some(update) = &loop_.update {
            self.scan_void_expression(update, true);
            self.visit_expression(update);
        }
        let refinements = loop_
            .test
            .as_ref()
            .map_or_else(HashMap::new, |test| self.implications(test, true));
        self.refinements.push(refinements);
        self.visit_statement(&loop_.body);
        self.refinements.pop();
    }

    fn visit_if_statement(&mut self, statement: &oxc_ast::ast::IfStatement<'a>) {
        self.visit_condition(&statement.test);
        self.refinements
            .push(self.implications(&statement.test, true));
        self.visit_statement(&statement.consequent);
        self.refinements.pop();
        if let Some(alternate) = &statement.alternate {
            self.refinements
                .push(self.implications(&statement.test, false));
            self.visit_statement(alternate);
            self.refinements.pop();
        }
    }

    fn visit_while_statement(&mut self, statement: &oxc_ast::ast::WhileStatement<'a>) {
        self.visit_condition(&statement.test);
        self.refinements
            .push(self.implications(&statement.test, true));
        self.visit_statement(&statement.body);
        self.refinements.pop();
    }

    fn visit_do_while_statement(&mut self, statement: &DoWhileStatement<'a>) {
        self.record_asi_statement(statement.span());
        self.visit_statement(&statement.body);
        self.visit_condition(&statement.test);
    }

    fn visit_logical_expression(&mut self, expression: &LogicalExpression<'a>) {
        self.report_refined_condition(&expression.left);
        if self.conditional_depth > 0 {
            self.report_refined_condition(&expression.right);
        }
        let guard = match expression.operator {
            oxc_ast::ast::LogicalOperator::And => self.implications(&expression.left, true),
            oxc_ast::ast::LogicalOperator::Or => self.implications(&expression.left, false),
            oxc_ast::ast::LogicalOperator::Coalesce => HashMap::new(),
        };
        self.visit_expression(&expression.left);
        self.refinements.push(guard);
        self.visit_expression(&expression.right);
        self.refinements.pop();
    }

    fn visit_conditional_expression(&mut self, expression: &ConditionalExpression<'a>) {
        self.visit_condition(&expression.test);
        self.refinements
            .push(self.implications(&expression.test, true));
        self.visit_expression(&expression.consequent);
        self.refinements.pop();
        self.refinements
            .push(self.implications(&expression.test, false));
        self.visit_expression(&expression.alternate);
        self.refinements.pop();
    }

    fn visit_try_statement(&mut self, statement: &TryStatement<'a>) {
        let first = statement.block.body.first().map(GetSpan::span);
        if let Some(span) = first {
            self.try_first_spans.push(span);
        }
        walk_try_statement(self, statement);
        if first.is_some() {
            self.try_first_spans.pop();
        }
    }

    fn visit_return_statement(&mut self, statement: &ReturnStatement<'a>) {
        self.record_asi_statement(statement.span());
        walk_return_statement(self, statement);
    }

    fn visit_throw_statement(&mut self, statement: &ThrowStatement<'a>) {
        self.record_asi_statement(statement.span());
        walk_throw_statement(self, statement);
    }

    fn visit_break_statement(&mut self, statement: &BreakStatement<'a>) {
        self.record_asi_statement(statement.span());
        walk_break_statement(self, statement);
    }

    fn visit_continue_statement(&mut self, statement: &ContinueStatement<'a>) {
        self.record_asi_statement(statement.span());
        walk_continue_statement(self, statement);
    }
    fn visit_debugger_statement(&mut self, statement: &DebuggerStatement) {
        self.record_asi_statement(statement.span());
        walk_debugger_statement(self, statement);
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

    fn visit_object_expression(&mut self, object: &ObjectExpression<'a>) {
        self.check_object_properties(object);
        walk_object_expression(self, object);
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
        self.push_asi_container(true);
        walk_static_block(self, block);
        self.pop_asi_container();
        self.forced_strict -= 1;
    }

    fn visit_variable_declaration(&mut self, declaration: &oxc_ast::ast::VariableDeclaration<'a>) {
        if !self.for_head_spans.contains(&declaration.span()) {
            self.record_asi_statement(declaration.span());
        }
        walk_variable_declaration(self, declaration);
    }

    fn visit_expression_statement(&mut self, statement: &oxc_ast::ast::ExpressionStatement<'a>) {
        self.record_asi_statement(statement.span());
        let expression = &statement.expression;
        let alone_in_file = self.program_stmt_count == 1 && !self.file_has_function;
        let config_object = self.program_stmt_count == 1
            && matches!(unparenthesized(expression), Expression::ObjectExpression(_));
        let try_first = self
            .try_first_spans
            .iter()
            .any(|span| *span == statement.span());
        if !alone_in_file && !config_object && !try_first && !self.has_attached_jsdoc_tag(statement)
        {
            self.scan_void_expression(expression, true);
        }
        walk_expression_statement(self, statement);
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

/// Whether the expression is a constant literal (`Literal` in the reference
/// query), so a variable initialized from it is a symbolic constant.
fn is_constant_literal(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        _ => false,
    }
}

/// Property names that can run user code when read from this file: class and
/// object getters, plus conservative `Object.defineProperty` targets.
fn collect_getter_names(program: &oxc_ast::ast::Program<'_>) -> HashSet<String> {
    struct Collector {
        names: HashSet<String>,
    }
    impl<'a> Visit<'a> for Collector {
        fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
            if method.kind == MethodDefinitionKind::Get
                && let Some(name) = property_key_name(&method.key)
            {
                self.names.insert(name.to_owned());
            }
            walk_method_definition(self, method);
        }

        fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
            if property.kind == PropertyKind::Get
                && let Some(name) = property_key_name(&property.key)
            {
                self.names.insert(name.to_owned());
            }
            oxc_ast_visit::walk::walk_object_property(self, property);
        }

        fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
            if let Some(expression) = unparenthesized(&call.callee).as_member_expression()
                && static_property_name(expression) == Some("defineProperty")
                && identifier_name(member_object(expression)) == Some("Object")
                && let Some(argument) = call.arguments.get(1)
                && let Some(Expression::StringLiteral(literal)) = argument.as_expression()
            {
                self.names.insert(literal.value.as_str().to_owned());
            }
            oxc_ast_visit::walk::walk_call_expression(self, call);
        }
    }
    let mut collector = Collector {
        names: HashSet::new(),
    };
    collector.visit_program(program);
    collector.names
}

/// Whether any function-like node exists in the file (`ExprHasNoEffect`
/// keeps bare single-statement files without functions out of scope).
fn program_has_function(program: &oxc_ast::ast::Program<'_>) -> bool {
    struct Counter {
        count: usize,
    }
    impl<'a> Visit<'a> for Counter {
        fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
            self.count += 1;
            oxc_ast_visit::walk::walk_function(self, function, flags);
        }

        fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
            self.count += 1;
            oxc_ast_visit::walk::walk_arrow_function_expression(self, arrow);
        }

        fn visit_static_block(&mut self, block: &StaticBlock<'a>) {
            self.count += 1;
            oxc_ast_visit::walk::walk_static_block(self, block);
        }
    }
    let mut counter = Counter { count: 0 };
    counter.visit_program(program);
    counter.count > 0
}

/// Names bound by one exported declaration (`export const x`, `export
/// function f`, `export class C`).
fn collect_exported_declaration_names(
    declaration: &oxc_ast::ast::Declaration<'_>,
    names: &mut HashSet<String>,
) {
    match declaration {
        oxc_ast::ast::Declaration::VariableDeclaration(declaration) => {
            for declarator in &declaration.declarations {
                for (name, _) in binding_identifiers(&declarator.id) {
                    names.insert(name.to_owned());
                }
            }
        }
        oxc_ast::ast::Declaration::FunctionDeclaration(function) => {
            if let Some(identifier) = &function.id {
                names.insert(identifier.name.as_str().to_owned());
            }
        }
        oxc_ast::ast::Declaration::ClassDeclaration(class) => {
            if let Some(identifier) = &class.id {
                names.insert(identifier.name.as_str().to_owned());
            }
        }
        _ => {}
    }
}

/// Names this module exports; their values escape the file, so stores to
/// them are never dead (`js/useless-assignment-to-local` exclusion).
fn exported_binding_names(program: &oxc_ast::ast::Program<'_>) -> HashSet<String> {
    struct Collector {
        names: HashSet<String>,
    }
    impl<'a> Visit<'a> for Collector {
        fn visit_export_declaration(&mut self, export: &oxc_ast::ast::ExportDeclaration<'a>) {
            collect_exported_declaration_names(&export.declaration, &mut self.names);
            oxc_ast_visit::walk::walk_export_declaration(self, export);
        }

        fn visit_export_named_declaration(
            &mut self,
            declaration: &oxc_ast::ast::ExportNamedDeclaration<'a>,
        ) {
            for specifier in &declaration.specifiers {
                if let Some(name) = module_export_name_name(&specifier.local) {
                    self.names.insert(name.to_owned());
                }
            }
            oxc_ast_visit::walk::walk_export_named_declaration(self, declaration);
        }

        fn visit_export_default_declaration(
            &mut self,
            declaration: &oxc_ast::ast::ExportDefaultDeclaration<'a>,
        ) {
            if let oxc_ast::ast::ExportDefaultDeclarationKind::FunctionDeclaration(function) =
                &declaration.declaration
                && let Some(identifier) = &function.id
            {
                self.names.insert(identifier.name.as_str().to_owned());
            }
            oxc_ast_visit::walk::walk_export_default_declaration(self, declaration);
        }
    }
    let mut collector = Collector {
        names: HashSet::new(),
    };
    collector.visit_program(program);
    collector.names
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
    use std::fmt::Write as _;

    use super::analyze_github_quality;
    use crate::JstsLanguage;

    fn ids(source: &str, language: JstsLanguage) -> Vec<String> {
        analyze_github_quality(source, language)
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect()
    }

    /// Rule ids of the original registry, excluding the four reference
    /// detectors added for issues #144-147: tests written before those
    /// detectors landed pin only the earlier checks and keep their own
    /// coverage for the new ids.
    fn legacy_ids(source: &str, language: JstsLanguage) -> Vec<String> {
        ids(source, language)
            .into_iter()
            .filter(|id| {
                !matches!(
                    id.as_str(),
                    "js/automatic-semicolon-insertion"
                        | "js/trivial-conditional"
                        | "js/useless-assignment-to-local"
                        | "js/useless-expression"
                )
            })
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
        assert!(legacy_ids(source, JstsLanguage::JavaScript).is_empty());
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
            !legacy_ids(different_literals, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-property")
        );

        let same_expression = "const object = { key: value /* comment */, key: value };";
        assert!(
            legacy_ids(same_expression, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-property")
        );

        let computed_same = "const object = { [\"key\"]: value, key: value };";
        assert!(
            legacy_ids(computed_same, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-property")
        );

        let cases = "switch (value) { case 'a b': break; case 'ab': break; }";
        assert!(
            !legacy_ids(cases, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-switch-case")
        );
    }

    #[test]
    fn duplicate_properties_normalize_static_computed_keys_without_guessing_dynamic_ones() {
        let duplicate_count = |source: &str, language: JstsLanguage| {
            legacy_ids(source, language)
                .into_iter()
                .filter(|id| id == "js/duplicate-property")
                .count()
        };

        assert_eq!(
            duplicate_count(
                r#"const computedStatic = { ["item"]: 1, item: 1 };"#,
                JstsLanguage::JavaScript,
            ),
            1
        );
        assert_eq!(
            duplicate_count(
                r#"const typedComputed = { ["item"]: 1, item: 1 };"#,
                JstsLanguage::TypeScript,
            ),
            1
        );
        assert_eq!(
            duplicate_count(
                r#"const unicodeKey = { ["café"]: 1, café: 1 };"#,
                JstsLanguage::TypeScript,
            ),
            1
        );
        assert_eq!(
            duplicate_count(
                "const literalDuplicate = { item: 1, item: 1 };",
                JstsLanguage::JavaScript,
            ),
            1
        );
        assert_eq!(
            duplicate_count(
                "const differentInitializer = { item: 1, item: 2 };",
                JstsLanguage::JavaScript,
            ),
            0
        );
        assert_eq!(
            duplicate_count(
                "const getterSetter = { get item() { return 1; }, set item(value) { void value; } };",
                JstsLanguage::JavaScript,
            ),
            0
        );
        assert_eq!(
            duplicate_count(
                "const dynamicKey = { [keyFromSomewhere]: 1, item: 1 };",
                JstsLanguage::JavaScript,
            ),
            0
        );
    }

    #[test]
    fn unused_index_requires_every_access_to_be_an_integer_constant() {
        let dynamic = "for (let i = 0; i < values.length; ++i) { values[0]; values[getIndex()]; }";
        assert!(
            !legacy_ids(dynamic, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/unused-index-variable")
        );
        let constants = "for (let i = 0; i < values.length; ++i) { values[0]; values[1]; }";
        assert!(
            legacy_ids(constants, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/unused-index-variable")
        );
    }

    #[test]
    fn arguments_and_duplicate_parameters_follow_lexical_bindings() {
        let arrow = "const f = () => { arguments = 1; };";
        assert!(
            !legacy_ids(arrow, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let destructured = "function f([arguments]) { arguments = 1; }";
        assert!(
            legacy_ids(destructured, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let accessed_dummy = "function f(_, _) { return _; }";
        assert!(
            legacy_ids(accessed_dummy, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-parameter-name")
        );
        let arrow_local = "const f = () => { let arguments = 1; };";
        assert!(
            legacy_ids(arrow_local, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let for_of = "function f() { for ([arguments] of values) {} }";
        assert!(
            legacy_ids(for_of, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let for_in = "function f() { for ({arguments} in values) {} }";
        assert!(
            legacy_ids(for_in, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let ambient = "declare function f(arguments: string[]): string;";
        assert!(
            !legacy_ids(ambient, JstsLanguage::TypeScript)
                .iter()
                .any(|id| id == "js/arguments-redefinition")
        );
        let nested_dummy = "function f(_, _) { function g(_) { return _; } }";
        assert!(
            !legacy_ids(nested_dummy, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/duplicate-parameter-name")
        );
    }
    #[test]
    fn shorthand_duplicates_and_shadowed_indexes_use_identity() {
        let shorthand = "const x = value; const object = { x, x };";
        assert_eq!(
            legacy_ids(shorthand, JstsLanguage::JavaScript)
                .iter()
                .filter(|id| *id == "js/duplicate-property")
                .count(),
            1
        );

        let shadowed = "for (let i = 0; i < values.length; ++i) { let i = 1; values[0]; }";
        assert!(
            legacy_ids(shadowed, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/unused-index-variable")
        );
        let used = "for (let i = 0; i < values.length; ++i) { values[i]; }";
        assert!(
            !legacy_ids(used, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/unused-index-variable")
        );
    }

    #[test]
    fn whitespace_zero_gap_and_loop_update_forms_are_exact() {
        let spaced = "const value = a+b * c;";
        assert!(
            legacy_ids(spaced, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/whitespace-contradicts-precedence")
        );
        let compound_update = "for (let i = 0; i < values.length; i += 1) values[0];";
        assert!(
            !legacy_ids(compound_update, JstsLanguage::JavaScript)
                .iter()
                .any(|id| id == "js/inconsistent-loop-direction")
        );
    }

    // --- GitHub Code Quality pinned-detector regression coverage ---

    fn find_issue<'a>(
        issues: &'a [hoonarqube_ir::Issue],
        rule_key: &str,
    ) -> Vec<&'a hoonarqube_ir::Issue> {
        issues
            .iter()
            .filter(|issue| issue.rule_key == rule_key)
            .collect()
    }

    fn assert_issue_at(
        issues: &[hoonarqube_ir::Issue],
        rule_key: &str,
        message: &str,
        start: (u32, u32),
        end: (u32, u32),
    ) {
        let found = find_issue(issues, rule_key);
        assert!(
            found.iter().any(|issue| issue.message == message
                && (issue.range.start.line, issue.range.start.column) == start
                && (issue.range.end.line, issue.range.end.column) == end),
            "expected {rule_key} {message:?} at {start:?}-{end:?}, got: {found:#?}"
        );
    }

    #[test]
    fn automatic_semicolon_insertion_reports_missing_semicolons_in_explicit_majority() {
        // 13 of 14 script statements are explicit (92%): the one ASI
        // statement is reported on its last line.
        let mut source = String::new();
        for index in 0..13 {
            let _ = writeln!(source, "var v{index} = {index};");
        }
        source.push_str("var rest = 13\n");
        let issues = analyze_github_quality(&source, JstsLanguage::JavaScript);
        assert_issue_at(
            &issues,
            "js/automatic-semicolon-insertion",
            "Avoid automated semicolon insertion (92% of all statements in the \
             enclosing script have an explicit semicolon).",
            (14, 0),
            (14, 13),
        );

        // Within a function the container is the enclosing function, not the
        // script; 19 of 20 statements are explicit (95%).
        let mut source = String::from("function f() {\n");
        for index in 0..19 {
            let _ = writeln!(source, "  this.a('{index:02}');");
        }
        source.push_str("  this.a('19')\n}\n");
        let issues = analyze_github_quality(&source, JstsLanguage::JavaScript);
        assert_issue_at(
            &issues,
            "js/automatic-semicolon-insertion",
            "Avoid automated semicolon insertion (95% of all statements in the \
             enclosing function have an explicit semicolon).",
            (21, 2),
            (21, 14),
        );
    }

    #[test]
    fn automatic_semicolon_insertion_ignores_minority_and_non_subject_statements() {
        // Only two of three statements are explicit (67%): style is not
        // consistent enough to judge the ASI statement a deviation.
        let relaxed = "var a = 1\nvar b = 2\nvar c = 3;\n";
        assert!(
            find_issue(
                &analyze_github_quality(relaxed, JstsLanguage::JavaScript),
                "js/automatic-semicolon-insertion"
            )
            .is_empty()
        );

        // Blocks, ifs, and loop heads are not subject to semicolon insertion
        // and must not dilute the denominator: `work();` (explicit) and
        // `done()` (ASI) split 50/50, so nothing is reported.
        let mixed = concat!(
            "function g(c) {\n",
            "  if (c) {\n",
            "    work();\n",
            "  }\n",
            "  done()\n",
            "}\n",
        );
        assert!(
            find_issue(
                &analyze_github_quality(mixed, JstsLanguage::JavaScript),
                "js/automatic-semicolon-insertion"
            )
            .is_empty()
        );
    }

    #[test]
    fn trivial_conditional_reports_guard_refined_variables() {
        // Inside the `err && ...` guard the left operand of the inner logical
        // expression is refined to always-truthy (the pinned axios shape).
        let truthy = concat!(
            "function handle(err) {\n",
            "  if (err && err.name === 'TypeError') {\n",
            "    const extra = err && err.response;\n",
            "  }\n",
            "}\n",
        );
        let issues = analyze_github_quality(truthy, JstsLanguage::JavaScript);
        assert_issue_at(
            &issues,
            "js/trivial-conditional",
            "This use of variable 'err' always evaluates to true.",
            (3, 18),
            (3, 21),
        );

        // A negated guard refines the same variable to always-falsy.
        let falsy = concat!(
            "function reject(err) {\n",
            "  if (!err) {\n",
            "    return err && null;\n",
            "  }\n",
            "}\n",
        );
        let issues = analyze_github_quality(falsy, JstsLanguage::JavaScript);
        assert_issue_at(
            &issues,
            "js/trivial-conditional",
            "This use of variable 'err' always evaluates to false.",
            (3, 11),
            (3, 14),
        );
    }

    #[test]
    fn trivial_conditional_whitelists_constants_and_unrefined_conditions() {
        // Literal tests are whitelisted by the reference query, symbolic
        // constants stay out even when they appear in guards, and a plain
        // parameter check without a nested re-check is never constant.
        let source = concat!(
            "const DEBUG = true;\n",
            "function check(x) {\n",
            "  if (true) {\n",
            "    ready();\n",
            "  }\n",
            "  if (DEBUG && x) {\n",
            "    go();\n",
            "  }\n",
            "}\n",
        );
        assert!(
            find_issue(
                &analyze_github_quality(source, JstsLanguage::JavaScript),
                "js/trivial-conditional"
            )
            .is_empty()
        );
    }

    #[test]
    fn useless_assignment_reports_overwritten_and_exit_dead_stores() {
        let source = concat!(
            "function load(state) {\n",
            "  let max = state.a;\n",
            "  max = state.b;\n",
            "  return max;\n",
            "}\n",
            "\n",
            "function drop(out) {\n",
            "  let start = out.pos;\n",
            "  start = out.limit;\n",
            "  return 1;\n",
            "}\n",
        );
        let issues = analyze_github_quality(source, JstsLanguage::JavaScript);
        assert_issue_at(
            &issues,
            "js/useless-assignment-to-local",
            "The initial value of max is unused, since it is always overwritten.",
            (2, 6),
            (2, 19),
        );
        assert_issue_at(
            &issues,
            "js/useless-assignment-to-local",
            "The initial value of start is unused, since it is always overwritten.",
            (8, 6),
            (8, 21),
        );
        assert_issue_at(
            &issues,
            "js/useless-assignment-to-local",
            "The value assigned to start here is unused.",
            (9, 2),
            (9, 19),
        );
    }

    #[test]
    fn useless_assignment_respects_purely_local_and_value_controls() {
        // Read after the store: the value is used.
        let read = "function f() {\n  let x = 1;\n  return x;\n}\n";
        assert!(
            find_issue(
                &analyze_github_quality(read, JstsLanguage::JavaScript),
                "js/useless-assignment-to-local"
            )
            .is_empty()
        );

        // Captured by a closure: not a purely local variable.
        let captured =
            "function f() {\n  let x = 1;\n  return function () {\n    return x;\n  };\n}\n";
        assert!(
            find_issue(
                &analyze_github_quality(captured, JstsLanguage::JavaScript),
                "js/useless-assignment-to-local"
            )
            .is_empty()
        );

        // null/undefined stores are deliberately out of scope, an
        // initializer-less `var` is a runtime no-op, a completely unused
        // declarator belongs to unused-variable rules, and exported bindings
        // escape the module.
        let nulls = concat!(
            "function f() {\n",
            "  let x = null;\n",
            "  let y = undefined;\n",
            "  var later;\n",
            "  later = 1;\n",
            "  return later;\n",
            "}\n",
            "function g() {\n",
            "  let unused = 1;\n",
            "}\n",
            "export const exported = 1;\n",
        );
        assert!(
            find_issue(
                &analyze_github_quality(nulls, JstsLanguage::JavaScript),
                "js/useless-assignment-to-local"
            )
            .is_empty()
        );
    }

    #[test]
    fn useless_expression_reports_pure_property_statement() {
        let source = concat!(
            "function strict(message) {\n",
            "  errorUtil.errToObj;\n",
            "  return 1;\n",
            "}\n",
        );
        let issues = analyze_github_quality(source, JstsLanguage::JavaScript);
        assert_issue_at(
            &issues,
            "js/useless-expression",
            "This expression has no effect.",
            (2, 2),
            (2, 20),
        );
    }

    #[test]
    fn useless_expression_side_effect_and_declaration_controls() {
        // Calls have effects; JSDoc-tagged reads are declarations; same-file
        // getters make the property read potentially effectful; the first
        // statement of a try block is excluded; a lone config object and a
        // single-statement file without functions stay out; and an
        // initializer is not a void context.
        let cases = [
            "function f(a) {\n  a.foo();\n}\n",
            "function f() {}\n/** @type {number} */\nflag;\n",
            "class Counter {\n  get count() {\n    return 1;\n  }\n}\nfunction read(it) {\n  it.count;\n}\n",
            "function f(it) {\n  try {\n    it.value;\n  } catch (e) {\n    handle(e);\n  }\n}\n",
            "({ base: 'x' });\n",
            "onlyValue;\n",
            "const kept = config.value;\n",
        ];
        for source in cases {
            assert!(
                find_issue(
                    &analyze_github_quality(source, JstsLanguage::JavaScript),
                    "js/useless-expression"
                )
                .is_empty(),
                "unexpected js/useless-expression for {source:?}"
            );
        }
    }
}
