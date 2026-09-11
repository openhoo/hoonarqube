use super::collectors::{FunctionMetricsCollector, ReturnMixScanner};
use crate::rules::shared::argument_expression;
use crate::support::{RuleScope, member_object, unparenthesized};
use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, BindingPattern, BlockStatement, CallExpression,
    CatchClause, Declaration, Expression, ForInStatement, ForOfStatement, ForStatement,
    FormalParameter, FormalParameterRest, Function, FunctionBody, ImportDeclaration,
    ImportDeclarationSpecifier, MemberExpression, Program, SimpleAssignmentTarget, Statement,
    StaticBlock, SwitchStatement, TSType, TSTypeAliasDeclaration, TSTypeAnnotation, TSTypeName,
    UpdateExpression, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_block_statement,
    walk_call_expression, walk_catch_clause, walk_declaration, walk_for_in_statement,
    walk_for_of_statement, walk_for_statement, walk_formal_parameter, walk_formal_parameter_rest,
    walk_function, walk_import_declaration, walk_program, walk_static_block, walk_switch_statement,
    walk_ts_type_alias_declaration, walk_update_expression, walk_variable_declaration,
    walk_variable_declarator,
};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;
use std::collections::BTreeSet;

/// `S3796`: array methods whose callbacks are expected to return values.
/// `forEach` is deliberately absent — its callbacks legitimately produce
/// nothing, so they never carry a missing-return defect.
const ARRAY_CALLBACK_METHODS: [&str; 10] = [
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

const TYPED_ARRAY_CONSTRUCTORS: [&str; 12] = [
    "Array",
    "BigInt64Array",
    "BigUint64Array",
    "Float32Array",
    "Float64Array",
    "Int8Array",
    "Int16Array",
    "Int32Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "Uint16Array",
    "Uint32Array",
];

const ARRAY_TYPE_NAMES: [&str; 13] = [
    "Array",
    "ReadonlyArray",
    "BigInt64Array",
    "BigUint64Array",
    "Float32Array",
    "Float64Array",
    "Int8Array",
    "Int16Array",
    "Int32Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "Uint16Array",
    "Uint32Array",
];

/// Whether one function body carries no value-returning statement outside
/// nested functions (`S3796`).
fn lacks_valued_return(body: &FunctionBody<'_>) -> bool {
    let mut scanner = ReturnMixScanner::default();
    scanner.visit_function_body(body);
    scanner.valued_spans.is_empty()
}

fn unwrapped_expression<'a, 'b>(expression: &'a Expression<'b>) -> &'a Expression<'b> {
    let mut current = expression;
    loop {
        current = match current {
            Expression::ParenthesizedExpression(parenthesized) => &parenthesized.expression,
            Expression::TSAsExpression(assertion) => &assertion.expression,
            Expression::TSSatisfiesExpression(assertion) => &assertion.expression,
            Expression::TSTypeAssertion(assertion) => &assertion.expression,
            Expression::TSNonNullExpression(assertion) => &assertion.expression,
            Expression::TSInstantiationExpression(instantiation) => &instantiation.expression,
            _ => break,
        };
    }
    current
}
fn typed_array_name<'a>(expression: &Expression<'a>) -> Option<&'a str> {
    let Expression::Identifier(identifier) = unwrapped_expression(expression) else {
        return None;
    };
    TYPED_ARRAY_CONSTRUCTORS
        .contains(&identifier.name.as_str())
        .then_some(identifier.name.as_str())
}

fn call_member_property<'r, 'a>(
    call: &'r CallExpression<'a>,
) -> Option<(&'r str, &'r MemberExpression<'a>)> {
    let member = call.callee.as_member_expression()?;
    let property = match member {
        MemberExpression::StaticMemberExpression(member) => member.property.name.as_str(),
        MemberExpression::ComputedMemberExpression(member) => {
            match unparenthesized(&member.expression) {
                Expression::StringLiteral(literal) => literal.value.as_str(),
                _ => return None,
            }
        }
        MemberExpression::PrivateFieldExpression(_) => return None,
    };
    Some((property, member))
}

#[derive(Clone, Copy)]
enum BindingKind<'a> {
    ArrayLiteral,
    TypedArray(&'a str),
    AnnotatedArray,
    Unknown,
}

#[derive(Clone, Copy)]
struct S3796Scope {
    parent: Option<usize>,
}

struct S3796Binding<'a> {
    name: &'a str,
    scope: usize,
    states: Vec<S3796BindingState<'a>>,
    start: u32,
    hoisted: bool,
}

struct S3796TypeBinding<'a> {
    name: &'a str,
    scope: usize,
}

struct S3796BindingState<'a> {
    start: u32,
    kind: BindingKind<'a>,
}

struct S3796Write<'a> {
    name: &'a str,
    scope: usize,
    start: u32,
}

#[derive(Clone)]
enum S3796Receiver {
    ArrayLiteral,
    TypedArray(String),
    Identifier(String),
    Unknown,
}

struct S3796Call {
    start: u32,
    scope: usize,
    receiver: S3796Receiver,
}

#[derive(Default)]
struct S3796BindingCollector<'a> {
    scopes: Vec<S3796Scope>,
    scope_stack: Vec<usize>,
    function_scope_stack: Vec<usize>,
    bindings: Vec<S3796Binding<'a>>,
    type_bindings: Vec<S3796TypeBinding<'a>>,
    writes: Vec<S3796Write<'a>>,
    calls: Vec<S3796Call>,
    in_var_declaration: bool,
}

impl<'a> S3796BindingCollector<'a> {
    fn push_scope(&mut self) {
        let parent = self.scope_stack.last().copied();
        self.scopes.push(S3796Scope { parent });
        self.scope_stack.push(self.scopes.len() - 1);
    }

    fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    fn current_scope(&self) -> usize {
        self.scope_stack
            .last()
            .copied()
            .expect("S3796 scope stack must contain a scope")
    }

    fn current_function_scope(&self) -> usize {
        self.function_scope_stack
            .last()
            .copied()
            .expect("S3796 function scope stack must contain a scope")
    }
    fn record_type_binding(&mut self, name: &'a str) {
        let scope = self.current_scope();
        if !self
            .type_bindings
            .iter()
            .any(|binding| binding.scope == scope && binding.name == name)
        {
            self.type_bindings.push(S3796TypeBinding { name, scope });
        }
    }

    fn type_name_is_shadowed(&self, mut scope: usize, name: &str) -> bool {
        loop {
            if self
                .type_bindings
                .iter()
                .any(|binding| binding.scope == scope && binding.name == name)
            {
                return true;
            }
            let Some(parent) = self.scopes[scope].parent else {
                return false;
            };
            scope = parent;
        }
    }

    fn type_is_array_like(&self, annotation: &TSTypeAnnotation<'_>, scope: usize) -> bool {
        self.type_is_array_like_type(&annotation.type_annotation, scope)
    }

    fn type_is_array_like_type(&self, type_: &TSType<'_>, scope: usize) -> bool {
        match type_ {
            TSType::TSArrayType(_) | TSType::TSTupleType(_) => true,
            TSType::TSTypeReference(reference) => match &reference.type_name {
                TSTypeName::IdentifierReference(identifier) => {
                    ARRAY_TYPE_NAMES.contains(&identifier.name.as_str())
                        && !self.type_name_is_shadowed(scope, identifier.name.as_str())
                }
                _ => false,
            },
            TSType::TSParenthesizedType(parenthesized) => {
                self.type_is_array_like_type(&parenthesized.type_annotation, scope)
            }
            _ => false,
        }
    }

    fn record_binding_in_scope(
        &mut self,
        scope: usize,
        name: &'a str,
        kind: BindingKind<'a>,
        start: u32,
        hoisted: bool,
    ) {
        if let Some(binding) = self
            .bindings
            .iter_mut()
            .find(|binding| binding.scope == scope && binding.name == name)
        {
            binding.states.push(S3796BindingState { start, kind });
            binding.start = binding.start.min(start);
            binding.hoisted |= hoisted;
            return;
        }
        self.bindings.push(S3796Binding {
            name,
            scope,
            states: vec![S3796BindingState { start, kind }],
            start,
            hoisted,
        });
    }

    fn record_binding(&mut self, name: &'a str, kind: BindingKind<'a>, start: u32, hoisted: bool) {
        self.record_binding_in_scope(self.current_scope(), name, kind, start, hoisted);
    }

    fn record_pattern_in_scope(
        &mut self,
        scope: usize,
        pattern: &BindingPattern<'a>,
        kind: BindingKind<'a>,
        start: u32,
        hoisted: bool,
    ) {
        match pattern {
            BindingPattern::BindingIdentifier(identifier) => {
                self.record_binding_in_scope(scope, identifier.name.as_str(), kind, start, hoisted);
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    self.record_pattern_in_scope(
                        scope,
                        &property.value,
                        BindingKind::Unknown,
                        start,
                        hoisted,
                    );
                }
                if let Some(rest) = &object.rest {
                    self.record_pattern_in_scope(
                        scope,
                        &rest.argument,
                        BindingKind::Unknown,
                        start,
                        hoisted,
                    );
                }
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    self.record_pattern_in_scope(
                        scope,
                        element,
                        BindingKind::Unknown,
                        start,
                        hoisted,
                    );
                }
                if let Some(rest) = &array.rest {
                    self.record_pattern_in_scope(
                        scope,
                        &rest.argument,
                        BindingKind::Unknown,
                        start,
                        hoisted,
                    );
                }
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.record_pattern_in_scope(scope, &assignment.left, kind, start, hoisted);
            }
        }
    }

    fn record_pattern(
        &mut self,
        pattern: &BindingPattern<'a>,
        kind: BindingKind<'a>,
        start: u32,
        hoisted: bool,
    ) {
        self.record_pattern_in_scope(self.current_scope(), pattern, kind, start, hoisted);
    }

    fn resolve_binding(&self, mut scope: usize, name: &str, start: u32) -> Option<usize> {
        loop {
            if let Some(binding) = self
                .bindings
                .iter()
                .enumerate()
                .filter(|(_, binding)| binding.scope == scope && binding.name == name)
                .filter(|(_, binding)| binding.states.iter().any(|state| state.start <= start))
                .max_by_key(|(_, binding)| binding.start)
            {
                return Some(binding.0);
            }
            if let Some(binding) = self
                .bindings
                .iter()
                .enumerate()
                .filter(|(_, binding)| binding.scope == scope && binding.name == name)
                .min_by_key(|(_, binding)| (binding.start, !binding.hoisted))
            {
                return Some(binding.0);
            }
            let parent = self.scopes[scope].parent?;
            scope = parent;
        }
    }
    fn binding_is_array_like(&self, binding_id: usize, scope: usize, start: u32) -> bool {
        let binding = &self.bindings[binding_id];
        let Some(state) = binding
            .states
            .iter()
            .filter(|state| state.start <= start)
            .max_by_key(|state| state.start)
        else {
            return false;
        };
        if self
            .writes
            .iter()
            .filter(|write| {
                write.name == binding.name
                    && write.start <= start
                    && self.resolve_binding(write.scope, write.name, write.start)
                        == Some(binding_id)
            })
            .max_by_key(|write| write.start)
            .is_some_and(|write| write.start > state.start)
        {
            return false;
        }
        match state.kind {
            BindingKind::ArrayLiteral | BindingKind::AnnotatedArray => true,
            BindingKind::TypedArray(name) => self.constructor_is_builtin(name, scope, start),
            BindingKind::Unknown => false,
        }
    }

    fn constructor_is_builtin(&self, name: &str, scope: usize, start: u32) -> bool {
        self.resolve_binding(scope, name, start).is_none()
            && !self.writes.iter().any(|write| {
                write.name == name
                    && write.start <= start
                    && self
                        .resolve_binding(write.scope, name, write.start)
                        .is_none()
            })
    }

    fn receiver_is_array(&self, receiver: &S3796Receiver, scope: usize, start: u32) -> bool {
        match receiver {
            S3796Receiver::ArrayLiteral => true,
            S3796Receiver::TypedArray(name) => self.constructor_is_builtin(name, scope, start),
            S3796Receiver::Identifier(name) => self
                .resolve_binding(scope, name, start)
                .is_some_and(|binding| self.binding_is_array_like(binding, scope, start)),
            S3796Receiver::Unknown => false,
        }
    }
}

impl<'a> Visit<'a> for S3796BindingCollector<'a> {
    fn visit_program(&mut self, it: &Program<'a>) {
        self.push_scope();
        self.function_scope_stack.push(self.current_scope());
        walk_program(self, it);
        self.function_scope_stack.pop();
        self.pop_scope();
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        self.push_scope();
        self.function_scope_stack.push(self.current_scope());
        if let Some(id) = &it.id {
            self.record_binding(id.name.as_str(), BindingKind::Unknown, it.span.start, true);
        }
        walk_function(self, it, flags);
        self.function_scope_stack.pop();
        self.pop_scope();
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.push_scope();
        self.function_scope_stack.push(self.current_scope());
        walk_arrow_function_expression(self, it);
        self.function_scope_stack.pop();
        self.pop_scope();
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.push_scope();
        walk_block_statement(self, it);
        self.pop_scope();
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.push_scope();
        walk_for_statement(self, it);
        self.pop_scope();
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.push_scope();
        walk_for_in_statement(self, it);
        self.pop_scope();
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.push_scope();
        walk_for_of_statement(self, it);
        self.pop_scope();
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        self.push_scope();
        walk_switch_statement(self, it);
        self.pop_scope();
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.push_scope();
        walk_static_block(self, it);
        self.pop_scope();
    }

    fn visit_ts_type_alias_declaration(&mut self, it: &TSTypeAliasDeclaration<'a>) {
        self.record_type_binding(it.id.name.as_str());
        walk_ts_type_alias_declaration(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        if let Some(specifiers) = &it.specifiers {
            for specifier in specifiers {
                let local = match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(specifier) => &specifier.local,
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
                        &specifier.local
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
                        &specifier.local
                    }
                };
                self.record_binding(
                    local.name.as_str(),
                    BindingKind::Unknown,
                    local.span.start,
                    true,
                );
            }
        }
        walk_import_declaration(self, it);
    }

    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        let is_var = it.kind == VariableDeclarationKind::Var;
        if is_var {
            let scope = self.current_function_scope();
            let type_scope = self.current_scope();
            for declarator in &it.declarations {
                let kind = if declarator
                    .type_annotation
                    .as_deref()
                    .is_some_and(|annotation| self.type_is_array_like(annotation, type_scope))
                {
                    BindingKind::AnnotatedArray
                } else {
                    match declarator.init.as_ref().map(unwrapped_expression) {
                        Some(Expression::ArrayExpression(_)) => BindingKind::ArrayLiteral,
                        Some(Expression::NewExpression(new_expression)) => {
                            typed_array_name(&new_expression.callee)
                                .map_or(BindingKind::Unknown, BindingKind::TypedArray)
                        }
                        _ => BindingKind::Unknown,
                    }
                };
                self.record_pattern_in_scope(
                    scope,
                    &declarator.id,
                    kind,
                    declarator.span.start,
                    true,
                );
            }
        }
        let was_var = self.in_var_declaration;
        self.in_var_declaration = is_var;
        walk_variable_declaration(self, it);
        self.in_var_declaration = was_var;
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if !self.in_var_declaration {
            let kind =
                if it.type_annotation.as_deref().is_some_and(|annotation| {
                    self.type_is_array_like(annotation, self.current_scope())
                }) {
                    BindingKind::AnnotatedArray
                } else {
                    match it.init.as_ref().map(unwrapped_expression) {
                        Some(Expression::ArrayExpression(_)) => BindingKind::ArrayLiteral,
                        Some(Expression::NewExpression(new_expression)) => {
                            typed_array_name(&new_expression.callee)
                                .map_or(BindingKind::Unknown, BindingKind::TypedArray)
                        }
                        _ => BindingKind::Unknown,
                    }
                };
            self.record_pattern(&it.id, kind, it.span.start, false);
        }
        walk_variable_declarator(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        let kind = it
            .type_annotation
            .as_deref()
            .filter(|annotation| self.type_is_array_like(annotation, self.current_scope()))
            .map_or(BindingKind::Unknown, |_| BindingKind::AnnotatedArray);
        self.record_pattern(&it.pattern, kind, it.span.start, false);
        walk_formal_parameter(self, it);
    }

    fn visit_formal_parameter_rest(&mut self, it: &FormalParameterRest<'a>) {
        let kind = it
            .type_annotation
            .as_deref()
            .filter(|annotation| self.type_is_array_like(annotation, self.current_scope()))
            .map_or(BindingKind::Unknown, |_| BindingKind::AnnotatedArray);
        self.record_pattern(&it.rest.argument, kind, it.span.start, false);
        walk_formal_parameter_rest(self, it);
    }

    fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
        self.push_scope();
        if let Some(parameter) = &it.param {
            let kind = parameter
                .type_annotation
                .as_deref()
                .filter(|annotation| self.type_is_array_like(annotation, self.current_scope()))
                .map_or(BindingKind::Unknown, |_| BindingKind::AnnotatedArray);
            self.record_pattern(&parameter.pattern, kind, parameter.span.start, false);
        }
        walk_catch_clause(self, it);
        self.pop_scope();
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        match it {
            Declaration::FunctionDeclaration(function) => {
                if let Some(id) = &function.id {
                    self.record_binding(
                        id.name.as_str(),
                        BindingKind::Unknown,
                        function.span.start,
                        true,
                    );
                }
            }
            Declaration::ClassDeclaration(class) => {
                if let Some(id) = &class.id {
                    self.record_binding(
                        id.name.as_str(),
                        BindingKind::Unknown,
                        class.span.start,
                        false,
                    );
                }
            }
            _ => {}
        }
        walk_declaration(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let Some(SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier)) =
            it.left.as_simple_assignment_target()
        {
            self.writes.push(S3796Write {
                name: identifier.name.as_str(),
                scope: self.current_scope(),
                start: it.span.start,
            });
        }
        walk_assignment_expression(self, it);
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        if let SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) = &it.argument {
            self.writes.push(S3796Write {
                name: identifier.name.as_str(),
                scope: self.current_scope(),
                start: it.span.start,
            });
        }
        walk_update_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Some((property, member)) = call_member_property(it)
            && ARRAY_CALLBACK_METHODS.contains(&property)
        {
            self.calls.push(S3796Call {
                start: it.span.start,
                scope: self.current_scope(),
                receiver: match unwrapped_expression(member_object(member)) {
                    Expression::ArrayExpression(_) => S3796Receiver::ArrayLiteral,
                    Expression::NewExpression(new_expression) => {
                        typed_array_name(&new_expression.callee)
                            .map_or(S3796Receiver::Unknown, |name| {
                                S3796Receiver::TypedArray(name.to_owned())
                            })
                    }
                    Expression::Identifier(identifier) => {
                        S3796Receiver::Identifier(identifier.name.to_string())
                    }
                    _ => S3796Receiver::Unknown,
                },
            });
        }
        walk_call_expression(self, it);
    }
}
/// Collects call spans whose receiver is syntactically or binding-wise an
/// array/typed array. Unknown receivers stay out of the set so an object's
/// own `map`/`filter` method is not treated as an array callback.
pub(crate) fn collect_s3796_call_spans(program: &Program<'_>) -> BTreeSet<u32> {
    let mut collector = S3796BindingCollector::default();
    collector.visit_program(program);
    let mut spans = BTreeSet::new();
    for call in &collector.calls {
        if collector.receiver_is_array(&call.receiver, call.scope, call.start) {
            spans.insert(call.start);
        }
    }
    spans
}

fn statements_never_return(statements: &[Statement<'_>]) -> bool {
    statements.iter().any(statement_never_returns)
}

fn statement_never_returns(statement: &Statement<'_>) -> bool {
    match statement {
        Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(block) => statements_never_return(&block.body),
        Statement::IfStatement(branch) => {
            statement_never_returns(&branch.consequent)
                && branch
                    .alternate
                    .as_ref()
                    .is_some_and(statement_never_returns)
        }
        _ => false,
    }
}

fn body_never_returns(body: &FunctionBody<'_>) -> bool {
    let mut scanner = ReturnMixScanner::default();
    scanner.visit_function_body(body);
    scanner.bare_spans.is_empty() && statements_never_return(&body.statements)
}

fn has_never_return_type(annotation: Option<&TSTypeAnnotation<'_>>) -> bool {
    let Some(annotation) = annotation else {
        return false;
    };
    match &annotation.type_annotation {
        TSType::TSNeverKeyword(_) => true,
        TSType::TSParenthesizedType(parenthesized) => {
            matches!(&parenthesized.type_annotation, TSType::TSNeverKeyword(_))
        }
        _ => false,
    }
}

fn callback_needs_return(callback: &Expression<'_>) -> bool {
    match unparenthesized(callback) {
        Expression::FunctionExpression(function) => {
            if function.r#async
                || function.generator
                || has_never_return_type(function.return_type.as_deref())
            {
                return false;
            }
            function
                .body
                .as_deref()
                .is_some_and(|body| !body_never_returns(body) && lacks_valued_return(body))
        }
        Expression::ArrowFunctionExpression(arrow) => {
            if arrow.r#async || has_never_return_type(arrow.return_type.as_deref()) {
                return false;
            }
            arrow
                .body
                .as_function_body()
                .is_some_and(|body| !body_never_returns(body) && lacks_valued_return(body))
        }
        _ => false,
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl FunctionMetricsCollector<'_> {
    /// `S3796` logic extracted from `visit_call_expression`.
    pub(crate) fn check_s3796_call_expression(&mut self, it: &CallExpression<'_>) {
        let Some((_property, _member)) = call_member_property(it) else {
            return;
        };
        if !self.array_call_spans.contains(&it.span.start) {
            return;
        }
        let Some(callback) = it.arguments.first().and_then(argument_expression) else {
            return;
        };
        if !callback_needs_return(callback) {
            return;
        }
        let anchor = match unparenthesized(callback) {
            Expression::FunctionExpression(function) => {
                Span::new(function.span.start, function.span.start.saturating_add(8))
            }
            _ => callback.span(),
        };
        self.sink.emit_span(
            RuleScope::Both,
            "S3796",
            "Add a \"return\" statement to this callback.",
            anchor,
        );
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{JstsLanguage, count_key, findings};

    fn count(source: &str, language: JstsLanguage) -> usize {
        count_key(
            &findings(source, language),
            &format!("{}:S3796", language.prefix()),
        )
    }

    #[test]
    fn throw_never_and_typescript_callbacks_follow_return_contract() {
        let source = "[1, 2].map(() => { throw new Error('stop'); });\n";
        assert_eq!(count(source, JstsLanguage::JavaScript), 0);
        assert_eq!(count(source, JstsLanguage::TypeScript), 0);

        let empty = "[1, 2].map(value => { console.log(value); });\n";
        assert_eq!(count(empty, JstsLanguage::JavaScript), 1);
        assert_eq!(count(empty, JstsLanguage::TypeScript), 1);

        let conditional_return =
            "[1, 2].map(value => { if (value) return; throw new Error('stop'); });\n";
        assert_eq!(count(conditional_return, JstsLanguage::JavaScript), 1);
        assert_eq!(count(conditional_return, JstsLanguage::TypeScript), 1);
        let throw_with_unreachable_tail =
            "[1].map(() => { throw new Error('stop'); const never = 1; });\n";
        assert_eq!(
            count(throw_with_unreachable_tail, JstsLanguage::JavaScript),
            0
        );
        assert_eq!(
            count(throw_with_unreachable_tail, JstsLanguage::TypeScript),
            0
        );
    }

    #[test]
    fn valued_callbacks_and_foreach_are_clean() {
        let source = "\
            const values = [1, 2];\n\
            values.map(value => value * 2);\n\
            values.filter(value => value > 0);\n\
            values.find(value => value > 0);\n\
            values.every(value => value > 0);\n\
            values.some(value => value > 0);\n\
            values.flatMap(value => [value]);\n\
            values.reduce((left, right) => left + right, 0);\n\
            values.reduceRight((left, right) => left + right, 0);\n\
            values.sort((left, right) => left - right);\n\
            values.forEach(value => console.log(value));\n";
        assert_eq!(count(source, JstsLanguage::JavaScript), 0);
        assert_eq!(count(source, JstsLanguage::TypeScript), 0);
    }

    #[test]
    fn array_controls_and_custom_same_named_methods_are_distinguished() {
        let source = "\
            const values = [1, 2];\n\
            values.filter(() => {});\n\
            values.find(() => {});\n\
            values.findIndex(() => {});\n\
            values.every(() => {});\n\
            values.some(() => {});\n\
            values.flatMap(() => {});\n\
            values.reduce(() => {});\n\
            values.reduceRight(() => {});\n\
            values.sort(() => {});\n\
            values.forEach(() => {});\n\
            const object = {};\n\
            object.map(() => {});\n";
        assert_eq!(count(source, JstsLanguage::JavaScript), 9);
        assert_eq!(count(source, JstsLanguage::TypeScript), 9);
    }

    #[test]
    fn shadowed_and_reassigned_receivers_are_not_misclassified() {
        let shadowed = "\
            const values = [1, 2];\n\
            values.map(() => {});\n\
            function consume(values) { values.map(() => {}); }\n";
        assert_eq!(count(shadowed, JstsLanguage::JavaScript), 1);
        assert_eq!(count(shadowed, JstsLanguage::TypeScript), 1);

        let reassigned = "\
            let values = [1, 2];\n\
            values.map(() => {});\n\
            values = {};\n\
            values.map(() => {});\n";
        assert_eq!(count(reassigned, JstsLanguage::JavaScript), 1);
        assert_eq!(count(reassigned, JstsLanguage::TypeScript), 1);
    }

    #[test]
    fn lexical_shadowing_and_var_redeclarations_follow_call_position() {
        let shadowed = "\
            const values = [1, 2];\n\
            try { throw new Error(); } catch (values) {\n\
                values.map(() => {});\n\
            }\n\
            function consume({ values }) { values.map(() => {}); }\n\
            values.map(() => {});\n";
        assert_eq!(count(shadowed, JstsLanguage::JavaScript), 1);
        assert_eq!(count(shadowed, JstsLanguage::TypeScript), 1);

        let array_then_object = "\
            var values = [1, 2];\n\
            values.map(() => {});\n\
            var values = {};\n\
            values.map(() => {});\n";
        assert_eq!(count(array_then_object, JstsLanguage::JavaScript), 1);
        assert_eq!(count(array_then_object, JstsLanguage::TypeScript), 1);

        let object_then_array = "\
            var values = {};\n\
            values.map(() => {});\n\
            var values = [1, 2];\n\
            values.map(() => {});\n";
        assert_eq!(count(object_then_array, JstsLanguage::JavaScript), 1);
        assert_eq!(count(object_then_array, JstsLanguage::TypeScript), 1);

        let hoisted_var = "\
            const values = [1, 2];\n\
            function consume() {\n\
                values.map(() => {});\n\
                if (true) { var values = {}; }\n\
            }\n";
        assert_eq!(count(hoisted_var, JstsLanguage::JavaScript), 0);
        assert_eq!(count(hoisted_var, JstsLanguage::TypeScript), 0);
        let loop_scope = "\
            const values = [1, 2];\n\
            for (let values of items) { values.map(() => {}); }\n\
            values.map(() => {});\n";
        assert_eq!(count(loop_scope, JstsLanguage::JavaScript), 1);
        assert_eq!(count(loop_scope, JstsLanguage::TypeScript), 1);
    }

    #[test]
    fn typed_arrays_are_checked() {
        let source = "\
            const bytes = new Uint8Array();\n\
            bytes.map(() => {});\n\
            const values = new Array();\n\
            values.map(() => {});\n";
        assert_eq!(count(source, JstsLanguage::JavaScript), 2);
        assert_eq!(count(source, JstsLanguage::TypeScript), 2);
    }

    #[test]
    fn imported_constructor_names_are_not_assumed_builtin() {
        let source = "import Uint8Array from \"custom\";\nnew Uint8Array().map(() => {});\n";
        assert_eq!(count(source, JstsLanguage::JavaScript), 0);
        assert_eq!(count(source, JstsLanguage::TypeScript), 0);
    }
}
