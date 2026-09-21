use super::{
    ArrowFunctionBody, ArrowFunctionExpression, BTreeMap, BinaryExpression, BinaryOperator, Class,
    ClassElement, Declaration, Expression, Function, GetSpan, MethodDefinition,
    MethodDefinitionKind, ReturnStatement, ScopeFlags, Span, Statement, SwitchStatement, TSLiteral,
    TSType, TSTypeAnnotation, TSTypeName, TSTypeOperatorOperator, TSTypeReference, UnaryOperator,
    VariableDeclarator, Visit, binding_identifier_name, identifier_name, property_key_name,
    unparenthesized, walk_binary_expression, walk_class, walk_declaration, walk_function,
    walk_program, walk_return_statement, walk_switch_statement, walk_variable_declarator,
};
// --- Tier C: operator/literal rules over a shared literal classifier ---

/// Literal classification used by the Tier-C operator checks; `None` means
/// the operand's type is unknown (identifiers, calls, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LiteralKind {
    String,
    Number,
    BigInt,
    Boolean,
    Null,
    Undefined,
    Array,
    Object,
    RegExp,
    Function,
}

/// Classifies an expression that is a literal (or literal-shaped, such as
/// `-1` or a template without substitutions).
pub(crate) fn literal_kind(expression: &Expression<'_>) -> Option<LiteralKind> {
    match unparenthesized(expression) {
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_) => Some(LiteralKind::String),
        Expression::NumericLiteral(_) => Some(LiteralKind::Number),
        Expression::BigIntLiteral(_) => Some(LiteralKind::BigInt),
        Expression::BooleanLiteral(_) => Some(LiteralKind::Boolean),
        Expression::NullLiteral(_) => Some(LiteralKind::Null),
        Expression::Identifier(identifier) => match identifier.name.as_str() {
            "undefined" => Some(LiteralKind::Undefined),
            "NaN" | "Infinity" => Some(LiteralKind::Number),
            _ => None,
        },
        Expression::UnaryExpression(unary) => {
            let numeric = matches!(
                unary.operator,
                UnaryOperator::UnaryNegation | UnaryOperator::UnaryPlus
            ) && matches!(
                unparenthesized(&unary.argument),
                Expression::NumericLiteral(_)
            );
            numeric.then_some(LiteralKind::Number)
        }
        Expression::ArrayExpression(_) => Some(LiteralKind::Array),
        Expression::ObjectExpression(_) => Some(LiteralKind::Object),
        Expression::RegExpLiteral(_) => Some(LiteralKind::RegExp),
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => {
            Some(LiteralKind::Function)
        }
        _ => None,
    }
}

/// Whether a classified literal behaves numerically (`S3760`).
pub(crate) fn kind_is_numeric(kind: LiteralKind) -> bool {
    matches!(kind, LiteralKind::Number | LiteralKind::BigInt)
}

/// Whether a classified literal coerces to `'[object Object]'` (`S3758`).
pub(crate) fn kind_is_composite(kind: LiteralKind) -> bool {
    matches!(
        kind,
        LiteralKind::Array | LiteralKind::Object | LiteralKind::RegExp | LiteralKind::Function
    )
}

/// Per-function facts recorded by [`FunctionCensus`].
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // per-facet flags, not states
pub(crate) struct FnFacts {
    pub(crate) r#async: bool,
    pub(crate) generator: bool,
    pub(crate) return_kinds: Vec<LiteralKind>,
    pub(crate) has_valued_return: bool,
    /// A valued `return` whose expression is not a classified literal, so
    /// the produced value is opaque to file-local analysis (`S4123`).
    pub(crate) has_opaque_return: bool,
    /// The function cannot return normally: declared `: never` or a body
    /// that provably diverges (throws) without any `return`.
    pub(crate) never_returns: bool,
    /// A declared return type other than `void`/`never` means calls produce
    /// a value even when the body is absent or has no valued `return`.
    pub(crate) declared_value_return: bool,
    /// A declared return type that covers every classified literal kind the
    /// body returns (`any`/`unknown`, or an explicit union naming each
    /// returned kind) makes mixed returns consistent by contract (`S3800`).
    pub(crate) return_covers_mixed: bool,
    /// A declared return type that is or contains `Promise`/`PromiseLike`,
    /// so awaiting the call is meaningful even without `async` (`S4123`).
    pub(crate) declared_maybe_thenable: bool,
    /// Span of a parameter that only selects the function's behavior.
    pub(crate) selector_span: Option<Span>,
    pub(crate) span: Span,
}

impl FnFacts {
    /// Whether calls of this function provably produce no usable value.
    pub(crate) fn is_void(&self) -> bool {
        !self.r#async
            && !self.generator
            && !self.has_valued_return
            && !self.never_returns
            && !self.declared_value_return
    }
}
/// File-local function facts used by the Tier-C call checks: declaration and
/// `const`-bound function/arrow names with their flags, spans, and the
/// literal kinds of their valued `return`s.
///
/// Facts are grouped by spelling and indexed by the span of the function-like
/// scope whose body lexically declares the binding, so a same-name nested
/// declaration keeps separate facts instead of overwriting the outer ones.
#[derive(Default)]
pub(crate) struct FunctionCensus {
    pub(crate) functions: BTreeMap<String, Vec<ScopedFnFacts>>,
    /// Spans of the enclosing function-like scopes during the walk.
    scopes: Vec<Span>,
}

/// One declared function's facts plus the scope that declares it.
pub(crate) struct ScopedFnFacts {
    pub(crate) facts: FnFacts,
    /// Span of the enclosing function-like scope (the whole program for
    /// top-level declarations).
    pub(crate) scope: Span,
}

impl FunctionCensus {
    /// Resolves `name` at byte `offset` through the innermost enclosing
    /// declaration scope. Textually later same-scope declarations win, so
    /// redeclared function names resolve to their override.
    pub(crate) fn resolve(&self, name: &str, offset: u32) -> Option<&FnFacts> {
        let candidates = self.functions.get(name)?;
        let mut best: Option<(u32, &FnFacts)> = None;
        for scoped in candidates {
            if scoped.scope.start > offset || scoped.scope.end < offset {
                continue;
            }
            let size = scoped.scope.end - scoped.scope.start;
            match best {
                Some((best_size, _)) if best_size < size => {}
                _ => best = Some((size, &scoped.facts)),
            }
        }
        best.map(|(_, facts)| facts)
    }
}

/// Parameter names treated as behavior selectors by `S2301` (weak subset).
const SELECTOR_PARAM_NAMES: [&str; 5] = ["type", "kind", "action", "mode", "command"];

/// Scoped scan of one function body: collects valued-return literal kinds
/// and branch logic driven by named parameters, without descending into
/// nested function-like nodes.
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // per-facet flags, not states
pub(crate) struct BodyScan {
    pub(crate) params: Vec<(String, Span)>,
    pub(crate) return_kinds: Vec<LiteralKind>,
    pub(crate) has_valued_return: bool,
    /// Any `return` statement (valued or bare) in this body.
    pub(crate) has_return: bool,
    /// A valued `return` whose expression is not a classified literal.
    pub(crate) has_opaque_return: bool,
    /// The body's statements provably cannot complete normally.
    pub(crate) never_returns: bool,
    pub(crate) selector_comparisons: u32,
    pub(crate) switches_on_param: bool,
}

impl<'a> Visit<'a> for BodyScan {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        self.has_return = true;
        if let Some(argument) = &it.argument {
            self.has_valued_return = true;
            if let Some(kind) = literal_kind(argument) {
                self.return_kinds.push(kind);
            } else {
                self.has_opaque_return = true;
            }
        }
        walk_return_statement(self, it);
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        if matches!(
            it.operator,
            BinaryOperator::Equality
                | BinaryOperator::StrictEquality
                | BinaryOperator::Inequality
                | BinaryOperator::StrictInequality
        ) {
            let left_is_param = self.param_index(&it.left).is_some();
            let right_is_param = self.param_index(&it.right).is_some();
            let other = if left_is_param {
                Some(&it.right)
            } else if right_is_param {
                Some(&it.left)
            } else {
                None
            };
            if other.is_some_and(|expression| literal_kind(expression).is_some()) {
                self.selector_comparisons += 1;
            }
        }
        walk_binary_expression(self, it);
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        if self.param_index(&it.discriminant).is_some() {
            self.switches_on_param = true;
        }
        walk_switch_statement(self, it);
    }

    /// Nested function-like subtrees belong to other functions.
    fn visit_function(&mut self, _it: &Function<'_>, _flags: ScopeFlags) {}
    fn visit_arrow_function_expression(&mut self, _it: &ArrowFunctionExpression<'_>) {}
    fn visit_method_definition(&mut self, _it: &MethodDefinition<'_>) {}
}

impl BodyScan {
    pub(crate) fn param_index(&self, expression: &Expression<'_>) -> Option<usize> {
        let name = identifier_name(expression)?;
        self.params.iter().position(|(param, _)| param == name)
    }

    /// The span of the first parameter that only selects behavior. A weak
    /// heuristic: switch over the parameter or at least two equality
    /// comparisons against literals.
    pub(crate) fn selector_span(&self) -> Option<Span> {
        let driven = self.switches_on_param || self.selector_comparisons >= 2;
        if !driven {
            return None;
        }
        self.params
            .iter()
            .find(|(name, _)| SELECTOR_PARAM_NAMES.contains(&name.as_str()))
            .map(|(_, span)| *span)
    }
}
pub(crate) fn scan_body(statements: &[Statement<'_>], params: Vec<(String, Span)>) -> BodyScan {
    let mut scan = BodyScan {
        params,
        ..BodyScan::default()
    };
    for statement in statements {
        scan.visit_statement(statement);
    }
    // A body that provably diverges (throws) and contains no `return` at
    // all cannot produce a value, matching a declared `never` return.
    scan.never_returns = !scan.has_return && statements_never_return(statements);
    scan
}

/// Whether one statement cannot complete normally: a `throw`, a block
/// ending in such a statement, or an `if` whose both branches do.
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

fn statements_never_return(statements: &[Statement<'_>]) -> bool {
    statements.iter().any(statement_never_returns)
}

/// Builds [`FnFacts`] from a body scan plus the function's flags and its
/// declared return-type annotation, when present.
fn fn_facts(
    r#async: bool,
    generator: bool,
    annotation: Option<&TSTypeAnnotation<'_>>,
    scan: BodyScan,
    anchor: Span,
) -> FnFacts {
    let declared_never = annotation.is_some_and(annotation_is_never);
    let return_covers_mixed = annotation
        .is_some_and(|annotation| annotation_covers_return_kinds(annotation, &scan.return_kinds));
    FnFacts {
        r#async,
        generator,
        selector_span: scan.selector_span(),
        return_kinds: scan.return_kinds,
        has_valued_return: scan.has_valued_return,
        has_opaque_return: scan.has_opaque_return,
        never_returns: declared_never || scan.never_returns,
        declared_value_return: annotation.is_some_and(annotation_declares_value),
        return_covers_mixed,
        declared_maybe_thenable: annotation.is_some_and(annotation_maybe_thenable),
        span: anchor,
    }
}

/// Strips `TSParenthesizedType` wrappers from a type annotation.
fn unparenthesized_type<'a>(ts_type: &'a TSType<'a>) -> &'a TSType<'a> {
    match ts_type {
        TSType::TSParenthesizedType(parenthesized) => {
            unparenthesized_type(&parenthesized.type_annotation)
        }
        _ => ts_type,
    }
}

/// Whether the annotation is exactly `never` (possibly parenthesized).
fn annotation_is_never(annotation: &TSTypeAnnotation<'_>) -> bool {
    matches!(
        unparenthesized_type(&annotation.type_annotation),
        TSType::TSNeverKeyword(_)
    )
}

/// Whether the annotation declares a usable return value: anything but
/// `void` or `never`.
fn annotation_declares_value(annotation: &TSTypeAnnotation<'_>) -> bool {
    !matches!(
        unparenthesized_type(&annotation.type_annotation),
        TSType::TSVoidKeyword(_) | TSType::TSNeverKeyword(_)
    )
}
/// Whether the declared return type covers every classified literal kind the
/// body actually returns: `any`/`unknown` cover everything, a union covers
/// the union of its members' kinds, and `Promise<...>`/`PromiseLike<...>`
/// covers the awaited kinds. An explicit annotation that names every
/// returned kind — for example `false | true | { id: string }` or
/// `T | undefined` — makes the mixed returns consistent by contract
/// (`S3800`, issues #534 and #806).
fn annotation_covers_return_kinds(
    annotation: &TSTypeAnnotation<'_>,
    kinds: &[LiteralKind],
) -> bool {
    kinds
        .iter()
        .all(|kind| type_covers_kind(&annotation.type_annotation, *kind))
}

/// Whether one declared type admits values of `kind`.
fn type_covers_kind(ts_type: &TSType<'_>, kind: LiteralKind) -> bool {
    match unparenthesized_type(ts_type) {
        TSType::TSAnyKeyword(_) | TSType::TSUnknownKeyword(_) | TSType::JSDocUnknownType(_) => true,
        TSType::TSUnionType(union) => union
            .types
            .iter()
            .any(|member| type_covers_kind(member, kind)),
        TSType::TSTypeReference(reference) => match promise_type_argument(reference) {
            Some(argument) => type_covers_kind(argument, kind),
            None => named_reference_kind(reference) == kind,
        },
        TSType::TSTypeOperatorType(operator)
            if operator.operator == TSTypeOperatorOperator::Readonly =>
        {
            type_covers_kind(&operator.type_annotation, kind)
        }
        TSType::JSDocNullableType(nullable) => {
            kind == LiteralKind::Null || type_covers_kind(&nullable.type_annotation, kind)
        }
        TSType::JSDocNonNullableType(non_nullable) => {
            type_covers_kind(&non_nullable.type_annotation, kind)
        }
        other => named_type_kind(other) == Some(kind),
    }
}

/// The [`LiteralKind`] a non-reference type admits, when it names exactly
/// one. `void` admits `undefined` returns; `never` admits nothing.
fn named_type_kind(ts_type: &TSType<'_>) -> Option<LiteralKind> {
    match ts_type {
        TSType::TSBooleanKeyword(_) => Some(LiteralKind::Boolean),
        TSType::TSNumberKeyword(_) => Some(LiteralKind::Number),
        TSType::TSBigIntKeyword(_) => Some(LiteralKind::BigInt),
        TSType::TSStringKeyword(_) | TSType::TSTemplateLiteralType(_) => Some(LiteralKind::String),
        TSType::TSNullKeyword(_) => Some(LiteralKind::Null),
        TSType::TSUndefinedKeyword(_) | TSType::TSVoidKeyword(_) => Some(LiteralKind::Undefined),
        TSType::TSObjectKeyword(_)
        | TSType::TSTypeLiteral(_)
        | TSType::TSMappedType(_)
        | TSType::TSIntersectionType(_)
        | TSType::TSThisType(_) => Some(LiteralKind::Object),
        TSType::TSArrayType(_) | TSType::TSTupleType(_) => Some(LiteralKind::Array),
        TSType::TSFunctionType(_) | TSType::TSConstructorType(_) => Some(LiteralKind::Function),
        TSType::TSLiteralType(literal) => literal_type_kind(&literal.literal),
        _ => None,
    }
}

/// The [`LiteralKind`] a named type reference admits. `Array`/`ReadonlyArray`
/// and `Function` name their literal kinds; every other named type — aliases,
/// classes, interfaces, qualified names — is an object shape to file-local
/// analysis.
fn named_reference_kind(reference: &TSTypeReference<'_>) -> LiteralKind {
    let TSTypeName::IdentifierReference(identifier) = &reference.type_name else {
        return LiteralKind::Object;
    };
    match identifier.name.as_str() {
        "Array" | "ReadonlyArray" => LiteralKind::Array,
        "Function" => LiteralKind::Function,
        _ => LiteralKind::Object,
    }
}

/// The [`LiteralKind`] a literal type admits (`'a'` → string, `2` → number).
fn literal_type_kind(literal: &TSLiteral<'_>) -> Option<LiteralKind> {
    match literal {
        TSLiteral::BooleanLiteral(_) => Some(LiteralKind::Boolean),
        TSLiteral::NumericLiteral(_) => Some(LiteralKind::Number),
        TSLiteral::BigIntLiteral(_) => Some(LiteralKind::BigInt),
        TSLiteral::StringLiteral(_) | TSLiteral::TemplateLiteral(_) => Some(LiteralKind::String),
        TSLiteral::UnaryExpression(unary) => {
            let numeric = matches!(
                unary.operator,
                UnaryOperator::UnaryNegation | UnaryOperator::UnaryPlus
            ) && matches!(
                unparenthesized(&unary.argument),
                Expression::NumericLiteral(_)
            );
            numeric.then_some(LiteralKind::Number)
        }
    }
}

/// Whether the declared return type is or contains `Promise`/`PromiseLike`,
/// so awaiting the call result is meaningful.
fn annotation_maybe_thenable(annotation: &TSTypeAnnotation<'_>) -> bool {
    type_maybe_thenable(&annotation.type_annotation)
}

fn type_maybe_thenable(ts_type: &TSType<'_>) -> bool {
    match unparenthesized_type(ts_type) {
        TSType::TSTypeReference(reference) => {
            matches!(&reference.type_name, TSTypeName::IdentifierReference(identifier)
                if matches!(identifier.name.as_str(), "Promise" | "PromiseLike"))
        }
        TSType::TSUnionType(union) => union.types.iter().any(type_maybe_thenable),
        _ => false,
    }
}

/// The single type argument of a `Promise<...>`/`PromiseLike<...>` reference.
fn promise_type_argument<'a>(reference: &'a TSTypeReference<'a>) -> Option<&'a TSType<'a>> {
    let TSTypeName::IdentifierReference(identifier) = &reference.type_name else {
        return None;
    };
    if !matches!(identifier.name.as_str(), "Promise" | "PromiseLike") {
        return None;
    }
    let arguments = reference.type_arguments.as_deref()?;
    if arguments.params.len() != 1 {
        return None;
    }
    arguments.params.first()
}

pub(crate) fn parameter_spans(params: &oxc_ast::ast::FormalParameters<'_>) -> Vec<(String, Span)> {
    params
        .items
        .iter()
        .filter_map(|item| {
            binding_identifier_name(&item.pattern).map(|name| (name.to_string(), item.span))
        })
        .collect()
}

impl<'a> Visit<'a> for FunctionCensus {
    fn visit_program(&mut self, program: &oxc_ast::ast::Program<'a>) {
        self.scopes.push(program.span);
        walk_program(self, program);
        self.scopes.pop();
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it
            && let Some(id) = &function.id
        {
            let scan = function
                .body
                .as_ref()
                .map(|body| scan_body(&body.statements, parameter_spans(&function.params)))
                .unwrap_or_default();
            let facts = fn_facts(
                function.r#async,
                function.generator,
                function.return_type.as_deref(),
                scan,
                id.span(),
            );
            self.insert(id.name.to_string(), facts);
        }
        walk_declaration(self, it);
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        self.scopes.push(function.span);
        walk_function(self, function, flags);
        self.scopes.pop();
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        self.scopes.push(class.span);
        walk_class(self, class);
        self.scopes.pop();
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(name) = binding_identifier_name(&it.id)
            && let Some(init) = &it.init
        {
            match unparenthesized(init) {
                Expression::ArrowFunctionExpression(arrow) => {
                    let facts = fn_facts(
                        arrow.r#async,
                        // Arrow functions cannot be generators.
                        false,
                        arrow.return_type.as_deref(),
                        arrow_body_scan(arrow),
                        arrow.span,
                    );
                    self.insert(name.to_string(), facts);
                }
                Expression::FunctionExpression(function) => {
                    let facts = fn_facts(
                        function.r#async,
                        function.generator,
                        function.return_type.as_deref(),
                        function_body_scan(function),
                        function.span,
                    );
                    self.insert(name.to_string(), facts);
                }
                _ => {}
            }
        }
        walk_variable_declarator(self, it);
    }
}

/// Body scan for a function's optional body; bodiless declarations scan
/// empty.
fn function_body_scan(function: &Function<'_>) -> BodyScan {
    function
        .body
        .as_ref()
        .map(|body| scan_body(&body.statements, parameter_spans(&function.params)))
        .unwrap_or_default()
}

/// Body scan for an arrow: statement bodies scan normally; expression
/// bodies produce a single implicit valued return.
fn arrow_body_scan(arrow: &ArrowFunctionExpression<'_>) -> BodyScan {
    if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
        return scan_body(&body.statements, parameter_spans(&arrow.params));
    }
    let mut scan = BodyScan::default();
    if let Some(expression) = arrow.body.as_expression() {
        scan.has_return = true;
        scan.has_valued_return = true;
        if let Some(kind) = literal_kind(expression) {
            scan.return_kinds.push(kind);
        } else {
            scan.has_opaque_return = true;
        }
    }
    scan
}

impl FunctionCensus {
    /// Records one declared function under the innermost open scope.
    fn insert(&mut self, name: String, facts: FnFacts) {
        let scope = self.scopes.last().copied().unwrap_or_default();
        self.functions
            .entry(name)
            .or_default()
            .push(ScopedFnFacts { facts, scope });
    }
}

// --- Tier C: file-local class facts for `S6551` ---

/// File-local class facts used by `S6551`: which classes declare a
/// `toString` member and which locals are constructed from classes that
/// do not.
#[derive(Default)]
pub(crate) struct ClassCensus {
    /// Class declaration name -> whether a `toString` member exists.
    pub(crate) classes: BTreeMap<String, bool>,
    /// Local name -> class name for locals bound through `new C(...)`
    /// where `C` declares no `toString` member.
    pub(crate) instances: BTreeMap<String, String>,
}

impl<'a> Visit<'a> for ClassCensus {
    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::ClassDeclaration(class) = it
            && let Some(id) = &class.id
        {
            self.classes
                .insert(id.name.to_string(), class_declares_to_string(class));
        }
        walk_declaration(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(name) = binding_identifier_name(&it.id)
            && let Some(init) = &it.init
            && let Expression::NewExpression(constructor) = unparenthesized(init)
            && let Expression::Identifier(callee) = &constructor.callee
        {
            self.instances
                .insert(name.to_string(), callee.name.to_string());
        }
        walk_variable_declarator(self, it);
    }
}

impl ClassCensus {
    /// Prunes recorded instances once the whole program is registered;
    /// instantiations may textually precede their class declaration.
    pub(crate) fn finalize(&mut self) {
        let Self { classes, instances } = self;
        instances.retain(|_, class| classes.get(class.as_str()) == Some(&false));
    }
}

/// Whether the class declares a `toString` method or property directly.
/// String-literal and computed keys are outside this subset.
pub(crate) fn class_declares_to_string(class: &Class<'_>) -> bool {
    class.body.body.iter().any(|element| match element {
        ClassElement::MethodDefinition(method)
            if !matches!(
                method.kind,
                MethodDefinitionKind::Constructor
                    | MethodDefinitionKind::Get
                    | MethodDefinitionKind::Set
            ) =>
        {
            property_key_name(&method.key) == Some("toString")
        }
        ClassElement::PropertyDefinition(property) => {
            property_key_name(&property.key) == Some("toString")
        }
        _ => false,
    })
}
