use super::{
    ArrowFunctionBody, ArrowFunctionExpression, BTreeMap, BinaryExpression, BinaryOperator, Class,
    ClassElement, Declaration, Expression, Function, GetSpan, MethodDefinition,
    MethodDefinitionKind, ReturnStatement, ScopeFlags, Span, Statement, SwitchStatement,
    UnaryOperator, VariableDeclarator, Visit, binding_identifier_name, identifier_name,
    property_key_name, unparenthesized, walk_binary_expression, walk_declaration,
    walk_return_statement, walk_switch_statement, walk_variable_declarator,
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
pub(crate) struct FnFacts {
    pub(crate) r#async: bool,
    pub(crate) generator: bool,
    pub(crate) return_kinds: Vec<LiteralKind>,
    /// Span of a parameter that only selects the function's behavior.
    pub(crate) selector_span: Option<Span>,
    pub(crate) span: Span,
}

impl FnFacts {
    /// Whether calls of this function provably produce no usable value.
    pub(crate) fn is_void(&self) -> bool {
        !self.r#async && !self.generator && self.return_kinds.is_empty()
    }
}

/// File-local function facts used by the Tier-C call checks: declaration and
/// `const`-bound function/arrow names with their flags, spans, and the
/// literal kinds of their valued `return`s.
#[derive(Default)]
pub(crate) struct FunctionCensus {
    pub(crate) functions: BTreeMap<String, FnFacts>,
}

/// Parameter names treated as behavior selectors by `S2301` (weak subset).
const SELECTOR_PARAM_NAMES: [&str; 5] = ["type", "kind", "action", "mode", "command"];

/// Scoped scan of one function body: collects valued-return literal kinds
/// and branch logic driven by named parameters, without descending into
/// nested function-like nodes.
#[derive(Default)]
pub(crate) struct BodyScan {
    pub(crate) params: Vec<(String, Span)>,
    pub(crate) return_kinds: Vec<LiteralKind>,
    pub(crate) selector_comparisons: u32,
    pub(crate) switches_on_param: bool,
}

impl<'a> Visit<'a> for BodyScan {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if let Some(argument) = &it.argument
            && let Some(kind) = literal_kind(argument)
        {
            self.return_kinds.push(kind);
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
    scan
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
    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it
            && let Some(id) = &function.id
        {
            let scan = function
                .body
                .as_ref()
                .map(|body| scan_body(&body.statements, parameter_spans(&function.params)))
                .unwrap_or_default();
            let facts = FnFacts {
                r#async: function.r#async,
                generator: function.generator,
                selector_span: scan.selector_span(),
                return_kinds: scan.return_kinds,
                span: id.span(),
            };
            self.functions.insert(id.name.to_string(), facts);
        }
        walk_declaration(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(name) = binding_identifier_name(&it.id)
            && let Some(init) = &it.init
        {
            match unparenthesized(init) {
                Expression::ArrowFunctionExpression(arrow) => {
                    let scan = if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                        scan_body(&body.statements, parameter_spans(&arrow.params))
                    } else {
                        let mut scan = BodyScan::default();
                        if let Some(kind) = arrow.body.as_expression().and_then(literal_kind) {
                            scan.return_kinds.push(kind);
                        }
                        scan
                    };
                    let facts = FnFacts {
                        r#async: arrow.r#async,
                        // Arrow functions cannot be generators.
                        generator: false,
                        selector_span: scan.selector_span(),
                        return_kinds: scan.return_kinds,
                        span: arrow.span,
                    };
                    self.functions.insert(name.to_string(), facts);
                }
                Expression::FunctionExpression(function) => {
                    let scan = function
                        .body
                        .as_ref()
                        .map(|body| scan_body(&body.statements, parameter_spans(&function.params)))
                        .unwrap_or_default();
                    let facts = FnFacts {
                        r#async: function.r#async,
                        generator: function.generator,
                        selector_span: scan.selector_span(),
                        return_kinds: scan.return_kinds,
                        span: function.span,
                    };
                    self.functions.insert(name.to_string(), facts);
                }
                _ => {}
            }
        }
        walk_variable_declarator(self, it);
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
