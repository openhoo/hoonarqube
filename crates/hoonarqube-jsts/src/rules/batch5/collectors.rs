use super::s4036_s4721_shell_exec::ProcessBindingResolver;
use super::s7059_s7059_await_expression::S7059State;
use crate::rules::shared::argument_expression;
use crate::rules::shared::duplicated_key_name;
use crate::support::{IssueSink, RuleScope, member_object, unparenthesized};
use oxc_ast::AstKind;
use oxc_ast::ast::ArrowFunctionExpression;
use oxc_ast::ast::AssignmentExpression;
use oxc_ast::ast::AwaitExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_ast::ast::BindingPattern;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Class;
use oxc_ast::ast::Declaration;
use oxc_ast::ast::Expression;
use oxc_ast::ast::FormalParameter;
use oxc_ast::ast::Function;
use oxc_ast::ast::FunctionBody;
use oxc_ast::ast::IfStatement;
use oxc_ast::ast::ImportDeclaration;
use oxc_ast::ast::ImportOrExportKind;
use oxc_ast::ast::LogicalExpression;
use oxc_ast::ast::MemberExpression;
use oxc_ast::ast::MethodDefinition;
use oxc_ast::ast::MethodDefinitionKind;
use oxc_ast::ast::ModuleExportName;
use oxc_ast::ast::NewExpression;
use oxc_ast::ast::ObjectExpression;
use oxc_ast::ast::ObjectProperty;
use oxc_ast::ast::ObjectPropertyKind;
use oxc_ast::ast::PropertyDefinition;
use oxc_ast::ast::ReturnStatement;
use oxc_ast::ast::SimpleAssignmentTarget;
use oxc_ast::ast::Statement;
use oxc_ast::ast::StringLiteral;
use oxc_ast::ast::TSAnyKeyword;
use oxc_ast::ast::TSEnumDeclaration;
use oxc_ast::ast::TSInterfaceDeclaration;
use oxc_ast::ast::TSIntersectionType;
use oxc_ast::ast::TSModuleReference;
use oxc_ast::ast::TSNamespaceDeclaration;
use oxc_ast::ast::TSNonNullExpression;
use oxc_ast::ast::TSPropertySignature;
use oxc_ast::ast::TSType;
use oxc_ast::ast::TSTypeAliasDeclaration;
use oxc_ast::ast::TSTypeAssertion;
use oxc_ast::ast::TSTypeLiteral;
use oxc_ast::ast::TSTypeParameter;
use oxc_ast::ast::TSUnionType;
use oxc_ast::ast::TemplateLiteral;
use oxc_ast::ast::TryStatement;
use oxc_ast::ast::UnaryExpression;
use oxc_ast::ast::UpdateExpression;
use oxc_ast::ast::VariableDeclarator;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_await_expression,
    walk_call_expression, walk_class, walk_formal_parameter, walk_function, walk_if_statement,
    walk_import_declaration, walk_logical_expression, walk_member_expression,
    walk_method_definition, walk_new_expression, walk_object_property, walk_property_definition,
    walk_return_statement, walk_statement, walk_string_literal, walk_template_literal,
    walk_try_statement, walk_ts_any_keyword, walk_ts_enum_declaration,
    walk_ts_interface_declaration, walk_ts_intersection_type, walk_ts_namespace_declaration,
    walk_ts_non_null_expression, walk_ts_property_signature, walk_ts_type_alias_declaration,
    walk_ts_type_assertion, walk_ts_type_literal, walk_ts_type_parameter, walk_ts_union_type,
    walk_unary_expression, walk_update_expression, walk_variable_declarator,
};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::{GetSpan, Span};
use oxc_syntax::reference::ReferenceId;
use oxc_syntax::scope::ScopeFlags;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SecurityModule {
    BodyParser,
    CookieSession,
    Cookies,
    Csurf,
    ErrorHandler,
    Express,
    ExpressSession,
    Crypto,
    Fs,
    Handlebars,
    Helmet,
    Https,
    Http,
    HttpProxyMiddleware,
    LibXmlJs,
    Multer,
    Passport,
    Signale,
    Tls,
    Ws,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecurityFactory {
    CookieSession,
    CsurfProtection,
    ErrorMiddleware,
    ExpressApp,
    ExpressRouter,
    ExpressSessionMiddleware,
    HelmetCsp,
    HelmetHsts,
    HelmetMiddleware,
    HelmetNoSniff,
    HelmetReferrerPolicy,
    MulterDiskStorage,
    ProxyMiddleware,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecurityInstance {
    Cookies,
    Signale,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SecurityOrigin {
    Module(SecurityModule, Option<String>),
    Factory(SecurityFactory),
    Instance(SecurityInstance),
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SecurityValue {
    Boolean(bool),
    Number(f64),
    String(String),
    EmptyArray,
    NonEmptyArray,
    EmptyFunction,
    UndefinedReturningFunction(Option<ReferenceId>),
    NonEmptyFunction,
    Unknown,
}

#[derive(Clone, Debug)]
enum SecurityExpression {
    Alias(SymbolId),
    Object(HashMap<String, SecurityExpression>),
    Call {
        callee: SecuritySeed,
        first_argument: Option<Box<SecurityExpression>>,
    },
    Unknown,
}

#[derive(Clone, Debug)]
enum SecuritySeed {
    Module(SecurityModule),
    Alias(SymbolId),
    Member(Box<SecuritySeed>, String),
    Call(Box<SecuritySeed>),
    Constructor(Box<SecuritySeed>),
    Unknown,
}

#[derive(Clone, Debug)]
struct SecurityBinding {
    seed: SecuritySeed,
    seed_at: u32,
    declaration_end: u32,
    writes: Vec<u32>,
}

/// File-local provenance for the supported security APIs.
///
/// OXC semantic symbols provide declaration identity and rebinding writes.
/// The resolver only projects module/API provenance onto those symbols; it
/// never treats an arbitrary spelling as a library call.
#[derive(Default)]
pub(crate) struct SecurityBindingResolver {
    reference_symbols: HashMap<ReferenceId, SymbolId>,
    bindings: HashMap<SymbolId, SecurityBinding>,
    object_values: HashMap<SymbolId, HashMap<String, (SecurityValue, Span)>>,
    object_writes: HashMap<SymbolId, HashMap<String, Vec<u32>>>,
    object_unknown_writes: HashMap<SymbolId, Vec<u32>>,
    constant_values: HashMap<SymbolId, SecurityValue>,
    expression_values: HashMap<SymbolId, SecurityExpression>,
}
struct ObjectPropertyWriteCollector<'a> {
    reference_symbols: &'a HashMap<ReferenceId, SymbolId>,
    writes: HashMap<SymbolId, HashMap<String, Vec<u32>>>,
    unknown_writes: HashMap<SymbolId, Vec<u32>>,
}

impl ObjectPropertyWriteCollector<'_> {
    fn record_member_write(&mut self, member: &MemberExpression<'_>, at: u32) {
        let Expression::Identifier(identifier) = unparenthesized(member_object(member)) else {
            return;
        };
        let Some(reference) = identifier.reference_id.get() else {
            return;
        };
        let Some(symbol) = self.reference_symbols.get(&reference).copied() else {
            return;
        };
        let property = match member {
            MemberExpression::StaticMemberExpression(member) => Some(member.property.name.as_str()),
            MemberExpression::ComputedMemberExpression(member) => {
                match unparenthesized(&member.expression) {
                    Expression::StringLiteral(property) => Some(property.value.as_str()),
                    Expression::TemplateLiteral(template)
                        if template.expressions.is_empty() && template.quasis.len() == 1 =>
                    {
                        template
                            .quasis
                            .first()
                            .and_then(|quasi| quasi.value.cooked.as_ref())
                            .map(oxc_ast::ast::Str::as_str)
                    }
                    _ => None,
                }
            }
            MemberExpression::PrivateFieldExpression(_) => return,
        };
        if let Some(property) = property {
            self.writes
                .entry(symbol)
                .or_default()
                .entry(property.to_owned())
                .or_default()
                .push(at);
        } else {
            self.unknown_writes.entry(symbol).or_default().push(at);
        }
    }
}

impl<'ast> Visit<'ast> for ObjectPropertyWriteCollector<'_> {
    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'ast>) {
        if let Some(simple) = assignment.left.as_simple_assignment_target()
            && let Some(member) = simple.as_member_expression()
        {
            self.record_member_write(member, assignment.span().start);
        }
        walk_assignment_expression(self, assignment);
    }

    fn visit_unary_expression(&mut self, unary: &UnaryExpression<'ast>) {
        if unary.operator == oxc_syntax::operator::UnaryOperator::Delete
            && let Some(member) = unparenthesized(&unary.argument).as_member_expression()
        {
            self.record_member_write(member, unary.span.start);
        }
        walk_unary_expression(self, unary);
    }

    fn visit_update_expression(&mut self, update: &UpdateExpression<'ast>) {
        if let Some(member) = update.argument.as_member_expression() {
            self.record_member_write(member, update.span.start);
        }
        walk_update_expression(self, update);
    }
}

impl SecurityBindingResolver {
    fn collect_expression_values(
        resolver: &SecurityBindingResolver,
        semantic: &Semantic<'_>,
    ) -> HashMap<SymbolId, SecurityExpression> {
        let mut values = HashMap::new();
        for symbol in semantic.scoping().symbol_ids() {
            let AstKind::VariableDeclarator(declarator) =
                semantic.symbol_declaration(symbol).kind()
            else {
                continue;
            };
            let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
                continue;
            };
            if identifier.symbol_id.get() != Some(symbol) {
                continue;
            }
            let Some(init) = declarator.init.as_ref() else {
                continue;
            };
            values.insert(symbol, resolver.expression_shape(init));
        }
        values
    }

    fn object_snapshot(
        object: &oxc_ast::ast::ObjectExpression<'_>,
    ) -> Option<HashMap<String, (SecurityValue, Span)>> {
        object
            .properties
            .iter()
            .map(|property| {
                let ObjectPropertyKind::ObjectProperty(property) = property else {
                    return None;
                };
                let key = duplicated_key_name(&property.key)?.to_owned();
                Some((
                    key,
                    (
                        static_value(&property.value),
                        unparenthesized(&property.value).span(),
                    ),
                ))
            })
            .collect()
    }

    pub(crate) fn new(
        program: &oxc_ast::ast::Program<'_>,
        semantic: Option<&Semantic<'_>>,
    ) -> Self {
        let Some(semantic) = semantic else {
            return Self::default();
        };
        let mut resolver = Self::default();
        let ts_imports = collect_ts_imports(program);

        // Populate reference ownership before resolving `require` roots so a
        // locally shadowed `require` cannot be mistaken for the Node loader.
        for symbol in semantic.scoping().symbol_ids() {
            let writes = semantic
                .scoping()
                .get_resolved_reference_ids(symbol)
                .iter()
                .filter_map(|&reference_id| {
                    let reference = semantic.scoping().get_reference(reference_id);
                    resolver.reference_symbols.insert(reference_id, symbol);
                    reference
                        .is_write()
                        .then(|| semantic.reference_span(reference).start)
                })
                .collect();
            resolver.bindings.insert(
                symbol,
                SecurityBinding {
                    seed: SecuritySeed::Unknown,
                    seed_at: 0,
                    declaration_end: semantic.scoping().symbol_span(symbol).end,
                    writes,
                },
            );
        }

        for symbol in semantic.scoping().symbol_ids() {
            let declaration = semantic.symbol_declaration(symbol);
            let declaration_kind = declaration.kind();
            let seed_at = match declaration_kind {
                AstKind::VariableDeclarator(declarator) => declarator.init.as_ref().map_or_else(
                    || semantic.scoping().symbol_span(symbol).start,
                    |init| init.span().start,
                ),
                _ => semantic.scoping().symbol_span(symbol).start,
            };
            let seed = ts_imports
                .get(&symbol)
                .cloned()
                .or_else(|| match declaration_kind {
                    AstKind::ImportSpecifier(_)
                    | AstKind::ImportDefaultSpecifier(_)
                    | AstKind::ImportNamespaceSpecifier(_) => {
                        import_seed(semantic, declaration_kind)
                    }
                    AstKind::VariableDeclarator(declarator) => {
                        let init = declarator.init.as_ref()?;
                        let source = resolver.seed_for_expression(init);
                        seed_for_pattern(&declarator.id, symbol, source)
                    }
                    _ => None,
                })
                .unwrap_or(SecuritySeed::Unknown);
            if let Some(binding) = resolver.bindings.get_mut(&symbol) {
                binding.seed = seed;
                binding.seed_at = seed_at;
            }

            if let AstKind::VariableDeclarator(declarator) = declaration_kind
                && let BindingPattern::BindingIdentifier(identifier) = &declarator.id
                && identifier.symbol_id.get() == Some(symbol)
                && let Some(Expression::ObjectExpression(object)) =
                    declarator.init.as_ref().map(unparenthesized)
                && let Some(values) = Self::object_snapshot(object)
            {
                resolver.object_values.insert(symbol, values);
            }
            if let AstKind::VariableDeclarator(declarator) = declaration_kind
                && let BindingPattern::BindingIdentifier(identifier) = &declarator.id
                && identifier.symbol_id.get() == Some(symbol)
                && let Some(init) = declarator.init.as_ref()
            {
                resolver.constant_values.insert(symbol, static_value(init));
            }
        }
        let expression_values = Self::collect_expression_values(&resolver, semantic);
        resolver.expression_values = expression_values;

        let mut property_writes = ObjectPropertyWriteCollector {
            reference_symbols: &resolver.reference_symbols,
            writes: HashMap::new(),
            unknown_writes: HashMap::new(),
        };
        property_writes.visit_program(program);
        resolver.object_writes = property_writes.writes;
        resolver.object_unknown_writes = property_writes.unknown_writes;
        resolver
    }

    pub(crate) fn origin(&self, expression: &Expression<'_>, at: u32) -> SecurityOrigin {
        let seed = self.seed_for_expression(expression);
        let mut visited = HashSet::new();
        self.resolve_seed(&seed, at, &mut visited)
    }
    /// Resolve the value produced by a complete call expression.
    ///
    /// `origin(call.callee, at)` describes the imported function/member, while
    /// this helper additionally applies the factory mapping for calls such as
    /// `helmet(...)`, `express()`, and `createProxyMiddleware(...)`.
    pub(crate) fn call_origin(&self, call: &CallExpression<'_>, at: u32) -> SecurityOrigin {
        let seed = if let Some(module) = self.require_module(call) {
            SecuritySeed::Module(module)
        } else {
            SecuritySeed::Call(Box::new(self.seed_for_expression(&call.callee)))
        };
        let mut visited = HashSet::new();
        self.resolve_seed(&seed, at, &mut visited)
    }

    pub(crate) fn is_call_module(
        &self,
        call: &CallExpression<'_>,
        module: SecurityModule,
        at: u32,
    ) -> bool {
        matches!(
            self.call_origin(call, at),
            SecurityOrigin::Module(found, _) if found == module
        )
    }

    pub(crate) fn is_call_factory(
        &self,
        call: &CallExpression<'_>,
        factory: SecurityFactory,
        at: u32,
    ) -> bool {
        matches!(
            self.call_origin(call, at),
            SecurityOrigin::Factory(found) if found == factory
        )
    }

    pub(crate) fn symbol(&self, expression: &Expression<'_>) -> Option<SymbolId> {
        match unparenthesized(expression) {
            Expression::Identifier(identifier) => identifier
                .reference_id
                .get()
                .and_then(|reference| self.reference_symbols.get(&reference).copied()),
            _ => None,
        }
    }

    pub(crate) fn object_property(
        &self,
        expression: &Expression<'_>,
        key: &str,
        at: u32,
    ) -> Option<SecurityValue> {
        if let Expression::ObjectExpression(object) = unparenthesized(expression) {
            return object_property(object, key).map(static_value);
        }
        let symbol = self.symbol(expression)?;
        if !self.symbol_is_current(symbol, at) {
            return None;
        }
        if self.object_property_was_written(symbol, key, at) {
            return Some(SecurityValue::Unknown);
        }
        self.object_values
            .get(&symbol)
            .and_then(|values| values.get(key).map(|(value, _)| value.clone()))
    }

    pub(crate) fn object_property_source_span(
        &self,
        expression: &Expression<'_>,
        key: &str,
        at: u32,
    ) -> Option<Span> {
        if let Expression::ObjectExpression(object) = unparenthesized(expression) {
            return object_property(object, key).map(|value| unparenthesized(value).span());
        }
        let symbol = self.symbol(expression)?;
        if !self.symbol_is_current(symbol, at) || self.object_property_was_written(symbol, key, at)
        {
            return None;
        }
        self.object_values
            .get(&symbol)
            .and_then(|values| values.get(key).map(|(_, span)| *span))
    }

    pub(crate) fn object_property_is_inert_function(
        &self,
        expression: &Expression<'_>,
        key: &str,
        at: u32,
    ) -> bool {
        match self.object_property(expression, key, at) {
            Some(
                SecurityValue::EmptyFunction | SecurityValue::UndefinedReturningFunction(None),
            ) => true,
            Some(SecurityValue::UndefinedReturningFunction(Some(reference))) => {
                !self.reference_symbols.contains_key(&reference)
            }
            _ => false,
        }
    }
    /// Resolve an object property through local bindings and inspect a nested
    /// factory call's first options object.
    pub(crate) fn object_property_factory_missing(
        &self,
        expression: &Expression<'_>,
        object_key: &str,
        factory: SecurityFactory,
        required_key: &str,
        at: u32,
    ) -> bool {
        let shape = self.expression_shape(expression);
        let mut visited = HashSet::new();
        self.shape_object_property_factory_missing(
            &shape,
            object_key,
            factory,
            required_key,
            at,
            &mut visited,
        )
    }

    fn expression_shape(&self, expression: &Expression<'_>) -> SecurityExpression {
        match unparenthesized(expression) {
            Expression::Identifier(identifier) => identifier
                .reference_id
                .get()
                .and_then(|reference| self.reference_symbols.get(&reference).copied())
                .map_or(SecurityExpression::Unknown, SecurityExpression::Alias),
            Expression::ObjectExpression(object) => {
                let mut properties = HashMap::new();
                for property in &object.properties {
                    let ObjectPropertyKind::ObjectProperty(property) = property else {
                        return SecurityExpression::Unknown;
                    };
                    let Some(key) = duplicated_key_name(&property.key) else {
                        return SecurityExpression::Unknown;
                    };
                    properties
                        .entry(key.to_owned())
                        .or_insert_with(|| self.expression_shape(&property.value));
                }
                SecurityExpression::Object(properties)
            }
            Expression::CallExpression(call) => SecurityExpression::Call {
                callee: self.seed_for_expression(&call.callee),
                first_argument: call
                    .arguments
                    .first()
                    .and_then(argument_expression)
                    .map(|argument| Box::new(self.expression_shape(argument))),
            },
            _ => SecurityExpression::Unknown,
        }
    }

    fn shape_object_property_factory_missing(
        &self,
        shape: &SecurityExpression,
        object_key: &str,
        factory: SecurityFactory,
        required_key: &str,
        at: u32,
        visited: &mut HashSet<SymbolId>,
    ) -> bool {
        match shape {
            SecurityExpression::Object(properties) => {
                properties.get(object_key).is_some_and(|value| {
                    self.shape_factory_missing(value, factory, required_key, at, visited)
                })
            }
            SecurityExpression::Alias(symbol) => {
                if !self.symbol_is_current(*symbol, at)
                    || !visited.insert(*symbol)
                    || self.object_property_was_written(*symbol, object_key, at)
                {
                    return false;
                }
                self.expression_values.get(symbol).is_some_and(|value| {
                    self.shape_object_property_factory_missing(
                        value,
                        object_key,
                        factory,
                        required_key,
                        at,
                        visited,
                    )
                })
            }
            SecurityExpression::Call { .. } | SecurityExpression::Unknown => false,
        }
    }

    fn shape_factory_missing(
        &self,
        shape: &SecurityExpression,
        factory: SecurityFactory,
        required_key: &str,
        at: u32,
        visited: &mut HashSet<SymbolId>,
    ) -> bool {
        match shape {
            SecurityExpression::Call {
                callee,
                first_argument,
            } => {
                let mut seed_visited = HashSet::new();
                if !matches!(
                    self.resolve_seed(
                        &SecuritySeed::Call(Box::new(callee.clone())),
                        at,
                        &mut seed_visited,
                    ),
                    SecurityOrigin::Factory(found) if found == factory
                ) {
                    return false;
                }
                let Some(first_argument) = first_argument.as_deref() else {
                    return false;
                };
                self.shape_has_property(first_argument, required_key, at, visited) == Some(false)
            }
            SecurityExpression::Alias(symbol) => {
                if !self.symbol_is_current(*symbol, at) || !visited.insert(*symbol) {
                    return false;
                }
                self.expression_values.get(symbol).is_some_and(|value| {
                    self.shape_factory_missing(value, factory, required_key, at, visited)
                })
            }
            SecurityExpression::Object(_) | SecurityExpression::Unknown => false,
        }
    }

    fn shape_has_property(
        &self,
        shape: &SecurityExpression,
        key: &str,
        at: u32,
        visited: &mut HashSet<SymbolId>,
    ) -> Option<bool> {
        match shape {
            SecurityExpression::Object(properties) => Some(properties.contains_key(key)),
            SecurityExpression::Alias(symbol) => {
                if !self.symbol_is_current(*symbol, at) || !visited.insert(*symbol) {
                    return None;
                }
                if self.object_property_was_written(*symbol, key, at) {
                    return Some(true);
                }
                self.expression_values
                    .get(symbol)
                    .and_then(|value| self.shape_has_property(value, key, at, visited))
            }
            SecurityExpression::Call { .. } | SecurityExpression::Unknown => None,
        }
    }

    fn object_property_was_written(&self, symbol: SymbolId, key: &str, at: u32) -> bool {
        let Some(declaration_end) = self
            .bindings
            .get(&symbol)
            .map(|binding| binding.declaration_end)
        else {
            return false;
        };
        self.object_writes
            .get(&symbol)
            .and_then(|writes| writes.get(key))
            .is_some_and(|writes| {
                writes
                    .iter()
                    .any(|&write| write > declaration_end && write <= at)
            })
            || self
                .object_unknown_writes
                .get(&symbol)
                .is_some_and(|writes| {
                    writes
                        .iter()
                        .any(|&write| write > declaration_end && write <= at)
                })
    }

    pub(crate) fn static_value(
        &self,
        expression: &Expression<'_>,
        at: u32,
    ) -> Option<SecurityValue> {
        if let Expression::Identifier(_) = unparenthesized(expression) {
            let symbol = self.symbol(expression)?;
            if !self.symbol_is_current(symbol, at) {
                return None;
            }
            return self.constant_values.get(&symbol).cloned();
        }
        Some(static_value(expression))
    }

    pub(crate) fn is_module(
        &self,
        expression: &Expression<'_>,
        module: SecurityModule,
        at: u32,
    ) -> bool {
        matches!(
            self.origin(expression, at),
            SecurityOrigin::Module(found, _) if found == module
        )
    }

    pub(crate) fn is_module_member(
        &self,
        expression: &Expression<'_>,
        module: SecurityModule,
        member: &str,
        at: u32,
    ) -> bool {
        matches!(
            self.origin(expression, at),
            SecurityOrigin::Module(found, Some(selected))
                if found == module && selected == member
        )
    }

    pub(crate) fn is_factory(
        &self,
        expression: &Expression<'_>,
        factory: SecurityFactory,
        at: u32,
    ) -> bool {
        self.origin(expression, at) == SecurityOrigin::Factory(factory)
    }

    pub(crate) fn is_instance(
        &self,
        expression: &Expression<'_>,
        instance: SecurityInstance,
        at: u32,
    ) -> bool {
        self.origin(expression, at) == SecurityOrigin::Instance(instance)
    }

    pub(crate) fn symbol_is_current(&self, symbol: SymbolId, at: u32) -> bool {
        let Some(binding) = self.bindings.get(&symbol) else {
            return false;
        };
        !binding
            .writes
            .iter()
            .any(|&write| write > binding.declaration_end && write <= at)
    }

    fn seed_for_expression(&self, expression: &Expression<'_>) -> SecuritySeed {
        let expression = unparenthesized(expression);
        match expression {
            Expression::Identifier(identifier) => identifier
                .reference_id
                .get()
                .and_then(|reference| self.reference_symbols.get(&reference).copied())
                .map_or(SecuritySeed::Unknown, SecuritySeed::Alias),
            Expression::CallExpression(call) => {
                if let Some(module) = self.require_module(call) {
                    SecuritySeed::Module(module)
                } else {
                    SecuritySeed::Call(Box::new(self.seed_for_expression(&call.callee)))
                }
            }
            Expression::NewExpression(new) => {
                SecuritySeed::Constructor(Box::new(self.seed_for_expression(&new.callee)))
            }
            Expression::StaticMemberExpression(member) => SecuritySeed::Member(
                Box::new(self.seed_for_expression(&member.object)),
                member.property.name.to_string(),
            ),
            Expression::ComputedMemberExpression(member) => {
                let Expression::StringLiteral(property) = unparenthesized(&member.expression)
                else {
                    return SecuritySeed::Unknown;
                };
                SecuritySeed::Member(
                    Box::new(self.seed_for_expression(&member.object)),
                    property.value.to_string(),
                )
            }
            _ => SecuritySeed::Unknown,
        }
    }

    fn require_module(&self, call: &CallExpression<'_>) -> Option<SecurityModule> {
        if call.arguments.len() != 1 {
            return None;
        }
        let Expression::Identifier(identifier) = unparenthesized(&call.callee) else {
            return None;
        };
        if identifier.name != "require"
            || identifier
                .reference_id
                .get()
                .is_some_and(|reference| self.reference_symbols.contains_key(&reference))
        {
            return None;
        }
        let Expression::StringLiteral(module) =
            unparenthesized(call.arguments.first()?.as_expression()?)
        else {
            return None;
        };
        module_from_path(module.value.as_str())
    }

    fn resolve_seed(
        &self,
        seed: &SecuritySeed,
        at: u32,
        visited: &mut HashSet<SymbolId>,
    ) -> SecurityOrigin {
        match seed {
            SecuritySeed::Module(module) => SecurityOrigin::Module(*module, None),
            SecuritySeed::Alias(symbol) => {
                if !visited.insert(*symbol) || !self.symbol_is_current(*symbol, at) {
                    return SecurityOrigin::Unknown;
                }
                let Some(binding) = self.bindings.get(symbol) else {
                    return SecurityOrigin::Unknown;
                };
                let seed_at = binding.seed_at;
                self.resolve_seed(&binding.seed, seed_at, visited)
            }
            SecuritySeed::Member(base, member) => match self.resolve_seed(base, at, visited) {
                SecurityOrigin::Module(module, _) => {
                    SecurityOrigin::Module(module, Some(member.clone()))
                }
                _ => SecurityOrigin::Unknown,
            },
            SecuritySeed::Call(callee) => {
                let SecurityOrigin::Module(module, member) = self.resolve_seed(callee, at, visited)
                else {
                    return SecurityOrigin::Unknown;
                };
                match factory_for(module, member.as_deref()) {
                    Some(factory) => SecurityOrigin::Factory(factory),
                    None => SecurityOrigin::Unknown,
                }
            }
            SecuritySeed::Constructor(callee) => {
                let SecurityOrigin::Module(module, _) = self.resolve_seed(callee, at, visited)
                else {
                    return SecurityOrigin::Unknown;
                };
                match module {
                    SecurityModule::Cookies => SecurityOrigin::Instance(SecurityInstance::Cookies),
                    SecurityModule::Signale => SecurityOrigin::Instance(SecurityInstance::Signale),
                    _ => SecurityOrigin::Unknown,
                }
            }
            SecuritySeed::Unknown => SecurityOrigin::Unknown,
        }
    }
}

fn import_seed<'a>(semantic: &Semantic<'a>, declaration: AstKind<'a>) -> Option<SecuritySeed> {
    let AstKind::ImportDeclaration(import) = semantic.nodes().parent_kind(declaration.node_id())
    else {
        return None;
    };
    if import.import_kind.is_type() {
        return None;
    }
    let module = module_from_path(import.source.value.as_str())?;
    match declaration {
        AstKind::ImportSpecifier(specifier) if !specifier.import_kind.is_type() => {
            Some(SecuritySeed::Member(
                Box::new(SecuritySeed::Module(module)),
                module_export_name(&specifier.imported).to_owned(),
            ))
        }
        AstKind::ImportDefaultSpecifier(_) | AstKind::ImportNamespaceSpecifier(_) => {
            Some(SecuritySeed::Module(module))
        }
        _ => None,
    }
}

fn collect_ts_imports(program: &oxc_ast::ast::Program<'_>) -> HashMap<SymbolId, SecuritySeed> {
    let mut imports = HashMap::new();
    for statement in &program.body {
        let Some(Declaration::TSImportEqualsDeclaration(declaration)) = statement.as_declaration()
        else {
            continue;
        };
        if declaration.import_kind != ImportOrExportKind::Value {
            continue;
        }
        let TSModuleReference::ExternalModuleReference(reference) = &declaration.module_reference
        else {
            continue;
        };
        let Some(module) = module_from_path(reference.expression.value.as_str()) else {
            continue;
        };
        if let Some(symbol) = declaration.id.symbol_id.get() {
            imports.insert(symbol, SecuritySeed::Module(module));
        }
    }
    imports
}

fn seed_for_pattern(
    pattern: &BindingPattern<'_>,
    symbol: SymbolId,
    source: SecuritySeed,
) -> Option<SecuritySeed> {
    match pattern {
        BindingPattern::BindingIdentifier(identifier) => {
            (identifier.symbol_id.get() == Some(symbol)).then_some(source)
        }
        BindingPattern::AssignmentPattern(assignment) => {
            seed_for_pattern(&assignment.left, symbol, source)
        }
        BindingPattern::ObjectPattern(object) => object.properties.iter().find_map(|property| {
            let key = duplicated_key_name(&property.key)?;
            seed_for_pattern(
                &property.value,
                symbol,
                SecuritySeed::Member(Box::new(source.clone()), key.to_owned()),
            )
        }),
        BindingPattern::ArrayPattern(_) => None,
    }
}

fn static_value(expression: &Expression<'_>) -> SecurityValue {
    match unparenthesized(expression) {
        Expression::BooleanLiteral(literal) => SecurityValue::Boolean(literal.value),
        Expression::NumericLiteral(literal) => SecurityValue::Number(literal.value),
        Expression::StringLiteral(literal) => SecurityValue::String(literal.value.to_string()),
        Expression::ArrayExpression(array) if array.elements.is_empty() => {
            SecurityValue::EmptyArray
        }
        Expression::ArrayExpression(_) => SecurityValue::NonEmptyArray,
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => {
            function_static_value(expression)
        }
        _ => SecurityValue::Unknown,
    }
}

fn function_static_value(expression: &Expression<'_>) -> SecurityValue {
    match unparenthesized(expression) {
        Expression::FunctionExpression(function) if !function.r#async && !function.generator => {
            function
                .body
                .as_ref()
                .map_or(SecurityValue::NonEmptyFunction, |body| {
                    function_body_value(body)
                })
        }
        Expression::ArrowFunctionExpression(arrow) if !arrow.r#async => {
            if let Some(body) = arrow.body.as_function_body() {
                function_body_value(body)
            } else if let Some(value) = arrow.body.as_expression() {
                undefined_function_value(value)
            } else {
                SecurityValue::NonEmptyFunction
            }
        }
        _ => SecurityValue::NonEmptyFunction,
    }
}

fn function_body_value(body: &FunctionBody<'_>) -> SecurityValue {
    match body.statements.as_slice() {
        [] => SecurityValue::EmptyFunction,
        [Statement::ReturnStatement(statement)] => statement
            .argument
            .as_ref()
            .map_or(SecurityValue::EmptyFunction, undefined_function_value),
        _ => SecurityValue::NonEmptyFunction,
    }
}

fn undefined_function_value(expression: &Expression<'_>) -> SecurityValue {
    match unparenthesized(expression) {
        Expression::Identifier(identifier) if identifier.name == "undefined" => identifier
            .reference_id
            .get()
            .map_or(SecurityValue::NonEmptyFunction, |reference| {
                SecurityValue::UndefinedReturningFunction(Some(reference))
            }),
        Expression::UnaryExpression(unary)
            if unary.operator == oxc_syntax::operator::UnaryOperator::Void
                && matches!(
                    unparenthesized(&unary.argument),
                    Expression::NumericLiteral(_)
                ) =>
        {
            SecurityValue::UndefinedReturningFunction(None)
        }
        _ => SecurityValue::NonEmptyFunction,
    }
}

fn module_export_name<'a>(name: &'a ModuleExportName<'a>) -> &'a str {
    match name {
        ModuleExportName::IdentifierName(identifier) => identifier.name.as_str(),
        ModuleExportName::IdentifierReference(identifier) => identifier.name.as_str(),
        ModuleExportName::StringLiteral(literal) => literal.value.as_str(),
    }
}
fn module_from_path(path: &str) -> Option<SecurityModule> {
    match path {
        "body-parser" => Some(SecurityModule::BodyParser),
        "crypto" | "node:crypto" => Some(SecurityModule::Crypto),
        "cookie-session" => Some(SecurityModule::CookieSession),
        "cookies" => Some(SecurityModule::Cookies),
        "csurf" => Some(SecurityModule::Csurf),
        "errorhandler" => Some(SecurityModule::ErrorHandler),
        "express" => Some(SecurityModule::Express),
        "express-session" => Some(SecurityModule::ExpressSession),
        "fs" | "node:fs" | "fs/promises" | "node:fs/promises" => Some(SecurityModule::Fs),
        "handlebars" => Some(SecurityModule::Handlebars),
        "helmet" => Some(SecurityModule::Helmet),
        "http" | "node:http" => Some(SecurityModule::Http),
        "https" | "node:https" => Some(SecurityModule::Https),
        "http-proxy-middleware" => Some(SecurityModule::HttpProxyMiddleware),
        "libxmljs" => Some(SecurityModule::LibXmlJs),
        "multer" => Some(SecurityModule::Multer),
        "passport" => Some(SecurityModule::Passport),
        "signale" => Some(SecurityModule::Signale),
        "tls" | "node:tls" => Some(SecurityModule::Tls),
        "ws" => Some(SecurityModule::Ws),
        _ => None,
    }
}

fn factory_for(module: SecurityModule, member: Option<&str>) -> Option<SecurityFactory> {
    match (module, member) {
        (SecurityModule::CookieSession, _) => Some(SecurityFactory::CookieSession),
        (SecurityModule::Csurf, _) => Some(SecurityFactory::CsurfProtection),
        (SecurityModule::ErrorHandler, _) => Some(SecurityFactory::ErrorMiddleware),
        (SecurityModule::Express, None | Some("default")) => Some(SecurityFactory::ExpressApp),
        (SecurityModule::Express, Some("Router")) => Some(SecurityFactory::ExpressRouter),
        (SecurityModule::ExpressSession, _) => Some(SecurityFactory::ExpressSessionMiddleware),
        (SecurityModule::Helmet, None | Some("default")) => Some(SecurityFactory::HelmetMiddleware),
        (SecurityModule::Helmet, Some("contentSecurityPolicy")) => Some(SecurityFactory::HelmetCsp),
        (SecurityModule::Helmet, Some("hsts")) => Some(SecurityFactory::HelmetHsts),
        (SecurityModule::Helmet, Some("noSniff")) => Some(SecurityFactory::HelmetNoSniff),
        (SecurityModule::Helmet, Some("referrerPolicy")) => {
            Some(SecurityFactory::HelmetReferrerPolicy)
        }
        (SecurityModule::HttpProxyMiddleware, Some("createProxyMiddleware")) => {
            Some(SecurityFactory::ProxyMiddleware)
        }
        (SecurityModule::Multer, Some("diskStorage")) => Some(SecurityFactory::MulterDiskStorage),
        _ => None,
    }
}

pub(crate) fn type_is_primitive_keyword(ts_type: &TSType<'_>) -> bool {
    matches!(
        ts_type,
        TSType::TSStringKeyword(_)
            | TSType::TSNumberKeyword(_)
            | TSType::TSBooleanKeyword(_)
            | TSType::TSBigIntKeyword(_)
            | TSType::TSSymbolKeyword(_)
            | TSType::TSUndefinedKeyword(_)
            | TSType::TSNullKeyword(_)
            | TSType::TSVoidKeyword(_)
            | TSType::TSNeverKeyword(_)
            | TSType::TSIntrinsicKeyword(_)
    )
}

pub(crate) struct TsTypeCollector<'s, 'index> {
    pub(crate) source: &'s str,
    pub(crate) sink: IssueSink<'index>,
    /// Enclosing class names, innermost last (`S6565`).
    pub(crate) class_stack: Vec<String>,
    /// Per-file state for `S7059` constructor execution tracking.
    pub(crate) s7059: S7059State,
    /// Constructor nesting depth (`S7059`).
    pub(crate) constructor_depth: u32,
    /// Depth of enclosing try statements that have a catch or finally
    /// handler (`S4326` return-await exemption).
    pub(crate) try_guard_depth: u32,
}

impl<'a> Visit<'a> for TsTypeCollector<'_, '_> {
    fn visit_ts_enum_declaration(&mut self, it: &TSEnumDeclaration<'a>) {
        self.check_enum_members(it);
        walk_ts_enum_declaration(self, it);
    }

    fn visit_ts_union_type(&mut self, it: &TSUnionType<'a>) {
        self.check_s4622_ts_union_type(it);
        walk_ts_union_type(self, it);
    }

    fn visit_ts_intersection_type(&mut self, it: &TSIntersectionType<'a>) {
        self.check_s4335_ts_intersection_type(it);
        walk_ts_intersection_type(self, it);
    }

    fn visit_ts_type_alias_declaration(&mut self, it: &TSTypeAliasDeclaration<'a>) {
        self.check_s6564_ts_type_alias_declaration(it);
        walk_ts_type_alias_declaration(self, it);
    }

    fn visit_ts_type_parameter(&mut self, it: &TSTypeParameter<'a>) {
        self.check_s6569_ts_type_parameter(it);
        self.check_s4157_ts_type_parameter(it);
        walk_ts_type_parameter(self, it);
    }

    fn visit_ts_non_null_expression(&mut self, it: &TSNonNullExpression<'a>) {
        self.check_s2966_ts_non_null_expression(it);
        walk_ts_non_null_expression(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        self.check_s3257_variable_declarator(it);
        self.check_s4327_variable_declarator(it);
        self.check_s6590_variable_declarator(it);
        walk_variable_declarator(self, it);
    }

    fn visit_ts_type_assertion(&mut self, it: &TSTypeAssertion<'a>) {
        self.check_s4137_ts_type_assertion(it);
        walk_ts_type_assertion(self, it);
    }

    fn visit_ts_namespace_declaration(&mut self, it: &TSNamespaceDeclaration<'a>) {
        self.check_s4156_ts_namespace_declaration(it);
        walk_ts_namespace_declaration(self, it);
    }

    fn visit_ts_any_keyword(&mut self, it: &TSAnyKeyword) {
        self.check_s4204_ts_any_keyword(it);
        walk_ts_any_keyword(self, it);
    }

    fn visit_ts_property_signature(&mut self, it: &TSPropertySignature<'a>) {
        self.check_s4782_ts_property_signature(it);
        walk_ts_property_signature(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        self.check_s4798_formal_parameter(it);
        walk_formal_parameter(self, it);
    }

    fn visit_ts_interface_declaration(&mut self, it: &TSInterfaceDeclaration<'a>) {
        self.check_s4323_ts_interface_declaration(it);
        walk_ts_interface_declaration(self, it);
    }

    fn visit_ts_type_literal(&mut self, it: &TSTypeLiteral<'a>) {
        self.check_single_call_signature(&it.members, it.span());
        self.check_overload_grouping(&it.members);
        walk_ts_type_literal(self, it);
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        self.s7059_enter_class(it);
        if let Some(id) = &it.id {
            self.class_stack.push(id.name.to_string());
        }
        walk_class(self, it);
        if it.id.is_some() {
            self.class_stack.pop();
        }
        self.s7059_leave_class();
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        let constructor = flags.contains(ScopeFlags::Constructor) && self.constructor_depth > 0;
        self.s7059_enter_function(constructor);
        walk_function(self, it, flags);
        self.s7059_leave_function(constructor);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if it.kind == MethodDefinitionKind::Constructor {
            self.constructor_depth += 1;
            walk_method_definition(self, it);
            self.constructor_depth -= 1;
        } else {
            walk_method_definition(self, it);
        }
        self.check_return_type_annotations(
            &it.value.params,
            it.value.return_type.as_deref(),
            it.value.this_param.as_deref(),
            it.value.body.as_deref(),
            it.value.id.as_ref(),
        );
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        let previous = self.s7059_enter_statement(it.span());
        if let Statement::FunctionDeclaration(function) = it {
            self.check_return_type_annotations(
                &function.params,
                function.return_type.as_deref(),
                function.this_param.as_deref(),
                function.body.as_deref(),
                function.id.as_ref(),
            );
        }
        walk_statement(self, it);
        self.s7059_leave_statement(previous);
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.check_return_type_annotations(&it.params, it.return_type.as_deref(), None, None, None);
        self.s7059_enter_function(false);
        walk_arrow_function_expression(self, it);
        self.s7059_leave_function(false);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.check_s6568_logical_expression(it);
        walk_logical_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_s7059_call_expression(it);
        walk_call_expression(self, it);
    }
    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        walk_assignment_expression(self, it);
        self.check_s7059_assignment_expression(it);
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
        self.check_s1444_property_definition(it);
        walk_property_definition(self, it);
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        self.check_s4326_return_await(it);
        walk_return_statement(self, it);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        // `return await` inside a try statement with a catch or finally
        // handler preserves rejection-handling semantics; those regions are
        // exempt from the `S4326` return-await finding.
        let guarded = it.handler.is_some() || it.finalizer.is_some();
        if guarded {
            self.try_guard_depth += 1;
        }
        walk_try_statement(self, it);
        if guarded {
            self.try_guard_depth -= 1;
        }
    }

    fn visit_await_expression(&mut self, it: &AwaitExpression<'a>) {
        self.check_s7059_await_expression(it);
        self.check_s4326_await_expression(it);
        walk_await_expression(self, it);
    }
}

/// The wider deprecated-hash family `S4790` flags.
pub(crate) const WEAK_HASH_FAMILY: [&str; 4] = ["md2", "md4", "md5", "sha1"];

/// Encryption APIs whose mere use `S4787` asks a developer to review.
pub(crate) const ENCRYPT_API_NAMES: [&str; 6] = [
    "createCipheriv",
    "createDecipheriv",
    "publicEncrypt",
    "privateDecrypt",
    "generateKeyPair",
    "generateKeyPairSync",
];

/// Elliptic curves `S4426` considers too weak for key generation.
pub(crate) const WEAK_EC_CURVES: [&str; 8] = [
    "secp112r1",
    "secp128r1",
    "secp160r1",
    "secp192r1",
    "prime192v1",
    "prime192v2",
    "prime192v3",
    "sect163r1",
];

/// Cipher families `S5547` considers broken.
pub(crate) const WEAK_CIPHER_FAMILIES: [&str; 6] = ["des", "rc2", "rc4", "bf", "blowfish", "idea"];

/// JWT algorithms `S5659` rejects for signing and verification.
pub(crate) const WEAK_JWT_ALGORITHMS: [&str; 1] = ["none"];

/// Angular sanitizer bypass methods `S6268` flags.
pub(crate) const ANGULAR_BYPASS_METHODS: [&str; 5] = [
    "bypassSecurityTrustHtml",
    "bypassSecurityTrustStyle",
    "bypassSecurityTrustScript",
    "bypassSecurityTrustUrl",
    "bypassSecurityTrustResourceUrl",
];

/// Referrer-Policy values `S5736` considers unsafe.
pub(crate) const UNSAFE_REFERRER_POLICIES: [&str; 2] = ["unsafe-url", "no-referrer-when-downgrade"];

/// Archive-extraction entry points `S5042` asks developers to review.
pub(crate) const ARCHIVE_EXTRACT_APIS: [&str; 5] =
    ["unzip", "unzipSync", "untar", "extract", "extractAllTo"];

/// Cleartext transport modules `S5332` flags on import and `require`.
pub(crate) const CLEARTEXT_MODULES: [&str; 2] = ["http", "ws"];

/// Identifier fragments whose presence in logged arguments `S5757` flags.
pub(crate) const SENSITIVE_DATA_FRAGMENTS: [&str; 6] = [
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
];

/// First call argument as a string-literal value, if it is one.
pub(crate) fn first_string_argument<'a>(call: &'a CallExpression<'_>) -> Option<&'a str> {
    let argument = call.arguments.first()?;
    match unparenthesized(argument_expression(argument)?) {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Value of a static or quoted-string key inside an object literal.
pub(crate) fn object_property<'a, 'b>(
    object: &'a ObjectExpression<'b>,
    key: &str,
) -> Option<&'a Expression<'b>> {
    object.properties.iter().find_map(|property| {
        let ObjectPropertyKind::ObjectProperty(inner) = property else {
            return None;
        };
        match duplicated_key_name(&inner.key) {
            Some(name) if name == key => Some(&inner.value),
            _ => None,
        }
    })
}

/// String value of an object-literal key, if it holds a string literal.
pub(crate) fn string_property<'a>(object: &'a ObjectExpression<'_>, key: &str) -> Option<&'a str> {
    match object_property(object, key)? {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Boolean value of an object-literal key, if it holds a boolean literal.
pub(crate) fn boolean_property(object: &ObjectExpression<'_>, key: &str) -> Option<bool> {
    match object_property(object, key)? {
        Expression::BooleanLiteral(literal) => Some(literal.value),
        _ => None,
    }
}

/// String-literal value of the call argument at `index`, if it is one.
pub(crate) fn string_argument_at<'a>(
    call: &'a CallExpression<'_>,
    index: usize,
) -> Option<&'a str> {
    let argument = call.arguments.get(index)?;
    match unparenthesized(argument_expression(argument)?) {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Numeric value of an object-literal key, if it holds a numeric literal.
pub(crate) fn number_property(object: &ObjectExpression<'_>, key: &str) -> Option<f64> {
    match object_property(object, key)? {
        Expression::NumericLiteral(literal) => Some(literal.value),
        _ => None,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ScriptBinding {
    span: Span,
    src: bool,
    integrity: bool,
    function_depth: usize,
}
/// Security-hotspot collector: sink tables and option-object inspections.
pub(crate) struct SecurityHotspotCollector<'s, 'index> {
    pub(crate) source: &'s str,
    pub(crate) sink: IssueSink<'index>,
    pub(crate) process_bindings: ProcessBindingResolver,
    pub(crate) security_bindings: SecurityBindingResolver,
    /// Unsafe middleware values captured by their lexical binding at creation.
    pub(crate) unsafe_helmet_middleware: HashSet<SymbolId>,
    pub(crate) pending_express_apps: Vec<(SymbolId, Span)>,
    pub(crate) app_aliases: HashMap<SymbolId, SymbolId>,
    pub(crate) disabled_express_apps: HashSet<SymbolId>,
    pub(crate) csrf_protected_apps: HashSet<SymbolId>,
    pub(crate) debug_guard_spans: Vec<Span>,
    pub(crate) script_bindings: HashMap<SymbolId, ScriptBinding>,
    pub(crate) signale_unprotected: HashSet<SymbolId>,
    pub(crate) function_depth: usize,
}

/// Modules whose imports `S4818` flags as raw socket surfaces.
pub(crate) const RAW_SOCKET_MODULES: [&str; 2] = ["net", "dgram"];

impl<'a> Visit<'a> for SecurityHotspotCollector<'_, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_mounted_helmet(it);
        self.check_hash_sink(it);
        self.check_encrypt_api(it);
        self.check_key_generation(it);
        self.check_cipher_mode(it);
        self.check_weak_cipher(it);
        self.check_shell_exec(it);
        self.check_math_random(it);
        self.check_jwt_algorithms(it);
        self.check_angular_bypass(it);
        self.check_message_handler(it);
        self.check_window_open(it);
        self.check_sensitive_log(it);
        self.check_signale_log(it);
        self.check_error_middleware(it);
        self.check_cors_wildcard(it);
        self.check_cleartext_require(it);
        self.check_cookie_options(it);
        self.check_xml_parser(it);
        self.check_upload_limits(it);
        self.check_body_parser_limit(it);
        self.check_helmet_config(it);
        self.check_header_call(it);
        self.check_route_security(it);
        self.check_csrf_disabled(it);
        self.check_tls_options(it);
        self.check_tls_protocol_call(it);
        self.check_template_options(it);
        self.check_temp_file_access(it);
        self.check_proxy_configuration(it);
        self.check_app_disable(it);
        self.check_script_append(it);
        self.check_archive_extraction(it);
        self.check_xpath_usage(it);
        self.check_socket_require(it);
        self.check_s3_create_bucket(it);
        walk_call_expression(self, it);
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

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        self.register_security_binding(it);
        walk_variable_declarator(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        if is_development_guard(&it.test, &self.security_bindings) {
            self.debug_guard_spans.push(it.consequent.span());
        }
        walk_if_statement(self, it);
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        self.check_cleartext_scheme(it);
        self.check_vue_v_html_string(&it.value, it.span());
        walk_string_literal(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        self.check_sensitive_permission(it);
        self.check_command_line_arguments(it);
        self.check_standard_input_reads(it);
        walk_member_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        self.check_tls_validation_disabled(it);
        self.check_script_assignment(it);
        walk_assignment_expression(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        self.check_s5332_import_declaration(it);
        walk_import_declaration(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        self.check_option_property(it);
        walk_object_property(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        Self::check_new_upload(it);
        self.check_new_xpath_evaluator(it);
        self.check_new_raw_socket(it);
        self.check_new_s3_bucket_command(it);
        walk_new_expression(self, it);
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        self.check_vue_v_html_template(it);
        walk_template_literal(self, it);
    }
}

impl SecurityHotspotCollector<'_, '_> {
    fn check_mounted_helmet(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
            return;
        };
        let at = call.span().start;
        if member.property.name != "use"
            || !self
                .security_bindings
                .is_factory(&member.object, SecurityFactory::ExpressApp, at)
        {
            return;
        }
        if call
            .arguments
            .iter()
            .filter_map(argument_expression)
            .any(|expression| self.is_unsafe_helmet_middleware(expression, at))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S5728",
                "Make sure not enabling content security policy fetch directives is safe here.",
                call.span(),
            );
        }
    }

    fn is_unsafe_helmet_middleware(&self, expression: &Expression<'_>, at: u32) -> bool {
        match unparenthesized(expression) {
            Expression::CallExpression(middleware)
                if self
                    .security_bindings
                    .call_origin(middleware, middleware.span().start)
                    == SecurityOrigin::Factory(SecurityFactory::HelmetMiddleware) =>
            {
                middleware
                    .arguments
                    .first()
                    .and_then(argument_expression)
                    .is_some_and(|options| {
                        self.security_bindings.object_property(
                            options,
                            "contentSecurityPolicy",
                            middleware.span().start,
                        ) == Some(SecurityValue::Boolean(false))
                    })
            }
            Expression::Identifier(_) => {
                self.security_bindings
                    .symbol(expression)
                    .is_some_and(|symbol| {
                        self.security_bindings.symbol_is_current(symbol, at)
                            && self.unsafe_helmet_middleware.contains(&symbol)
                    })
            }
            Expression::ArrayExpression(array) => array
                .elements
                .iter()
                .filter_map(|element| element.as_expression())
                .any(|expression| self.is_unsafe_helmet_middleware(expression, at)),
            _ => false,
        }
    }

    fn register_security_binding(&mut self, declarator: &VariableDeclarator<'_>) {
        let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
            return;
        };
        let Some(init) = declarator.init.as_ref() else {
            return;
        };
        let at = init.span().start;
        let symbol = identifier.symbol_id.get();
        if let Some(symbol) = symbol
            && self.is_unsafe_helmet_middleware(init, at)
        {
            self.unsafe_helmet_middleware.insert(symbol);
        }

        if self
            .security_bindings
            .is_factory(init, SecurityFactory::ExpressApp, at)
            && let Some(symbol) = symbol
        {
            if matches!(unparenthesized(init), Expression::Identifier(_))
                && let Some(source) = self.security_bindings.symbol(init)
            {
                let root = self.app_aliases.get(&source).copied().unwrap_or(source);
                self.app_aliases.insert(symbol, root);
            } else {
                self.pending_express_apps.push((symbol, init.span()));
            }
        }

        if self
            .security_bindings
            .is_instance(init, SecurityInstance::Signale, at)
            && let Some(symbol) = symbol
            && let Expression::NewExpression(new) = unparenthesized(init)
            && let Some(options) = new.arguments.first().and_then(argument_expression)
            && matches!(
                self.security_bindings
                    .object_property(options, "secrets", at),
                Some(SecurityValue::EmptyArray)
            )
        {
            self.signale_unprotected.insert(symbol);
        }

        if is_script_element(init, &self.security_bindings, at)
            && let Some(symbol) = symbol
        {
            self.script_bindings.insert(
                symbol,
                ScriptBinding {
                    span: init.span(),
                    src: false,
                    integrity: false,
                    function_depth: self.function_depth,
                },
            );
        }
    }

    pub(crate) fn finish_security(&mut self) {
        for &(symbol, span) in &self.pending_express_apps {
            if !self.disabled_express_apps.contains(&symbol) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5689",
                    "This framework implicitly discloses version information by default. Make sure it is safe here.",
                    span,
                );
            }
        }
    }

    pub(crate) fn in_development_guard(&self, span: Span) -> bool {
        self.debug_guard_spans
            .iter()
            .any(|guard| guard.start <= span.start && span.end <= guard.end)
    }

    fn check_app_disable(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let at = call.span().start;
        if !self
            .security_bindings
            .is_factory(&member.object, SecurityFactory::ExpressApp, at)
        {
            return;
        }
        let Some(raw_symbol) = self.security_bindings.symbol(&member.object) else {
            return;
        };
        let symbol = self
            .app_aliases
            .get(&raw_symbol)
            .copied()
            .unwrap_or(raw_symbol);
        let explicitly_disabled = member.property.name == "disable"
            && first_string_argument(call) == Some("x-powered-by");
        let hide_powered_by = member.property.name == "use"
            && call
                .arguments
                .first()
                .and_then(argument_expression)
                .and_then(|expression| {
                    let Expression::CallExpression(helper) = unparenthesized(expression) else {
                        return None;
                    };
                    Some(self.security_bindings.is_module_member(
                        &helper.callee,
                        SecurityModule::Helmet,
                        "hidePoweredBy",
                        at,
                    ))
                })
                .unwrap_or(false);
        if explicitly_disabled || hide_powered_by {
            self.disabled_express_apps.insert(symbol);
        }
    }

    fn check_route_security(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let at = call.span().start;
        let app_or_router =
            self.security_bindings
                .is_factory(&member.object, SecurityFactory::ExpressApp, at)
                || self.security_bindings.is_factory(
                    &member.object,
                    SecurityFactory::ExpressRouter,
                    at,
                );
        if !app_or_router {
            return;
        }
        let Some(raw_app_symbol) = self.security_bindings.symbol(&member.object) else {
            return;
        };
        let app_symbol = self
            .app_aliases
            .get(&raw_app_symbol)
            .copied()
            .unwrap_or(raw_app_symbol);
        if member.property.name == "use" {
            if call.arguments.iter().any(|argument| {
                argument_expression(argument).is_some_and(|expression| {
                    self.security_bindings.is_factory(
                        expression,
                        SecurityFactory::CsurfProtection,
                        at,
                    )
                })
            }) {
                self.csrf_protected_apps.insert(app_symbol);
            }
            return;
        }
        if !matches!(
            member.property.name.as_str(),
            "post" | "put" | "patch" | "delete"
        ) || call.arguments.len() < 2
        {
            return;
        }
        let protected = self.csrf_protected_apps.contains(&app_symbol)
            || call.arguments.iter().skip(1).any(|argument| {
                argument_expression(argument).is_some_and(|expression| {
                    self.security_bindings.is_factory(
                        expression,
                        SecurityFactory::CsurfProtection,
                        at,
                    )
                })
            });
        if !protected {
            self.sink.emit_span(
                RuleScope::Both,
                "S4502",
                "Make sure this state-changing route is protected against CSRF.",
                call.span(),
            );
        }
    }

    fn check_proxy_configuration(&mut self, call: &CallExpression<'_>) {
        if !self.security_bindings.is_call_factory(
            call,
            SecurityFactory::ProxyMiddleware,
            call.span().start,
        ) {
            return;
        }
        let Some(options) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        if self
            .security_bindings
            .object_property(options, "xfwd", call.span().start)
            == Some(SecurityValue::Boolean(true))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S5759",
                "Make sure forwarding client IP address is safe here.",
                call.callee.span(),
            );
        }
    }

    fn check_template_options(&mut self, call: &CallExpression<'_>) {
        if !self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::Handlebars,
            "compile",
            call.span().start,
        ) {
            return;
        }
        let Some(options) = call.arguments.get(1).and_then(argument_expression) else {
            return;
        };
        if self
            .security_bindings
            .object_property(options, "noEscape", call.span().start)
            == Some(SecurityValue::Boolean(true))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S5247",
                "Disable automatic HTML escaping only when the input is fully trusted.",
                call.span(),
            );
        }
    }

    fn check_temp_file_access(&mut self, call: &CallExpression<'_>) {
        if !matches!(
            self.security_bindings.origin(&call.callee, call.span().start),
            SecurityOrigin::Module(SecurityModule::Fs, Some(member))
                if matches!(member.as_str(), "readFile" | "readFileSync")
        ) {
            return;
        }
        let Some(path) = call
            .arguments
            .first()
            .and_then(argument_expression)
            .and_then(|expression| {
                self.security_bindings
                    .static_value(expression, call.span().start)
            })
        else {
            return;
        };
        let SecurityValue::String(path) = path else {
            return;
        };
        if is_public_temp_path(&path) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5443",
                "Temporary files should not be created in publicly writable directories.",
                call.span(),
            );
        }
    }

    fn check_script_append(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if member.property.name != "appendChild"
            || !is_document_head(&member.object, &self.security_bindings)
        {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Some(symbol) = self.security_bindings.symbol(argument) else {
            return;
        };
        let Some(binding) = self.script_bindings.get(&symbol).copied() else {
            return;
        };
        if binding.src && !binding.integrity {
            self.sink.emit_span(
                RuleScope::Both,
                "S5725",
                "Add an integrity attribute to this element to ensure resource integrity.",
                binding.span,
            );
        }
    }

    fn check_signale_log(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if member.property.name != "log" {
            return;
        }
        let Some(symbol) = self.security_bindings.symbol(&member.object) else {
            return;
        };
        if self.signale_unprotected.contains(&symbol) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5757",
                "Make sure this logged data is not sensitive.",
                call.span(),
            );
        }
    }

    fn check_script_assignment(&mut self, assignment: &AssignmentExpression<'_>) {
        let Some(SimpleAssignmentTarget::StaticMemberExpression(member)) =
            assignment.left.as_simple_assignment_target()
        else {
            return;
        };
        let Some(symbol) = self.security_bindings.symbol(&member.object) else {
            return;
        };
        let Some(binding) = self.script_bindings.get_mut(&symbol) else {
            return;
        };
        if binding.function_depth != self.function_depth {
            return;
        }
        match member.property.name.as_str() {
            "src" => binding.src = true,
            "integrity" => {
                binding.integrity = matches!(
                    self.security_bindings
                        .static_value(&assignment.right, assignment.span().start),
                    Some(SecurityValue::String(value)) if !value.is_empty()
                );
            }
            _ => {}
        }
    }
}

fn is_script_element(
    expression: &Expression<'_>,
    bindings: &SecurityBindingResolver,
    at: u32,
) -> bool {
    let Expression::CallExpression(call) = unparenthesized(expression) else {
        return false;
    };
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return false;
    };
    if member.property.name != "createElement"
        || !matches!(
            unparenthesized(&member.object),
            Expression::Identifier(identifier)
                if identifier.name == "document" && bindings.symbol(&member.object).is_none()
        )
    {
        return false;
    }
    matches!(
        call.arguments.first().and_then(argument_expression),
        Some(Expression::StringLiteral(literal)) if literal.value == "script"
    ) && at <= call.span().start
}

fn is_document_head(expression: &Expression<'_>, bindings: &SecurityBindingResolver) -> bool {
    let Expression::StaticMemberExpression(member) = unparenthesized(expression) else {
        return false;
    };
    member.property.name == "head"
        && matches!(
            unparenthesized(&member.object),
            Expression::Identifier(identifier)
                if identifier.name == "document" && bindings.symbol(&member.object).is_none()
        )
}

fn is_public_temp_path(path: &str) -> bool {
    matches!(
        path,
        path if path.starts_with("/tmp/")
            || path.starts_with("/var/tmp/")
            || path.starts_with("/dev/shm/")
    )
}

fn is_development_guard(expression: &Expression<'_>, bindings: &SecurityBindingResolver) -> bool {
    let Expression::BinaryExpression(binary) = unparenthesized(expression) else {
        return false;
    };
    if !matches!(
        binary.operator,
        BinaryOperator::Equality | BinaryOperator::StrictEquality
    ) {
        return false;
    }
    (is_node_env(&binary.left, bindings) && is_development_literal(&binary.right))
        || (is_node_env(&binary.right, bindings) && is_development_literal(&binary.left))
}

fn is_node_env(expression: &Expression<'_>, bindings: &SecurityBindingResolver) -> bool {
    let Expression::StaticMemberExpression(node_env) = unparenthesized(expression) else {
        return false;
    };
    if node_env.property.name != "NODE_ENV" {
        return false;
    }
    let Expression::StaticMemberExpression(env) = unparenthesized(&node_env.object) else {
        return false;
    };
    env.property.name == "env"
        && matches!(
            unparenthesized(&env.object),
            Expression::Identifier(identifier)
                if identifier.name == "process" && bindings.symbol(&env.object).is_none()
        )
}

fn is_development_literal(expression: &Expression<'_>) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::StringLiteral(literal) if literal.value == "development"
    )
}
