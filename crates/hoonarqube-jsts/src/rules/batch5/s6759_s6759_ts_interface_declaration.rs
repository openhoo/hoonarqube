use crate::support::{IssueSink, RuleScope, unparenthesized};
use oxc_ast::ast::{
    ArrowFunctionExpression, BlockStatement, Class, Declaration, Expression, Function,
    FunctionBody, FunctionType, ImportDeclaration, ImportDeclarationSpecifier, MethodDefinition,
    Program, PropertyKey, ReturnStatement, TSInterfaceDeclaration, TSNamespaceDeclaration,
    TSSignature, TSType, TSTypeAliasDeclaration, TSTypeName, TSTypeOperatorOperator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_block_statement, walk_class, walk_declaration,
    walk_expression, walk_function, walk_function_body, walk_program, walk_return_statement,
    walk_ts_interface_declaration, walk_ts_namespace_declaration, walk_ts_type_alias_declaration,
};
use oxc_span::Span;
use oxc_syntax::scope::ScopeFlags;
use std::collections::{BTreeMap, BTreeSet};

/// `S6759` applies to named React functional components, not to every type
/// whose name happens to contain `Props`. The type model is deliberately
/// file-local: imported and otherwise unresolved names stay conservative.
pub(crate) fn check_s6759(program: &Program<'_>, sink: &mut IssueSink<'_>) {
    let mut model = TypeModel::default();
    model.visit_program(program);

    let mut components = ComponentCollector {
        model: &model,
        components: Vec::new(),
    };
    components.visit_program(program);
    components.emit(sink);
}

#[derive(Clone)]
enum TypeShape {
    Properties(Vec<(String, Span, bool)>),
    Reference(String),
    Readonly(Box<TypeShape>),
    ReadonlyUtility(Box<TypeShape>),
    Intersection(Vec<TypeShape>),
    Unknown,
}

/// A binding is tracked in the lexical scope where it is declared. An
/// interface may merge with another interface in that same scope; all other
/// duplicate declarations are unresolved rather than invalidating unrelated
/// outer scopes.
#[derive(Clone)]
enum TypeBinding {
    Known { shape: TypeShape, interface: bool },
    Unknown,
}

struct TypeScope {
    span: Span,
    parent: Option<usize>,
    bindings: BTreeMap<String, TypeBinding>,
    generic_names: BTreeSet<String>,
}

#[derive(Default)]
struct TypeModel {
    scopes: Vec<TypeScope>,
    stack: Vec<usize>,
}

impl TypeModel {
    fn push_scope(&mut self, span: Span) -> usize {
        let parent = self.stack.last().copied();
        let id = self.scopes.len();
        self.scopes.push(TypeScope {
            span,
            parent,
            bindings: BTreeMap::new(),
            generic_names: BTreeSet::new(),
        });
        self.stack.push(id);
        id
    }

    fn pop_scope(&mut self) {
        self.stack.pop();
    }

    fn current_scope(&self) -> usize {
        self.stack
            .last()
            .copied()
            .expect("S6759 scope stack must contain a scope")
    }

    fn add_generic_names(
        &mut self,
        parameters: Option<&oxc_ast::ast::TSTypeParameterDeclaration<'_>>,
    ) {
        let Some(parameters) = parameters else {
            return;
        };
        let scope = self.current_scope();
        for parameter in &parameters.params {
            self.scopes[scope]
                .generic_names
                .insert(parameter.name.name.to_string());
        }
    }

    fn bind_unknown(&mut self, name: String) {
        let scope = self.current_scope();
        self.scopes[scope]
            .bindings
            .insert(name, TypeBinding::Unknown);
    }

    fn bind_type(&mut self, name: String, shape: TypeShape, interface: bool) {
        let scope = self.current_scope();
        let previous = self.scopes[scope].bindings.remove(&name);
        let binding = match previous {
            None => TypeBinding::Known { shape, interface },
            Some(TypeBinding::Known {
                shape: previous_shape,
                interface: previous_interface,
            }) if interface && previous_interface => TypeBinding::Known {
                shape: TypeShape::Intersection(vec![previous_shape, shape]),
                interface: true,
            },
            Some(TypeBinding::Unknown | TypeBinding::Known { .. }) => TypeBinding::Unknown,
        };
        self.scopes[scope].bindings.insert(name, binding);
    }

    fn scope_for_span(&self, span: Span) -> usize {
        self.scopes
            .iter()
            .enumerate()
            .filter(|(_, scope)| scope.span.start <= span.start && span.end <= scope.span.end)
            .min_by_key(|(_, scope)| scope.span.end.saturating_sub(scope.span.start))
            .map_or(0, |(id, _)| id)
    }

    fn lookup(&self, scope_id: usize, name: &str) -> Option<TypeLookup<'_>> {
        let mut scope_id = Some(scope_id);
        while let Some(id) = scope_id {
            let scope = &self.scopes[id];
            if scope.generic_names.contains(name) {
                return Some(TypeLookup::Unknown);
            }
            if let Some(binding) = scope.bindings.get(name) {
                return Some(match binding {
                    TypeBinding::Known { shape, .. } => TypeLookup::Known(shape, id),
                    TypeBinding::Unknown => TypeLookup::Unknown,
                });
            }
            scope_id = scope.parent;
        }
        None
    }
}

enum TypeLookup<'a> {
    Known(&'a TypeShape, usize),
    Unknown,
}

impl<'a> Visit<'a> for TypeModel {
    fn visit_program(&mut self, it: &Program<'a>) {
        self.push_scope(it.span);
        walk_program(self, it);
        self.pop_scope();
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.push_scope(it.span);
        walk_block_statement(self, it);
        self.pop_scope();
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.push_scope(it.span);
        walk_function_body(self, it);
        self.pop_scope();
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        self.push_scope(it.span);
        self.add_generic_names(it.type_parameters.as_deref());
        walk_function(self, it, flags);
        self.pop_scope();
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        self.push_scope(it.span);
        self.add_generic_names(it.type_parameters.as_deref());
        walk_class(self, it);
        self.pop_scope();
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.push_scope(it.span);
        self.add_generic_names(it.type_parameters.as_deref());
        walk_arrow_function_expression(self, it);
        self.pop_scope();
    }

    fn visit_ts_namespace_declaration(&mut self, it: &TSNamespaceDeclaration<'a>) {
        self.push_scope(it.span);
        walk_ts_namespace_declaration(self, it);
        self.pop_scope();
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        let Some(specifiers) = &it.specifiers else {
            return;
        };
        for specifier in specifiers {
            let local = match specifier {
                ImportDeclarationSpecifier::ImportSpecifier(specifier) => &specifier.local,
                ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => &specifier.local,
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => &specifier.local,
            };
            self.bind_unknown(local.name.to_string());
        }
    }

    fn visit_ts_interface_declaration(&mut self, it: &TSInterfaceDeclaration<'a>) {
        self.bind_type(it.id.name.to_string(), interface_shape(it), true);
        walk_ts_interface_declaration(self, it);
    }

    fn visit_ts_type_alias_declaration(&mut self, it: &TSTypeAliasDeclaration<'a>) {
        let shape = if it.type_parameters.is_some() {
            // Instantiating generic aliases needs a type checker. Keep the
            // binding known only for non-generic, fully local shapes.
            TypeShape::Unknown
        } else {
            shape_from_type(&it.type_annotation)
        };
        self.bind_type(it.id.name.to_string(), shape, false);
        walk_ts_type_alias_declaration(self, it);
    }
}

struct Component {
    props_shape: TypeShape,
    scope_id: usize,
    parameter_span: Span,
}

struct ComponentCollector<'model> {
    model: &'model TypeModel,
    components: Vec<Component>,
}

impl<'ast> Visit<'ast> for ComponentCollector<'_> {
    fn visit_function(&mut self, it: &Function<'ast>, flags: ScopeFlags) {
        if matches!(it.r#type, FunctionType::FunctionDeclaration)
            && it.id.as_ref().is_some_and(|id| {
                id.name
                    .as_str()
                    .starts_with(|ch: char| ch.is_ascii_uppercase())
            })
            && it.params.items.len() + usize::from(it.params.rest.is_some()) <= 1
            && let Some(parameter) = it.params.items.first()
            && let Some(annotation) = &parameter.type_annotation
            && it.body.as_deref().is_some_and(function_returns_jsx)
        {
            self.components.push(Component {
                props_shape: shape_from_type(&annotation.type_annotation),
                scope_id: self.model.scope_for_span(parameter.span),
                parameter_span: parameter.span,
            });
        }
        walk_function(self, it, flags);
    }
}

impl ComponentCollector<'_> {
    fn emit(&self, sink: &mut IssueSink<'_>) {
        for component in &self.components {
            let Some(props) = resolve_shape(
                &component.props_shape,
                self.model,
                component.scope_id,
                &mut Vec::new(),
            ) else {
                continue;
            };
            if props.is_empty() || props.iter().all(|(_, _, readonly)| *readonly) {
                continue;
            }
            sink.emit_span(
                RuleScope::TsOnly,
                "S6759",
                "Mark the props of the component as read-only.",
                component.parameter_span,
            );
        }
    }
}

fn type_property_name<'a>(key: &PropertyKey<'a>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) => Some(identifier.name.as_str()),
        PropertyKey::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

fn properties(signatures: &[TSSignature<'_>]) -> Vec<(String, Span, bool)> {
    signatures
        .iter()
        .filter_map(|signature| match signature {
            TSSignature::TSPropertySignature(property) => type_property_name(&property.key)
                .map(|name| (name.to_string(), property.span, property.readonly)),
            _ => None,
        })
        .collect()
}

fn interface_shape(interface: &TSInterfaceDeclaration<'_>) -> TypeShape {
    let mut parts = Vec::with_capacity(interface.extends.len() + 1);
    for heritage in &interface.extends {
        if heritage.type_arguments.is_some() {
            parts.push(TypeShape::Unknown);
            continue;
        }
        let Some(name) = type_name(&heritage.type_name) else {
            parts.push(TypeShape::Unknown);
            continue;
        };
        parts.push(TypeShape::Reference(name));
    }
    parts.push(TypeShape::Properties(properties(&interface.body.body)));
    if parts.len() == 1 {
        parts.pop().unwrap_or(TypeShape::Unknown)
    } else {
        TypeShape::Intersection(parts)
    }
}

fn shape_from_type(type_: &TSType<'_>) -> TypeShape {
    match type_ {
        TSType::TSTypeLiteral(literal) => TypeShape::Properties(properties(&literal.members)),
        TSType::TSTypeReference(reference) => {
            let Some(name) = type_name(&reference.type_name) else {
                return TypeShape::Unknown;
            };
            if name == "Readonly" {
                let Some(arguments) = reference.type_arguments.as_deref() else {
                    return TypeShape::Unknown;
                };
                if arguments.params.len() != 1 {
                    return TypeShape::Unknown;
                }
                return TypeShape::ReadonlyUtility(Box::new(shape_from_type(&arguments.params[0])));
            }
            if reference.type_arguments.is_some() {
                return TypeShape::Unknown;
            }
            TypeShape::Reference(name)
        }
        TSType::TSParenthesizedType(parenthesized) => {
            shape_from_type(&parenthesized.type_annotation)
        }
        TSType::TSIntersectionType(intersection) => {
            TypeShape::Intersection(intersection.types.iter().map(shape_from_type).collect())
        }
        TSType::TSTypeOperatorType(operator)
            if operator.operator == TSTypeOperatorOperator::Readonly =>
        {
            TypeShape::Readonly(Box::new(shape_from_type(&operator.type_annotation)))
        }
        _ => TypeShape::Unknown,
    }
}

fn type_name(name: &TSTypeName<'_>) -> Option<String> {
    match name {
        TSTypeName::IdentifierReference(identifier) => Some(identifier.name.to_string()),
        // Qualified and imported names cannot be resolved by this file-local
        // model; never collapse them to an unrelated local suffix.
        TSTypeName::QualifiedName(_) | TSTypeName::ThisExpression(_) => None,
    }
}

fn resolve_shape(
    shape: &TypeShape,
    model: &TypeModel,
    scope_id: usize,
    seen: &mut Vec<(usize, String)>,
) -> Option<Vec<(String, Span, bool)>> {
    match shape {
        TypeShape::Properties(properties) => Some(properties.clone()),
        TypeShape::Readonly(inner) => {
            resolve_shape(inner, model, scope_id, seen).map(|properties| {
                properties
                    .into_iter()
                    .map(|(name, span, _)| (name, span, true))
                    .collect()
            })
        }
        TypeShape::ReadonlyUtility(inner) => {
            // A local/imported/generic `Readonly` shadows the built-in utility.
            if model.lookup(scope_id, "Readonly").is_some() {
                return None;
            }
            resolve_shape(inner, model, scope_id, seen).map(|properties| {
                properties
                    .into_iter()
                    .map(|(name, span, _)| (name, span, true))
                    .collect()
            })
        }
        TypeShape::Reference(name) => {
            let TypeLookup::Known(target, target_scope) = model.lookup(scope_id, name)? else {
                return None;
            };
            let key = (target_scope, name.clone());
            if seen.contains(&key) {
                return None;
            }
            seen.push(key);
            let resolved = resolve_shape(target, model, target_scope, seen);
            seen.pop();
            resolved
        }
        TypeShape::Intersection(parts) => {
            let mut merged = BTreeMap::new();
            for part in parts {
                for (name, span, readonly) in resolve_shape(part, model, scope_id, seen)? {
                    merged.insert(name, (span, readonly));
                }
            }
            Some(
                merged
                    .into_iter()
                    .map(|(name, (span, readonly))| (name, span, readonly))
                    .collect(),
            )
        }
        TypeShape::Unknown => None,
    }
}

fn function_returns_jsx(body: &FunctionBody<'_>) -> bool {
    let mut scanner = JsxReturnScanner::default();
    scanner.visit_function_body(body);
    scanner.found
}

#[derive(Default)]
struct JsxReturnScanner {
    found: bool,
}

impl<'a> Visit<'a> for JsxReturnScanner {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if it.argument.as_ref().is_some_and(|argument| {
            matches!(
                unparenthesized(argument),
                Expression::JSXElement(_) | Expression::JSXFragment(_)
            )
        }) {
            self.found = true;
        }
        walk_return_statement(self, it);
    }

    fn visit_function(&mut self, _it: &Function<'a>, _flags: ScopeFlags) {}

    fn visit_class(&mut self, _it: &Class<'a>) {}

    fn visit_method_definition(&mut self, _it: &MethodDefinition<'a>) {}

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            return;
        }
        walk_expression(self, it);
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if matches!(it, Declaration::FunctionDeclaration(_)) {
            return;
        }
        walk_declaration(self, it);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    fn tsx_keys(source: &str) -> Vec<(String, u32)> {
        report_keys(&analyze(
            PathBuf::from("test.tsx"),
            source,
            JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        ))
    }

    #[test]
    fn s6759_resolves_aliases_and_interfaces_only_for_real_react_components() {
        let mutable_alias = tsx_keys(
            "type Props = { title: string };\n\
             function View(props: Props) { return <div>{props.title}</div>; }\n",
        );
        assert_eq!(count_key(&mutable_alias, "typescript:S6759"), 1);

        let mutable_interface = tsx_keys(
            "interface Props { title: string }\n\
             function View(props: Props) { return <div>{props.title}</div>; }\n",
        );
        assert_eq!(count_key(&mutable_interface, "typescript:S6759"), 1);

        let non_react = ts_keys(
            "interface NetworkProps { retries: number }\n\
             function update(config: NetworkProps) { return config.retries; }\n",
        );
        assert_eq!(count_key(&non_react, "typescript:S6759"), 0);
    }

    #[test]
    fn s6759_handles_readonly_wrappers_and_named_property_overrides() {
        let quoted = tsx_keys(
            "type Props = { \"data-value\": string };\n\
             function View(props: Props) { return <div/>; }\n",
        );
        assert_eq!(count_key(&quoted, "typescript:S6759"), 1);

        let inherited = tsx_keys(
            "interface Base { \"data-value\": string }\n\
             interface Model extends Base { readonly \"data-value\": string }\n\
             function View(props: Model) { return <div/>; }\n",
        );
        assert_eq!(count_key(&inherited, "typescript:S6759"), 0);

        let wrapped = tsx_keys(
            "type Props = Readonly<{ title: string }>;\n\
             function View(props: Props) { return <div/>; }\n",
        );
        assert_eq!(count_key(&wrapped, "typescript:S6759"), 0);
    }

    #[test]
    fn s6759_keeps_lexical_shadowing_conservative_without_global_name_poisoning() {
        let outer = tsx_keys(
            "type Props = { title: string };\n\
             function View(props: Props) {\n\
               function helper() { type Props = { readonly title: string }; return 1; }\n\
               return <div/>;\n\
             }\n",
        );
        assert_eq!(count_key(&outer, "typescript:S6759"), 1);

        let generic = tsx_keys(
            "type Props = { title: string };\n\
             function factory<Props>() {\n\
               function View(props: Props) { return <div/>; }\n\
               return View;\n\
             }\n",
        );
        assert_eq!(count_key(&generic, "typescript:S6759"), 0);
        let class_generic = tsx_keys(
            "type Props = { title: string };\n\
             class Factory<Props> {\n\
               render() { function View(props: Props) { return <div/>; } return View; }\n\
             }\n",
        );
        assert_eq!(count_key(&class_generic, "typescript:S6759"), 0);

        let imported = tsx_keys(
            "import type { Props } from './props';\n\
             function View(props: Props) { return <div/>; }\n",
        );
        assert_eq!(count_key(&imported, "typescript:S6759"), 0);
    }

    #[test]
    fn s6759_does_not_treat_jsx_in_factory_object_methods_as_component_returns() {
        let factory = tsx_keys(
            "type Props = { title: string };\n\
             function Factory(props: Props) {\n\
               return { render() { return <div/>; } };\n\
             }\n",
        );
        assert_eq!(count_key(&factory, "typescript:S6759"), 0);
    }
}
