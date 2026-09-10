//! Owned project/module facts for Python rules that need cross-file symbols.
//!
//! This context is intentionally small and rule-oriented.  It resolves only
//! syntax-backed imports, re-exports, aliases, and class inheritance.  A
//! missing dependency, wildcard import, dynamic assignment, or unresolved
//! base remains `Unknown`; the GraphQL rule never turns that state into a
//! claimed safe configuration.

use crate::support::{child_bodies, parse};
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_text_size::{Ranged, TextRange, TextSize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
/// Framework identities pinned to `SonarPython` 4.26.0.19456's S6786 contract.
/// The analyzer does not infer package versions from import spelling; callers
/// must treat a different installed framework version as an external
/// qualification prerequisite.
pub(crate) const GRAPHQL_VIEW_FQNS: [&str; 2] = [
    "flask_graphql.GraphQLView",
    "graphql_server.flask.GraphQLView",
];
/// The `SQLAlchemy` constructor identity required by S6785's relationship owner.
pub(crate) const SQLALCHEMY_FQNS: [&str; 1] = ["flask_sqlalchemy.SQLAlchemy"];

/// The Graphene depth validator identity used by S6785 ownership checks.
pub(crate) const GRAPHQL_DEPTH_VALIDATOR_FQNS: [&str; 1] =
    ["graphene.validation.depth_limit_validator"];

/// Accepted blocker identities from the same pinned `SonarPython` contract.
pub(crate) const SAFE_VALIDATION_RULE_FQNS: [&str; 2] = [
    "graphene.validation.DisableIntrospection",
    "graphql.validation.NoSchemaIntrospectionCustomRule",
];

/// Provenance of a middleware or validation configuration value.
///
/// `Unknown` is deliberately distinct from `Safe`: the analyzer does not
/// claim that a dynamically composed or unresolved configuration blocks
/// introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraphqlSafety {
    Safe,
    Unsafe,
    Unknown,
}

/// Explicit project/module input for Python rules requiring cross-file facts.
///
/// Callers should insert every source file under its importable dotted module
/// name before invoking [`crate::analyze_with_context`].  The context stores
/// owned facts, not AST borrows, so callers may discard source buffers after
/// insertion.  Missing modules and dependencies remain unresolved.
#[derive(Debug, Clone, Default)]
pub struct PythonProjectContext {
    pub(crate) modules: BTreeMap<String, ModuleFacts>,
}

impl PythonProjectContext {
    /// Creates an empty project context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a source module under an explicit dotted name.
    pub fn add_module(&mut self, module_name: impl Into<String>, source: &str) {
        let module_name = normalize_module_name(&module_name.into());
        let parsed = parse(source);
        self.modules.insert(
            module_name.clone(),
            build_module_facts(&module_name, &parsed),
        );
    }

    /// Adds a source file using a path-derived dotted module name.
    ///
    /// Explicit [`Self::add_module`] names are preferred when the caller has a
    /// project root or import map.  This convenience method is intended for
    /// relative project paths such as `package/views.py`.
    pub fn add_path(&mut self, path: impl Into<PathBuf>, source: &str) -> String {
        let path = path.into();
        let module_name = module_name_from_path(&path);
        self.add_module(module_name.clone(), source);
        module_name
    }

    /// Returns whether a module with this dotted name was inserted.
    #[must_use]
    pub fn contains_module(&self, module_name: &str) -> bool {
        self.modules.contains_key(module_name)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ModuleFacts {
    pub(crate) name: String,
    scopes: Vec<ScopeFacts>,
    symbols: Vec<SymbolFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Function,
    Class,
}

#[derive(Debug, Clone)]
struct ScopeFacts {
    parent: Option<usize>,
    kind: ScopeKind,
    range: TextRange,
    bindings: Vec<BindingFact>,
}

#[derive(Debug, Clone)]
struct BindingFact {
    name: String,
    value: ValueFact,
    at: TextSize,
}

#[derive(Debug, Clone)]
enum SymbolFact {
    Class {
        name: String,
        bases: Vec<RefExpr>,
        scope: usize,
        at: TextSize,
    },
}

#[derive(Debug, Clone)]
enum ValueFact {
    Module(String),
    Symbol(usize),
    Reference(RefExpr),
    Collection(CollectionKind, Vec<ValueFact>),
    Call(Option<RefExpr>),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CollectionKind {
    List,
    Tuple,
    Set,
    Other,
}

#[derive(Debug, Clone)]
pub(crate) enum RefExpr {
    Name(String),
    Module(String),
    Attribute(Box<RefExpr>, String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SymbolResolution {
    GraphqlView,
    GraphqlDepthValidator,
    SqlAlchemy,
    SafeValidation,
    User,
    Other,
    Unknown,
}

impl ModuleFacts {
    pub(crate) fn scope_at(&self, offset: TextSize) -> usize {
        let mut best = 0;
        for (index, scope) in self.scopes.iter().enumerate() {
            if scope.range.start() <= offset
                && offset <= scope.range.end()
                && self.scopes[best].range.start() <= scope.range.start()
                && scope.range.end() <= self.scopes[best].range.end()
            {
                best = index;
            }
        }
        best
    }

    fn module_binding(&self, name: &str) -> Option<&ValueFact> {
        self.scopes[0]
            .bindings
            .iter()
            .rev()
            .find(|binding| binding.name == name)
            .map(|binding| &binding.value)
    }

    fn lookup_binding_with_scope(
        &self,
        start: usize,
        name: &str,
        at: TextSize,
    ) -> Option<(usize, &ValueFact)> {
        let mut scope_id = Some(start);
        while let Some(current) = scope_id {
            let scope = &self.scopes[current];
            if let Some(binding) = scope
                .bindings
                .iter()
                .rev()
                .find(|binding| binding.name == name && binding.at <= at)
            {
                return Some((current, &binding.value));
            }
            scope_id = match scope.kind {
                // Python functions do not close over a containing class body.
                ScopeKind::Function => {
                    let mut parent = scope.parent;
                    while parent.is_some_and(|id| self.scopes[id].kind == ScopeKind::Class) {
                        parent = parent.and_then(|id| self.scopes[id].parent);
                    }
                    parent
                }
                ScopeKind::Module | ScopeKind::Class => scope.parent,
            };
        }
        None
    }

    fn single_assigned_binding_at(
        &self,
        start: usize,
        name: &str,
        at: TextSize,
    ) -> Option<(usize, TextSize, &ValueFact)> {
        let mut scope_id = Some(start);
        while let Some(current) = scope_id {
            let scope = &self.scopes[current];
            if let Some(binding) = scope
                .bindings
                .iter()
                .rev()
                .find(|binding| binding.name == name && binding.at <= at)
            {
                if scope
                    .bindings
                    .iter()
                    .filter(|candidate| candidate.name == name)
                    .count()
                    != 1
                {
                    return None;
                }
                return Some((current, binding.at, &binding.value));
            }
            scope_id = match scope.kind {
                ScopeKind::Function => {
                    let mut parent = scope.parent;
                    while parent.is_some_and(|id| self.scopes[id].kind == ScopeKind::Class) {
                        parent = parent.and_then(|id| self.scopes[id].parent);
                    }
                    parent
                }
                ScopeKind::Module | ScopeKind::Class => scope.parent,
            };
        }
        None
    }
}

/// Resolves references against one current module plus the explicit project
/// context.  It is intentionally not a general Python type checker.
pub(crate) struct GraphqlResolver<'a> {
    current: &'a ModuleFacts,
    project: &'a PythonProjectContext,
}

impl<'a> GraphqlResolver<'a> {
    pub(crate) fn new(current: &'a ModuleFacts, project: &'a PythonProjectContext) -> Self {
        Self { current, project }
    }

    pub(crate) fn resolve_expression(
        &self,
        scope: usize,
        at: TextSize,
        expression: &Expr,
    ) -> SymbolResolution {
        let Some(reference) = ref_expr(expression) else {
            return SymbolResolution::Unknown;
        };
        self.resolve_reference(self.current, scope, at, &reference, &mut Vec::new())
    }

    pub(crate) fn is_single_assigned_sqlalchemy_constructor(
        &self,
        scope: usize,
        at: TextSize,
        name: &str,
    ) -> bool {
        let Some((binding_scope, binding_at, value)) =
            self.current.single_assigned_binding_at(scope, name, at)
        else {
            return false;
        };
        let ValueFact::Call(Some(callee)) = value else {
            return false;
        };
        self.resolve_reference(
            self.current,
            binding_scope,
            binding_at,
            callee,
            &mut Vec::new(),
        ) == SymbolResolution::SqlAlchemy
    }

    pub(crate) fn configuration_safety(
        &self,
        scope: usize,
        at: TextSize,
        expression: &Expr,
    ) -> GraphqlSafety {
        let value = value_fact(expression);
        self.configuration_value_safety(
            self.current,
            scope,
            at,
            &value,
            &mut Vec::new(),
            &mut Vec::new(),
        )
    }

    fn configuration_value_safety(
        &self,
        module: &ModuleFacts,
        scope: usize,
        at: TextSize,
        value: &ValueFact,
        visited: &mut Vec<(String, usize)>,
        binding_stack: &mut Vec<(String, String)>,
    ) -> GraphqlSafety {
        match value {
            ValueFact::Collection(kind, values) => {
                self.collection_safety(module, scope, at, *kind, values, visited)
            }
            // Sonar's helper only inspects list, tuple, and (since the
            // set-literal contract change) set literals.  Other expressions
            // remain explicit Unknown rather than being guessed safe/unsafe.
            ValueFact::Reference(reference) => {
                let Some((bound_module, bound_scope, bound)) =
                    self.bound_reference_value(module, scope, at, reference, visited)
                else {
                    return GraphqlSafety::Unknown;
                };
                let marker = (bound_module.name.clone(), reference_text(reference));
                if binding_stack.contains(&marker) {
                    return GraphqlSafety::Unknown;
                }
                binding_stack.push(marker);
                let result = self.configuration_value_safety(
                    bound_module,
                    bound_scope,
                    at,
                    bound,
                    visited,
                    binding_stack,
                );
                binding_stack.pop();
                result
            }
            ValueFact::Call(..)
            | ValueFact::Unknown
            | ValueFact::Module(_)
            | ValueFact::Symbol(..) => GraphqlSafety::Unknown,
        }
    }

    fn collection_safety(
        &self,
        module: &ModuleFacts,
        scope: usize,
        at: TextSize,
        kind: CollectionKind,
        values: &[ValueFact],
        visited: &mut Vec<(String, usize)>,
    ) -> GraphqlSafety {
        if !matches!(
            kind,
            CollectionKind::List | CollectionKind::Tuple | CollectionKind::Set
        ) {
            return GraphqlSafety::Unknown;
        }
        if values
            .iter()
            .any(|value| self.item_safety(module, scope, at, value, visited) == GraphqlSafety::Safe)
        {
            GraphqlSafety::Safe
        } else {
            // For a syntactically known collection this is the exact
            // reference-rule outcome: no recognized safe item means unsafe.
            GraphqlSafety::Unsafe
        }
    }

    fn item_safety(
        &self,
        module: &ModuleFacts,
        scope: usize,
        at: TextSize,
        value: &ValueFact,
        visited: &mut Vec<(String, usize)>,
    ) -> GraphqlSafety {
        match value {
            ValueFact::Reference(reference) => {
                self.reference_safety(module, scope, at, reference, visited)
            }
            ValueFact::Symbol(symbol) => symbol_safety(module, *symbol),
            ValueFact::Call(Some(callee)) if reference_contains_introspection(callee) => {
                GraphqlSafety::Safe
            }
            ValueFact::Collection(..) => GraphqlSafety::Unknown,
            ValueFact::Call(..) | ValueFact::Unknown | ValueFact::Module(_) => {
                GraphqlSafety::Unsafe
            }
        }
    }

    fn reference_safety(
        &self,
        module: &ModuleFacts,
        scope: usize,
        at: TextSize,
        reference: &RefExpr,
        visited: &mut Vec<(String, usize)>,
    ) -> GraphqlSafety {
        if reference_contains_introspection(reference)
            || self.resolve_reference(module, scope, at, reference, visited)
                == SymbolResolution::SafeValidation
        {
            return GraphqlSafety::Safe;
        }
        if self
            .bound_reference_value(module, scope, at, reference, visited)
            .is_some_and(|(bound_module, _, bound)| bound_value_is_safe(bound_module, bound))
        {
            GraphqlSafety::Safe
        } else {
            GraphqlSafety::Unsafe
        }
    }

    fn bound_reference_value<'b>(
        &'b self,
        module: &'b ModuleFacts,
        scope: usize,
        at: TextSize,
        reference: &RefExpr,
        visited: &mut Vec<(String, usize)>,
    ) -> Option<(&'b ModuleFacts, usize, &'b ValueFact)> {
        match reference {
            RefExpr::Name(name) => module
                .lookup_binding_with_scope(scope, name, at)
                .map(|(binding_scope, value)| (module, binding_scope, value)),
            RefExpr::Attribute(base, attribute) => {
                let module_name =
                    self.resolve_module_reference(module, scope, at, base, visited)?;
                let target = self.module(&module_name)?;
                target
                    .module_binding(attribute)
                    .map(|value| (target, 0, value))
            }
            RefExpr::Module(_) => None,
        }
    }

    fn resolve_reference(
        &self,
        module: &ModuleFacts,
        scope: usize,
        at: TextSize,
        reference: &RefExpr,
        visited: &mut Vec<(String, usize)>,
    ) -> SymbolResolution {
        match reference {
            RefExpr::Name(name) => {
                let marker = (format!("\0alias:{}::{name}", module.name), usize::MAX);
                if visited.contains(&marker) {
                    return SymbolResolution::Unknown;
                }
                visited.push(marker.clone());
                let result = match module.lookup_binding_with_scope(scope, name, at) {
                    Some((binding_scope, value)) => {
                        self.resolve_value(module, binding_scope, at, value, visited)
                    }
                    None => SymbolResolution::Unknown,
                };
                visited.pop();
                result
            }
            RefExpr::Module(name) => self.resolve_module_name(name),
            RefExpr::Attribute(base, attribute) => {
                let Some(module_name) =
                    self.resolve_module_reference(module, scope, at, base, visited)
                else {
                    return match self.resolve_reference(module, scope, at, base, visited) {
                        SymbolResolution::Unknown => SymbolResolution::Unknown,
                        _ => SymbolResolution::Other,
                    };
                };
                self.resolve_module_member(&module_name, attribute, visited)
            }
        }
    }

    fn resolve_value(
        &self,
        module: &ModuleFacts,
        scope: usize,
        at: TextSize,
        value: &ValueFact,
        visited: &mut Vec<(String, usize)>,
    ) -> SymbolResolution {
        match value {
            ValueFact::Module(name) => self.resolve_module_name(name),
            ValueFact::Symbol(symbol) => self.resolve_symbol(module, *symbol, visited),
            ValueFact::Reference(reference) => {
                self.resolve_reference(module, scope, at, reference, visited)
            }
            ValueFact::Collection(..) | ValueFact::Call(..) | ValueFact::Unknown => {
                SymbolResolution::Unknown
            }
        }
    }

    fn resolve_module_reference(
        &self,
        module: &ModuleFacts,
        scope: usize,
        at: TextSize,
        reference: &RefExpr,
        visited: &mut Vec<(String, usize)>,
    ) -> Option<String> {
        let mut reference_stack = Vec::new();
        self.resolve_module_reference_inner(
            module,
            scope,
            at,
            reference,
            visited,
            &mut reference_stack,
        )
    }

    fn resolve_module_reference_inner(
        &self,
        module: &ModuleFacts,
        scope: usize,
        at: TextSize,
        reference: &RefExpr,
        visited: &mut Vec<(String, usize)>,
        reference_stack: &mut Vec<(String, String)>,
    ) -> Option<String> {
        match reference {
            RefExpr::Module(name) => Some(name.clone()),
            RefExpr::Name(name) => {
                let marker = (module.name.clone(), name.clone());
                if reference_stack.contains(&marker) {
                    return None;
                }
                reference_stack.push(marker);
                let result = match module.lookup_binding_with_scope(scope, name, at) {
                    Some((_, ValueFact::Module(module_name))) => Some(module_name.clone()),
                    Some((binding_scope, ValueFact::Reference(alias))) => self
                        .resolve_module_reference_inner(
                            module,
                            binding_scope,
                            at,
                            alias,
                            visited,
                            reference_stack,
                        ),
                    _ => None,
                };
                reference_stack.pop();
                result
            }
            RefExpr::Attribute(base, attribute) => {
                let parent = self.resolve_module_reference_inner(
                    module,
                    scope,
                    at,
                    base,
                    visited,
                    reference_stack,
                )?;
                let candidate = format!("{parent}.{attribute}");
                if self.module_exists(&candidate) || Self::looks_like_known_module(&candidate) {
                    Some(candidate)
                } else {
                    self.resolve_module_member_alias(&parent, attribute, visited, reference_stack)
                }
            }
        }
    }
    fn resolve_module_member_alias(
        &self,
        parent: &str,
        attribute: &str,
        visited: &mut Vec<(String, usize)>,
        reference_stack: &mut Vec<(String, String)>,
    ) -> Option<String> {
        let marker = (format!("\0member:{parent}"), attribute.to_string());
        if reference_stack.contains(&marker) {
            return None;
        }
        reference_stack.push(marker);
        let Some(module) = self.module(parent) else {
            reference_stack.pop();
            return None;
        };
        let Some(value) = module.module_binding(attribute) else {
            reference_stack.pop();
            return None;
        };
        let result = match value {
            ValueFact::Module(module_name) => Some(module_name.clone()),
            ValueFact::Reference(alias) => self.resolve_module_reference_inner(
                module,
                0,
                TextSize::new(u32::MAX),
                alias,
                visited,
                reference_stack,
            ),
            _ => None,
        };
        reference_stack.pop();
        result
    }

    fn resolve_symbol(
        &self,
        module: &ModuleFacts,
        symbol: usize,
        visited: &mut Vec<(String, usize)>,
    ) -> SymbolResolution {
        let Some(SymbolFact::Class {
            bases, scope, at, ..
        }) = module.symbols.get(symbol)
        else {
            return SymbolResolution::Other;
        };
        let marker = (module.name.clone(), symbol);
        if visited.contains(&marker) {
            return SymbolResolution::Unknown;
        }
        visited.push(marker.clone());
        let mut unknown = false;
        let mut target = false;
        for base in bases {
            match self.resolve_reference(module, *scope, *at, base, visited) {
                SymbolResolution::GraphqlView => target = true,
                SymbolResolution::Unknown => unknown = true,
                SymbolResolution::GraphqlDepthValidator
                | SymbolResolution::SqlAlchemy
                | SymbolResolution::SafeValidation
                | SymbolResolution::User
                | SymbolResolution::Other => {}
            }
        }
        visited.pop();
        if target {
            SymbolResolution::GraphqlView
        } else if unknown {
            SymbolResolution::Unknown
        } else {
            SymbolResolution::User
        }
    }

    fn resolve_module_name(&self, name: &str) -> SymbolResolution {
        if self.module_exists(name) || Self::looks_like_known_module(name) {
            SymbolResolution::Other
        } else {
            SymbolResolution::Unknown
        }
    }

    fn resolve_module_member(
        &self,
        module_name: &str,
        attribute: &str,
        visited: &mut Vec<(String, usize)>,
    ) -> SymbolResolution {
        if let Some(module) = self.module(module_name)
            && let Some(value) = module.module_binding(attribute)
        {
            return self.resolve_value(module, 0, TextSize::new(u32::MAX), value, visited);
        }
        let fqn = format!("{module_name}.{attribute}");
        known_module_member_resolution(&fqn).unwrap_or_else(|| {
            if self.module_exists(&fqn) {
                SymbolResolution::Other
            } else {
                SymbolResolution::Unknown
            }
        })
    }

    fn looks_like_known_module(name: &str) -> bool {
        GRAPHQL_VIEW_FQNS
            .iter()
            .chain(GRAPHQL_DEPTH_VALIDATOR_FQNS.iter())
            .chain(SQLALCHEMY_FQNS.iter())
            .chain(SAFE_VALIDATION_RULE_FQNS.iter())
            .any(|fqn| *fqn == name || fqn.starts_with(&format!("{name}.")))
    }

    fn module(&self, name: &str) -> Option<&ModuleFacts> {
        if self.current.name == name {
            Some(self.current)
        } else {
            self.project.modules.get(name)
        }
    }

    fn module_exists(&self, name: &str) -> bool {
        self.module(name).is_some()
    }
}
fn known_module_member_resolution(fqn: &str) -> Option<SymbolResolution> {
    match fqn {
        "flask_graphql.GraphQLView" | "graphql_server.flask.GraphQLView" => {
            Some(SymbolResolution::GraphqlView)
        }
        "graphene.validation.depth_limit_validator" => {
            Some(SymbolResolution::GraphqlDepthValidator)
        }
        "flask_sqlalchemy.SQLAlchemy" => Some(SymbolResolution::SqlAlchemy),
        "graphene.validation.DisableIntrospection"
        | "graphql.validation.NoSchemaIntrospectionCustomRule" => {
            Some(SymbolResolution::SafeValidation)
        }
        _ => None,
    }
}

fn symbol_safety(module: &ModuleFacts, symbol: usize) -> GraphqlSafety {
    match module.symbols.get(symbol) {
        Some(SymbolFact::Class { name, .. })
            if name.to_ascii_uppercase().contains("INTROSPECTION") =>
        {
            GraphqlSafety::Safe
        }
        _ => GraphqlSafety::Unsafe,
    }
}

fn bound_value_is_safe(module: &ModuleFacts, value: &ValueFact) -> bool {
    match value {
        ValueFact::Symbol(symbol) => symbol_safety(module, *symbol) == GraphqlSafety::Safe,
        ValueFact::Call(Some(callee)) => reference_contains_introspection(callee),
        _ => false,
    }
}

pub(crate) fn build_module_facts(module_name: &str, parsed: &Parsed<ModModule>) -> ModuleFacts {
    let end = parsed
        .syntax()
        .body
        .last()
        .map_or(TextSize::new(0), Ranged::end);
    let mut facts = ModuleFacts {
        name: module_name.to_string(),
        scopes: vec![ScopeFacts {
            parent: None,
            kind: ScopeKind::Module,
            range: TextRange::new(TextSize::new(0), end),
            bindings: Vec::new(),
        }],
        symbols: Vec::new(),
    };
    collect_suite(&mut facts, 0, parsed.syntax().body.as_slice());
    facts
}

fn collect_suite(facts: &mut ModuleFacts, scope: usize, suite: &[Stmt]) {
    for statement in suite {
        collect_statement(facts, scope, statement);
    }
}

fn collect_statement(facts: &mut ModuleFacts, scope: usize, statement: &Stmt) {
    match statement {
        Stmt::Import(import) => collect_import(facts, scope, import, statement.start()),
        Stmt::ImportFrom(import) => collect_import_from(facts, scope, import, statement.start()),
        Stmt::FunctionDef(function) => collect_function(facts, scope, function, statement.start()),
        Stmt::ClassDef(class) => collect_class(facts, scope, class, statement.start()),
        Stmt::Assign(assign) => collect_assign(facts, scope, assign, statement.start()),
        Stmt::AnnAssign(assign) => collect_ann_assign(facts, scope, assign, statement.start()),
        Stmt::AugAssign(assign) => collect_aug_assign(facts, scope, assign, statement.start()),
        Stmt::TypeAlias(alias) => collect_type_alias(facts, scope, alias, statement.start()),
        Stmt::For(for_stmt) => collect_for(facts, scope, for_stmt, statement),
        Stmt::With(with_stmt) => collect_with(facts, scope, with_stmt, statement),
        Stmt::Delete(delete_stmt) => collect_delete(facts, scope, delete_stmt, statement.start()),
        _ => collect_child_bodies(facts, scope, statement),
    }
}
fn collect_import(
    facts: &mut ModuleFacts,
    scope: usize,
    import: &ruff_python_ast::StmtImport,
    at: TextSize,
) {
    for alias in &import.names {
        let full_name = alias.name.as_str().to_string();
        let local = alias.asname.as_ref().map_or_else(
            || {
                full_name
                    .split('.')
                    .next()
                    .unwrap_or(&full_name)
                    .to_string()
            },
            |name| name.as_str().to_string(),
        );
        let module_name = if alias.asname.is_some() {
            full_name
        } else {
            full_name
                .split('.')
                .next()
                .unwrap_or(&full_name)
                .to_string()
        };
        bind(facts, scope, &local, ValueFact::Module(module_name), at);
    }
}

fn collect_import_from(
    facts: &mut ModuleFacts,
    scope: usize,
    import: &ruff_python_ast::StmtImportFrom,
    at: TextSize,
) {
    let module_name = relative_module_name(&facts.name, import.level, import.module.as_deref());
    for alias in &import.names {
        if alias.name.as_str() == "*" {
            continue;
        }
        let local = alias
            .asname
            .as_ref()
            .map_or_else(|| alias.name.as_str(), |name| name.as_str());
        bind(
            facts,
            scope,
            local,
            ValueFact::Reference(RefExpr::Attribute(
                Box::new(RefExpr::Module(module_name.clone())),
                alias.name.as_str().to_string(),
            )),
            at,
        );
    }
}

fn collect_function(
    facts: &mut ModuleFacts,
    scope: usize,
    function: &ruff_python_ast::StmtFunctionDef,
    at: TextSize,
) {
    bind(facts, scope, function.name.as_str(), ValueFact::Unknown, at);
    let child = new_scope(facts, scope, ScopeKind::Function, function.range());
    collect_parameters(facts, child, function);
    collect_suite(facts, child, function.body.as_slice());
}

fn collect_parameters(
    facts: &mut ModuleFacts,
    scope: usize,
    function: &ruff_python_ast::StmtFunctionDef,
) {
    for parameter in function
        .parameters
        .posonlyargs
        .iter()
        .chain(function.parameters.args.iter())
        .chain(function.parameters.kwonlyargs.iter())
    {
        bind(
            facts,
            scope,
            parameter.name().as_str(),
            ValueFact::Unknown,
            function.start(),
        );
    }
    if let Some(parameter) = &function.parameters.vararg {
        bind(
            facts,
            scope,
            parameter.name.as_str(),
            ValueFact::Unknown,
            function.start(),
        );
    }
    if let Some(parameter) = &function.parameters.kwarg {
        bind(
            facts,
            scope,
            parameter.name.as_str(),
            ValueFact::Unknown,
            function.start(),
        );
    }
}

fn collect_class(
    facts: &mut ModuleFacts,
    scope: usize,
    class: &ruff_python_ast::StmtClassDef,
    at: TextSize,
) {
    let symbol = facts.symbols.len();
    facts.symbols.push(SymbolFact::Class {
        name: class.name.as_str().to_string(),
        bases: class.bases().iter().filter_map(ref_expr).collect(),
        scope,
        at: class.start(),
    });
    bind(
        facts,
        scope,
        class.name.as_str(),
        ValueFact::Symbol(symbol),
        at,
    );
    let child = new_scope(facts, scope, ScopeKind::Class, class.range());
    collect_suite(facts, child, class.body.as_slice());
}

fn collect_assign(
    facts: &mut ModuleFacts,
    scope: usize,
    assign: &ruff_python_ast::StmtAssign,
    at: TextSize,
) {
    let value = value_fact(assign.value.as_ref());
    for target in &assign.targets {
        bind_target(facts, scope, target, value.clone(), at);
    }
}

fn collect_ann_assign(
    facts: &mut ModuleFacts,
    scope: usize,
    assign: &ruff_python_ast::StmtAnnAssign,
    at: TextSize,
) {
    let value = assign
        .value
        .as_deref()
        .map_or(ValueFact::Unknown, value_fact);
    bind_target(facts, scope, assign.target.as_ref(), value, at);
}

fn collect_aug_assign(
    facts: &mut ModuleFacts,
    scope: usize,
    assign: &ruff_python_ast::StmtAugAssign,
    at: TextSize,
) {
    bind_target(facts, scope, assign.target.as_ref(), ValueFact::Unknown, at);
}

fn collect_type_alias(
    facts: &mut ModuleFacts,
    scope: usize,
    alias: &ruff_python_ast::StmtTypeAlias,
    at: TextSize,
) {
    bind_target(
        facts,
        scope,
        alias.name.as_ref(),
        value_fact(alias.value.as_ref()),
        at,
    );
}

fn collect_for(
    facts: &mut ModuleFacts,
    scope: usize,
    for_stmt: &ruff_python_ast::StmtFor,
    statement: &Stmt,
) {
    bind_target(
        facts,
        scope,
        for_stmt.target.as_ref(),
        ValueFact::Unknown,
        statement.start(),
    );
    collect_child_bodies(facts, scope, statement);
}

fn collect_with(
    facts: &mut ModuleFacts,
    scope: usize,
    with_stmt: &ruff_python_ast::StmtWith,
    statement: &Stmt,
) {
    for item in &with_stmt.items {
        if let Some(target) = item.optional_vars.as_deref() {
            bind_target(facts, scope, target, ValueFact::Unknown, statement.start());
        }
    }
    collect_child_bodies(facts, scope, statement);
}

fn collect_delete(
    facts: &mut ModuleFacts,
    scope: usize,
    delete_stmt: &ruff_python_ast::StmtDelete,
    at: TextSize,
) {
    for target in &delete_stmt.targets {
        bind_target(facts, scope, target, ValueFact::Unknown, at);
    }
}

fn collect_child_bodies(facts: &mut ModuleFacts, scope: usize, statement: &Stmt) {
    for body in child_bodies(statement) {
        collect_suite(facts, scope, body);
    }
}

fn new_scope(facts: &mut ModuleFacts, parent: usize, kind: ScopeKind, range: TextRange) -> usize {
    let id = facts.scopes.len();
    facts.scopes.push(ScopeFacts {
        parent: Some(parent),
        kind,
        range,
        bindings: Vec::new(),
    });
    id
}

fn bind(facts: &mut ModuleFacts, scope: usize, name: &str, value: ValueFact, at: TextSize) {
    facts.scopes[scope].bindings.push(BindingFact {
        name: name.to_string(),
        value,
        at,
    });
}

fn bind_target(
    facts: &mut ModuleFacts,
    scope: usize,
    target: &Expr,
    value: ValueFact,
    at: TextSize,
) {
    match target {
        Expr::Name(name) => bind(facts, scope, name.id.as_str(), value, at),
        Expr::Starred(starred) => bind_target(facts, scope, starred.value.as_ref(), value, at),
        Expr::List(list) => {
            for target in &list.elts {
                bind_target(facts, scope, target, ValueFact::Unknown, at);
            }
        }
        Expr::Tuple(tuple) => {
            for target in &tuple.elts {
                bind_target(facts, scope, target, ValueFact::Unknown, at);
            }
        }
        _ => {}
    }
}

fn value_fact(expression: &Expr) -> ValueFact {
    if let Some(reference) = ref_expr(expression) {
        return ValueFact::Reference(reference);
    }
    match expression {
        Expr::List(list) => ValueFact::Collection(
            CollectionKind::List,
            list.elts.iter().map(value_fact).collect(),
        ),
        Expr::Tuple(tuple) => ValueFact::Collection(
            CollectionKind::Tuple,
            tuple.elts.iter().map(value_fact).collect(),
        ),
        Expr::Set(set) => ValueFact::Collection(
            CollectionKind::Set,
            set.elts.iter().map(value_fact).collect(),
        ),
        Expr::Dict(_) | Expr::SetComp(_) | Expr::ListComp(_) | Expr::Generator(_) => {
            ValueFact::Collection(CollectionKind::Other, Vec::new())
        }
        Expr::Call(call) => ValueFact::Call(ref_expr(&call.func)),
        Expr::Starred(starred) => value_fact(starred.value.as_ref()),
        Expr::Named(named) => value_fact(named.value.as_ref()),
        _ => ValueFact::Unknown,
    }
}

fn ref_expr(expression: &Expr) -> Option<RefExpr> {
    match expression {
        Expr::Name(name) => Some(RefExpr::Name(name.id.as_str().to_string())),
        Expr::Attribute(attribute) => Some(RefExpr::Attribute(
            Box::new(ref_expr(attribute.value.as_ref())?),
            attribute.attr.as_str().to_string(),
        )),
        Expr::Starred(starred) => ref_expr(starred.value.as_ref()),
        Expr::Named(named) => ref_expr(named.value.as_ref()),
        _ => None,
    }
}

fn reference_contains_introspection(reference: &RefExpr) -> bool {
    reference_text(reference)
        .to_ascii_uppercase()
        .contains("INTROSPECTION")
}

fn reference_text(reference: &RefExpr) -> String {
    match reference {
        RefExpr::Name(name) | RefExpr::Module(name) => name.clone(),
        RefExpr::Attribute(base, attribute) => format!("{}.{}", reference_text(base), attribute),
    }
}

fn relative_module_name(current: &str, level: u32, module: Option<&str>) -> String {
    if level == 0 {
        return module.unwrap_or_default().to_string();
    }
    let mut parts: Vec<&str> = current.split('.').collect();
    parts.pop();
    for _ in 1..level {
        parts.pop();
    }
    if let Some(module) = module
        && !module.is_empty()
    {
        parts.extend(module.split('.'));
    }
    parts.join(".")
}

fn normalize_module_name(name: &str) -> String {
    name.replace(['/', '\\'], ".")
        .trim_start_matches('.')
        .strip_suffix(".py")
        .unwrap_or(name)
        .trim_matches('.')
        .to_string()
}

pub(crate) fn module_name_from_path(path: &Path) -> String {
    let mut name = path.to_string_lossy().replace(['/', '\\'], ".");
    if let Some(stripped) = name.strip_suffix(".py") {
        name = stripped.to_string();
    }
    if name.ends_with(".__init__") {
        name.truncate(name.len() - ".__init__".len());
    }
    normalize_module_name(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_module_names_strip_init_and_extension() {
        assert_eq!(
            module_name_from_path(Path::new("pkg/views.py")),
            "pkg.views"
        );
        assert_eq!(module_name_from_path(Path::new("pkg/__init__.py")), "pkg");
    }

    #[test]
    fn relative_imports_resolve_against_current_package() {
        assert_eq!(
            relative_module_name("pkg.views", 1, Some("base")),
            "pkg.base"
        );
        assert_eq!(
            relative_module_name("pkg.sub.views", 2, Some("base")),
            "pkg.base"
        );
    }
}
