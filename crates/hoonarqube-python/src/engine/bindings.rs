use crate::support::{child_bodies, collect_target_names, named_parameters, stmt_store_names};
use ruff_python_ast::{Expr, ExprCall, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_text_size::{Ranged, TextRange, TextSize};
use std::collections::HashMap;

/// A conservative identity for standard-library callables used by the rules
/// whose diagnostics depend on API provenance rather than the final attribute
/// name. `Unknown` is intentionally distinct from an unresolved builtin name:
/// any local binding wins over Python's builtin fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KnownBinding {
    Unknown,
    BuiltinsModule,
    BuiltinEval,
    BuiltinExec,
    OsModule,
    OsSystem,
    OsPopen,
    SubprocessModule,
    SubprocessRun,
    SubprocessPopen,
    SubprocessCall,
    SubprocessCheckCall,
    SubprocessCheckOutput,
    SubprocessGetoutput,
    SubprocessGetstatusoutput,
    AsyncioModule,
    AsyncioCreateTask,
    AsyncioEnsureFuture,
    AsyncioTaskGroup,
}

#[derive(Clone, Copy)]
struct Binding {
    value: KnownBinding,
    range: TextRange,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Function,
    Class,
}

struct Scope {
    kind: ScopeKind,
    parent: Option<usize>,
    range: TextRange,
    bindings: HashMap<String, Vec<Binding>>,
}

/// Minimal lexical binding facts for standard-library identities. This is not
/// a general type checker: it only tracks imports, local definitions, and
/// straightforward aliases, which is enough to avoid guessing from a method's
/// spelling while preserving conservative unknown-call behavior.
pub(crate) struct KnownBindings {
    scopes: Vec<Scope>,
}

impl KnownBindings {
    pub(crate) fn build(parsed: &Parsed<ModModule>) -> Self {
        let mut facts = Self {
            scopes: vec![Scope {
                kind: ScopeKind::Module,
                parent: None,
                range: parsed.syntax().range(),
                bindings: HashMap::new(),
            }],
        };
        facts.record_suite(0, parsed.syntax().body.as_slice());
        facts
    }

    /// Resolves a call's target identity at the call's source position.
    pub(crate) fn resolve_call(&self, call: &ExprCall) -> KnownBinding {
        self.resolve_expr(&call.func, call.range())
    }

    fn record_suite(&mut self, scope: usize, statements: &[Stmt]) {
        for statement in statements {
            self.record_statement(scope, statement);
        }
    }

    fn record_statement(&mut self, scope: usize, statement: &Stmt) {
        match statement {
            Stmt::Import(import) => self.record_import(scope, import),
            Stmt::ImportFrom(import) => self.record_import_from(scope, import),
            Stmt::FunctionDef(function) => self.record_function(scope, statement, function),
            Stmt::ClassDef(class) => self.record_class(scope, statement, class),
            Stmt::Assign(assign) => {
                let value = self.resolve_expr_in_scope(scope, &assign.value);
                for target in &assign.targets {
                    self.bind_assignment_targets(scope, target, value, statement.range());
                }
                self.record_nested_bodies(scope, statement);
            }
            Stmt::AnnAssign(assign) => {
                let value = assign
                    .value
                    .as_deref()
                    .map_or(KnownBinding::Unknown, |value| {
                        self.resolve_expr_in_scope(scope, value)
                    });
                self.bind_assignment_targets(scope, &assign.target, value, statement.range());
                self.record_nested_bodies(scope, statement);
            }
            Stmt::AugAssign(assign) => {
                let activation = self.activation_range(scope, statement.range());
                self.bind_targets(scope, &assign.target, KnownBinding::Unknown, activation);
                self.record_nested_bodies(scope, statement);
            }
            _ => {
                let activation = self.activation_range(scope, statement.range());
                for name in stmt_store_names(statement) {
                    self.bind(scope, &name, KnownBinding::Unknown, activation);
                }
                self.record_nested_bodies(scope, statement);
            }
        }
    }

    fn record_import(&mut self, scope: usize, import: &ruff_python_ast::StmtImport) {
        for alias in &import.names {
            let local = alias.asname.as_deref().map_or_else(
                || {
                    alias
                        .name
                        .as_str()
                        .split('.')
                        .next()
                        .unwrap_or("")
                        .to_string()
                },
                str::to_string,
            );
            let value = module_binding(alias.name.as_str());
            self.bind(scope, &local, value, alias.range());
        }
    }

    fn record_import_from(&mut self, scope: usize, import: &ruff_python_ast::StmtImportFrom) {
        let module = import
            .module
            .as_ref()
            .filter(|_| import.level == 0)
            .map(ruff_python_ast::Identifier::as_str);
        for alias in &import.names {
            let local = alias
                .asname
                .as_deref()
                .map_or_else(|| alias.name.as_str().to_string(), str::to_string);
            let value = from_import_binding(module, alias.name.as_str());
            self.bind(scope, &local, value, alias.range());
        }
    }

    fn record_function(
        &mut self,
        scope: usize,
        statement: &Stmt,
        function: &ruff_python_ast::StmtFunctionDef,
    ) {
        self.bind(
            scope,
            function.name.as_str(),
            KnownBinding::Unknown,
            self.activation_range(scope, statement.range()),
        );
        let child = self.push_scope(
            ScopeKind::Function,
            scope,
            scope_body_range(&function.body, function.range()),
        );
        for parameter in named_parameters(&function.parameters) {
            self.bind(
                child,
                parameter.parameter.name.as_str(),
                KnownBinding::Unknown,
                parameter.parameter.name.range(),
            );
        }
        for parameter in [
            function.parameters.vararg.as_deref(),
            function.parameters.kwarg.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            self.bind(
                child,
                parameter.name.as_str(),
                KnownBinding::Unknown,
                parameter.name.range(),
            );
        }
        self.record_suite(child, &function.body);
    }

    fn record_class(
        &mut self,
        scope: usize,
        statement: &Stmt,
        class: &ruff_python_ast::StmtClassDef,
    ) {
        self.bind(
            scope,
            class.name.as_str(),
            KnownBinding::Unknown,
            self.activation_range(scope, statement.range()),
        );
        let child = self.push_scope(
            ScopeKind::Class,
            scope,
            scope_body_range(&class.body, class.range()),
        );
        self.record_suite(child, &class.body);
    }

    fn record_nested_bodies(&mut self, scope: usize, statement: &Stmt) {
        for body in child_bodies(statement) {
            self.record_suite(scope, body);
        }
    }

    fn bind_targets(&mut self, scope: usize, target: &Expr, value: KnownBinding, range: TextRange) {
        let mut names = Vec::new();
        collect_target_names(target, &mut names);
        for name in names {
            self.bind(scope, &name, value, range);
        }
    }

    fn bind(&mut self, scope: usize, name: &str, value: KnownBinding, range: TextRange) {
        self.scopes[scope]
            .bindings
            .entry(name.to_string())
            .or_default()
            .push(Binding { value, range });
    }

    fn bind_assignment_targets(
        &mut self,
        scope: usize,
        target: &Expr,
        value: KnownBinding,
        statement: TextRange,
    ) {
        if self.scopes[scope].kind == ScopeKind::Function {
            let lexical = self.activation_range(scope, statement);
            self.bind_targets(scope, target, KnownBinding::Unknown, lexical);
        }
        let end = TextRange::new(statement.end(), statement.end());
        self.bind_targets(scope, target, value, end);
    }

    fn activation_range(&self, scope: usize, statement: TextRange) -> TextRange {
        if self.scopes[scope].kind == ScopeKind::Function {
            let start = self.scopes[scope].range.start();
            TextRange::new(start, start)
        } else {
            let end = statement.end();
            TextRange::new(end, end)
        }
    }

    fn push_scope(&mut self, kind: ScopeKind, parent: usize, range: TextRange) -> usize {
        self.scopes.push(Scope {
            kind,
            parent: Some(parent),
            range,
            bindings: HashMap::new(),
        });
        self.scopes.len() - 1
    }

    fn resolve_expr(&self, expr: &Expr, _at: TextRange) -> KnownBinding {
        let scope = self.scope_for(expr.range());
        self.resolve_expr_in_scope(scope, expr)
    }

    fn resolve_expr_in_scope(&self, scope: usize, expr: &Expr) -> KnownBinding {
        match expr {
            Expr::Name(name) => self.resolve_name(scope, name.id.as_str(), expr.range().start()),
            Expr::Attribute(attribute) => {
                let base = self.resolve_expr_in_scope(scope, attribute.value.as_ref());
                attribute_binding(base, attribute.attr.as_str())
            }
            _ => KnownBinding::Unknown,
        }
    }

    fn resolve_name(&self, scope: usize, name: &str, position: TextSize) -> KnownBinding {
        if let Some(value) = self.binding_at(scope, name, position) {
            return value;
        }
        if self.scopes[scope].kind != ScopeKind::Module
            && self.scopes[scope].bindings.contains_key(name)
        {
            return KnownBinding::Unknown;
        }
        self.resolve_parent_or_fallback(scope, name, position)
    }

    fn binding_at(&self, scope: usize, name: &str, position: TextSize) -> Option<KnownBinding> {
        self.scopes[scope]
            .bindings
            .get(name)?
            .iter()
            .filter(|binding| binding.range.start() <= position)
            .max_by_key(|binding| binding.range.start())
            .map(|binding| binding.value)
    }

    fn resolve_parent_or_fallback(
        &self,
        scope: usize,
        name: &str,
        position: TextSize,
    ) -> KnownBinding {
        let Some(parent) = self.lexical_parent(scope) else {
            return fallback_binding(name);
        };
        let parent_position = if self.scopes[scope].kind == ScopeKind::Function {
            self.scopes[scope].range.end()
        } else {
            position
        };
        let parent_value = self.resolve_name(parent, name, parent_position);
        if parent_value != KnownBinding::Unknown {
            return parent_value;
        }
        if self.scopes[scope].kind != ScopeKind::Module && self.has_binding_in_chain(scope, name) {
            KnownBinding::Unknown
        } else {
            fallback_binding(name)
        }
    }

    fn lexical_parent(&self, scope: usize) -> Option<usize> {
        let mut parent = self.scopes[scope].parent;
        if self.scopes[scope].kind == ScopeKind::Function {
            while let Some(parent_index) = parent {
                if self.scopes[parent_index].kind != ScopeKind::Class {
                    break;
                }
                parent = self.scopes[parent_index].parent;
            }
        }
        parent
    }

    fn has_binding_in_chain(&self, scope: usize, name: &str) -> bool {
        self.scopes[scope].bindings.contains_key(name)
            || self
                .lexical_parent(scope)
                .is_some_and(|parent| self.has_binding_in_chain(parent, name))
    }
    fn scope_for(&self, range: TextRange) -> usize {
        self.scopes
            .iter()
            .enumerate()
            .filter(|(_, scope)| {
                scope.range.start() <= range.start() && range.end() <= scope.range.end()
            })
            .min_by_key(|(_, scope)| u32::from(scope.range.end()) - u32::from(scope.range.start()))
            .map_or(0, |(index, _)| index)
    }
}

fn scope_body_range(body: &[Stmt], fallback: TextRange) -> TextRange {
    body.first()
        .zip(body.last())
        .map_or(fallback, |(first, last)| {
            TextRange::new(first.range().start(), last.range().end())
        })
}

fn module_binding(module: &str) -> KnownBinding {
    match module {
        "builtins" => KnownBinding::BuiltinsModule,
        "os" => KnownBinding::OsModule,
        "subprocess" => KnownBinding::SubprocessModule,
        "asyncio" => KnownBinding::AsyncioModule,
        _ => KnownBinding::Unknown,
    }
}

fn from_import_binding(module: Option<&str>, name: &str) -> KnownBinding {
    match (module, name) {
        (Some("builtins"), "eval") => KnownBinding::BuiltinEval,
        (Some("builtins"), "exec") => KnownBinding::BuiltinExec,
        (Some("os"), "system") => KnownBinding::OsSystem,
        (Some("os"), "popen") => KnownBinding::OsPopen,
        (Some("subprocess"), "run") => KnownBinding::SubprocessRun,
        (Some("subprocess"), "Popen") => KnownBinding::SubprocessPopen,
        (Some("subprocess"), "call") => KnownBinding::SubprocessCall,
        (Some("subprocess"), "check_call") => KnownBinding::SubprocessCheckCall,
        (Some("subprocess"), "check_output") => KnownBinding::SubprocessCheckOutput,
        (Some("subprocess"), "getoutput") => KnownBinding::SubprocessGetoutput,
        (Some("subprocess"), "getstatusoutput") => KnownBinding::SubprocessGetstatusoutput,
        (Some("asyncio"), "create_task") => KnownBinding::AsyncioCreateTask,
        (Some("asyncio"), "ensure_future") => KnownBinding::AsyncioEnsureFuture,
        (Some("asyncio"), "TaskGroup") => KnownBinding::AsyncioTaskGroup,
        _ => KnownBinding::Unknown,
    }
}

fn fallback_binding(name: &str) -> KnownBinding {
    match name {
        "builtins" => KnownBinding::BuiltinsModule,
        "os" => KnownBinding::OsModule,
        "subprocess" => KnownBinding::SubprocessModule,
        "asyncio" => KnownBinding::AsyncioModule,
        "eval" => KnownBinding::BuiltinEval,
        "exec" => KnownBinding::BuiltinExec,
        _ => KnownBinding::Unknown,
    }
}

fn attribute_binding(base: KnownBinding, attribute: &str) -> KnownBinding {
    match (base, attribute) {
        (KnownBinding::BuiltinsModule, "eval") => KnownBinding::BuiltinEval,
        (KnownBinding::BuiltinsModule, "exec") => KnownBinding::BuiltinExec,
        (KnownBinding::OsModule, "system") => KnownBinding::OsSystem,
        (KnownBinding::OsModule, "popen") => KnownBinding::OsPopen,
        (KnownBinding::SubprocessModule, "run") => KnownBinding::SubprocessRun,
        (KnownBinding::SubprocessModule, "Popen") => KnownBinding::SubprocessPopen,
        (KnownBinding::SubprocessModule, "call") => KnownBinding::SubprocessCall,
        (KnownBinding::SubprocessModule, "check_call") => KnownBinding::SubprocessCheckCall,
        (KnownBinding::SubprocessModule, "check_output") => KnownBinding::SubprocessCheckOutput,
        (KnownBinding::SubprocessModule, "getoutput") => KnownBinding::SubprocessGetoutput,
        (KnownBinding::SubprocessModule, "getstatusoutput") => {
            KnownBinding::SubprocessGetstatusoutput
        }
        (KnownBinding::AsyncioModule, "create_task") => KnownBinding::AsyncioCreateTask,
        (KnownBinding::AsyncioModule, "ensure_future") => KnownBinding::AsyncioEnsureFuture,
        (KnownBinding::AsyncioModule, "TaskGroup") => KnownBinding::AsyncioTaskGroup,
        _ => KnownBinding::Unknown,
    }
}
