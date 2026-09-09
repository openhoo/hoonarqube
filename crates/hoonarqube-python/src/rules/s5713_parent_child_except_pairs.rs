use crate::support::{
    child_bodies, collect_target_names, for_each_stmt, issue_at, named_parameters, stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{
    ExceptHandler, Expr, ModModule, Stmt, StmtClassDef, StmtFunctionDef, StmtImport, StmtImportFrom,
};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};
use std::collections::HashMap;
use std::collections::HashSet;

/// python:S5713 — flags except-tuples listing both a parent and its subclass,
/// or the same exception twice. Known standard-library identities are resolved
/// conservatively; arbitrary external classes remain unknown.
pub(crate) fn check_s5713_parent_child_except_pairs(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let module = parsed.syntax().body.as_slice();
    let environment = ExceptionEnvironment::build(module, parsed.syntax().range());
    let mut issues = Vec::new();
    for_each_stmt(module, &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else {
            return;
        };
        for handler in &try_stmt.handlers {
            if let Some(issue) = redundant_except_issue(handler, &environment, index, source) {
                issues.push(issue);
            }
        }
    });
    issues
}

fn redundant_except_issue(
    handler: &ExceptHandler,
    environment: &ExceptionEnvironment,
    index: &LineIndex,
    source: &str,
) -> Option<Issue> {
    let ExceptHandler::ExceptHandler(inner) = handler;
    let Expr::Tuple(tuple) = inner.type_.as_deref()? else {
        return None;
    };
    let entries: Vec<(ExceptionIdentity, TextRange)> = tuple
        .elts
        .iter()
        .map(|element| (environment.resolve_expr(element), element.range()))
        .collect();
    let redundant = redundant_entry_index(&entries, environment)?;
    Some(issue_at(
        "python:S5713",
        "Remove this redundant Exception class; it derives from another which is already caught.",
        entries[redundant].1,
        index,
        source,
    ))
}

fn redundant_entry_index(
    entries: &[(ExceptionIdentity, TextRange)],
    environment: &ExceptionEnvironment,
) -> Option<usize> {
    for (index, (identity, _)) in entries.iter().enumerate() {
        if !identity.is_unknown()
            && entries[..index]
                .iter()
                .any(|(previous, _)| previous == identity)
        {
            return Some(index);
        }
    }
    for (child_index, (child, _)) in entries.iter().enumerate() {
        if child.is_unknown() {
            continue;
        }
        for (parent_index, (parent, _)) in entries.iter().enumerate() {
            if child_index == parent_index || parent.is_unknown() {
                continue;
            }
            if environment.is_ancestor(child, parent) {
                return Some(child_index);
            }
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ExceptionIdentity {
    Known(String),
    Local(usize),
    Module(String),
    Unknown,
}

impl ExceptionIdentity {
    fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown | Self::Module(_))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Function,
    Class,
}

struct Binding {
    identity: ExceptionIdentity,
    activation: TextSize,
}

struct Scope {
    kind: ScopeKind,
    parent: Option<usize>,
    range: TextRange,
    bindings: HashMap<String, Vec<Binding>>,
}

struct ExceptionEnvironment {
    scopes: Vec<Scope>,
    classes: HashMap<usize, Vec<ExceptionIdentity>>,
    next_class: usize,
}

impl ExceptionEnvironment {
    fn build(module: &[Stmt], module_range: TextRange) -> Self {
        let mut environment = Self {
            scopes: vec![Scope {
                kind: ScopeKind::Module,
                parent: None,
                range: module_range,
                bindings: HashMap::new(),
            }],
            classes: HashMap::new(),
            next_class: 0,
        };
        environment.record_suite(0, module);
        environment
    }

    fn record_suite(&mut self, scope: usize, statements: &[Stmt]) {
        for statement in statements {
            self.record_statement(scope, statement);
        }
    }

    fn record_statement(&mut self, scope: usize, statement: &Stmt) {
        match statement {
            Stmt::Import(import) => self.record_import(scope, import, statement.range().end()),
            Stmt::ImportFrom(import) => {
                self.record_import_from(scope, import, statement.range().end());
            }
            Stmt::FunctionDef(function) => {
                self.record_function(scope, function, statement.range().end());
            }
            Stmt::ClassDef(class) => self.record_class(scope, class, statement.range().end()),
            Stmt::Assign(assign) => {
                let value = self.resolve_expr_in_scope(scope, &assign.value);
                for target in &assign.targets {
                    self.bind_assignment_targets(scope, target, &value, statement.range());
                }
                self.record_nested_bodies(scope, statement);
            }
            Stmt::AnnAssign(assign) => {
                let value = assign
                    .value
                    .as_deref()
                    .map_or(ExceptionIdentity::Unknown, |value| {
                        self.resolve_expr_in_scope(scope, value)
                    });
                self.bind_assignment_targets(scope, &assign.target, &value, statement.range());
                self.record_nested_bodies(scope, statement);
            }
            Stmt::AugAssign(assign) => {
                self.bind_store_names(
                    scope,
                    statement,
                    &assign.target,
                    &ExceptionIdentity::Unknown,
                );
                self.record_nested_bodies(scope, statement);
            }
            _ => {
                let activation = self.activation_for(scope, statement.range());
                for name in stmt_store_names(statement) {
                    self.bind(scope, &name, ExceptionIdentity::Unknown, activation);
                }
                self.record_nested_bodies(scope, statement);
            }
        }
    }

    fn record_import(&mut self, scope: usize, import: &StmtImport, activation: TextSize) {
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
            let module = alias
                .asname
                .as_deref()
                .map_or_else(|| local.clone(), |_| alias.name.as_str().to_string());
            self.bind(scope, &local, ExceptionIdentity::Module(module), activation);
        }
    }

    fn record_import_from(&mut self, scope: usize, import: &StmtImportFrom, activation: TextSize) {
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
            let identity = module
                .and_then(|module| Self::imported_identity(module, alias.name.as_str()))
                .unwrap_or_else(|| {
                    module.map_or(ExceptionIdentity::Unknown, |module| {
                        ExceptionIdentity::Module(format!("{module}.{}", alias.name))
                    })
                });
            self.bind(scope, &local, identity, activation);
        }
    }

    fn record_function(&mut self, scope: usize, function: &StmtFunctionDef, activation: TextSize) {
        self.bind(
            scope,
            function.name.as_str(),
            ExceptionIdentity::Unknown,
            activation,
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
                ExceptionIdentity::Unknown,
                parameter.parameter.name.range().start(),
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
                ExceptionIdentity::Unknown,
                parameter.name.range().start(),
            );
        }
        self.record_suite(child, &function.body);
    }

    fn record_class(&mut self, scope: usize, class: &StmtClassDef, activation: TextSize) {
        let class_id = self.next_class;
        self.next_class += 1;
        let bases = class
            .arguments
            .as_deref()
            .map(|arguments| {
                arguments
                    .args
                    .iter()
                    .map(|base| self.resolve_expr_in_scope(scope, base))
                    .collect()
            })
            .unwrap_or_default();
        self.classes.insert(class_id, bases);
        self.bind(
            scope,
            class.name.as_str(),
            ExceptionIdentity::Local(class_id),
            activation,
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

    fn bind_assignment_targets(
        &mut self,
        scope: usize,
        target: &Expr,
        value: &ExceptionIdentity,
        statement: TextRange,
    ) {
        let mut names = Vec::new();
        collect_target_names(target, &mut names);
        let end = statement.end();
        if self.scopes[scope].kind == ScopeKind::Function {
            let lexical = self.scopes[scope].range.start();
            for name in &names {
                self.bind(scope, name, ExceptionIdentity::Unknown, lexical);
            }
        }
        for name in names {
            self.bind(scope, &name, value.clone(), end);
        }
    }

    fn bind_store_names(
        &mut self,
        scope: usize,
        statement: &Stmt,
        target: &Expr,
        value: &ExceptionIdentity,
    ) {
        let mut names = Vec::new();
        collect_target_names(target, &mut names);
        let activation = self.activation_for(scope, statement.range());
        for name in names {
            self.bind(scope, &name, value.clone(), activation);
        }
    }

    fn activation_for(&self, scope: usize, statement: TextRange) -> TextSize {
        if self.scopes[scope].kind == ScopeKind::Function {
            self.scopes[scope].range.start()
        } else {
            statement.end()
        }
    }

    fn bind(
        &mut self,
        scope: usize,
        name: &str,
        identity: ExceptionIdentity,
        activation: TextSize,
    ) {
        self.scopes[scope]
            .bindings
            .entry(name.to_string())
            .or_default()
            .push(Binding {
                identity,
                activation,
            });
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

    fn resolve_expr(&self, expression: &Expr) -> ExceptionIdentity {
        let scope = self.scope_for(expression.range());
        self.resolve_expr_in_scope(scope, expression)
    }

    fn resolve_expr_in_scope(&self, scope: usize, expression: &Expr) -> ExceptionIdentity {
        match expression {
            Expr::Name(name) => {
                self.resolve_name(scope, name.id.as_str(), expression.range().start())
            }
            Expr::Attribute(attribute) => {
                let base = self.resolve_expr_in_scope(scope, attribute.value.as_ref());
                let ExceptionIdentity::Module(module) = base else {
                    return ExceptionIdentity::Unknown;
                };
                let qualified = format!("{module}.{}", attribute.attr);
                if is_known_exception_path(&qualified) {
                    ExceptionIdentity::Known(qualified)
                } else {
                    ExceptionIdentity::Module(qualified)
                }
            }
            _ => ExceptionIdentity::Unknown,
        }
    }

    fn resolve_name(&self, scope: usize, name: &str, position: TextSize) -> ExceptionIdentity {
        if let Some(values) = self.scopes[scope].bindings.get(name) {
            if let Some(binding) = values
                .iter()
                .filter(|binding| binding.activation <= position)
                .max_by_key(|binding| binding.activation)
            {
                return binding.identity.clone();
            }
            if self.scopes[scope].kind == ScopeKind::Function {
                return ExceptionIdentity::Unknown;
            }
        }
        self.lexical_parent(scope).map_or_else(
            || {
                if is_builtin_exception(name) {
                    ExceptionIdentity::Known(format!("builtins.{name}"))
                } else {
                    ExceptionIdentity::Unknown
                }
            },
            |parent| self.resolve_name(parent, name, position),
        )
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

    fn imported_identity(module: &str, name: &str) -> Option<ExceptionIdentity> {
        if module == "builtins" && is_builtin_exception(name) {
            return Some(ExceptionIdentity::Known(format!("builtins.{name}")));
        }
        match (module, name) {
            ("json", "JSONDecodeError") => {
                Some(ExceptionIdentity::Known("json.JSONDecodeError".to_string()))
            }
            ("urllib.error", "URLError") => Some(ExceptionIdentity::Known(
                "urllib.error.URLError".to_string(),
            )),
            ("urllib", "error") => Some(ExceptionIdentity::Module("urllib.error".to_string())),
            _ => None,
        }
    }

    fn is_ancestor(&self, child: &ExceptionIdentity, candidate: &ExceptionIdentity) -> bool {
        self.is_ancestor_inner(child, candidate, &mut HashSet::new())
    }

    fn is_ancestor_inner(
        &self,
        child: &ExceptionIdentity,
        candidate: &ExceptionIdentity,
        visited: &mut HashSet<ExceptionIdentity>,
    ) -> bool {
        if !visited.insert(child.clone()) {
            return false;
        }
        let bases = match child {
            ExceptionIdentity::Local(id) => self.classes.get(id).cloned().unwrap_or_default(),
            ExceptionIdentity::Known(path) => known_exception_bases(path),
            ExceptionIdentity::Module(_) | ExceptionIdentity::Unknown => Vec::new(),
        };
        bases
            .iter()
            .any(|base| base == candidate || self.is_ancestor_inner(base, candidate, visited))
    }
}

fn scope_body_range(body: &[Stmt], fallback: TextRange) -> TextRange {
    body.first()
        .zip(body.last())
        .map_or(fallback, |(first, last)| {
            TextRange::new(first.range().start(), last.range().end())
        })
}

fn is_builtin_exception(name: &str) -> bool {
    matches!(
        name,
        "ArithmeticError"
            | "AssertionError"
            | "AttributeError"
            | "BaseException"
            | "BaseExceptionGroup"
            | "BlockingIOError"
            | "BrokenPipeError"
            | "BufferError"
            | "BytesWarning"
            | "ChildProcessError"
            | "ConnectionAbortedError"
            | "ConnectionError"
            | "ConnectionRefusedError"
            | "ConnectionResetError"
            | "DeprecationWarning"
            | "EOFError"
            | "EncodingWarning"
            | "EnvironmentError"
            | "Exception"
            | "ExceptionGroup"
            | "FileExistsError"
            | "FileNotFoundError"
            | "FloatingPointError"
            | "FutureWarning"
            | "GeneratorExit"
            | "IOError"
            | "ImportError"
            | "ImportWarning"
            | "IndentationError"
            | "IndexError"
            | "InterruptedError"
            | "IsADirectoryError"
            | "KeyError"
            | "KeyboardInterrupt"
            | "LookupError"
            | "MemoryError"
            | "ModuleNotFoundError"
            | "NameError"
            | "NotADirectoryError"
            | "NotImplementedError"
            | "OSError"
            | "OverflowError"
            | "PendingDeprecationWarning"
            | "PermissionError"
            | "ProcessLookupError"
            | "PythonFinalizationError"
            | "RecursionError"
            | "ReferenceError"
            | "ResourceWarning"
            | "RuntimeError"
            | "RuntimeWarning"
            | "StopAsyncIteration"
            | "StopIteration"
            | "SyntaxError"
            | "SyntaxWarning"
            | "SystemError"
            | "SystemExit"
            | "TabError"
            | "TimeoutError"
            | "TypeError"
            | "UnboundLocalError"
            | "UnicodeDecodeError"
            | "UnicodeEncodeError"
            | "UnicodeError"
            | "UnicodeTranslateError"
            | "UnicodeWarning"
            | "UserWarning"
            | "ValueError"
            | "Warning"
            | "ZeroDivisionError"
    )
}

fn is_known_exception_path(path: &str) -> bool {
    path == "json.JSONDecodeError"
        || path == "urllib.error.URLError"
        || path
            .strip_prefix("builtins.")
            .is_some_and(is_builtin_exception)
}

fn known_exception_bases(path: &str) -> Vec<ExceptionIdentity> {
    let parents: &[&str] = match path {
        "builtins.BaseExceptionGroup"
        | "builtins.Exception"
        | "builtins.GeneratorExit"
        | "builtins.KeyboardInterrupt"
        | "builtins.SystemExit" => &["builtins.BaseException"],
        "builtins.ExceptionGroup" => &["builtins.Exception", "builtins.BaseExceptionGroup"],
        "builtins.NotImplementedError"
        | "builtins.PythonFinalizationError"
        | "builtins.RecursionError" => &["builtins.RuntimeError"],
        "builtins.ZeroDivisionError" | "builtins.FloatingPointError" | "builtins.OverflowError" => {
            &["builtins.ArithmeticError"]
        }
        "builtins.ModuleNotFoundError" => &["builtins.ImportError"],
        "builtins.IndexError" | "builtins.KeyError" => &["builtins.LookupError"],
        "builtins.UnboundLocalError" => &["builtins.NameError"],
        "builtins.IndentationError" => &["builtins.SyntaxError"],
        "builtins.TabError" => &["builtins.IndentationError"],
        "builtins.UnicodeDecodeError"
        | "builtins.UnicodeEncodeError"
        | "builtins.UnicodeTranslateError" => &["builtins.UnicodeError"],
        "builtins.UnicodeError" | "json.JSONDecodeError" => &["builtins.ValueError"],
        "builtins.BrokenPipeError"
        | "builtins.ConnectionAbortedError"
        | "builtins.ConnectionRefusedError"
        | "builtins.ConnectionResetError" => &["builtins.ConnectionError"],
        "builtins.BlockingIOError"
        | "builtins.ChildProcessError"
        | "builtins.FileExistsError"
        | "builtins.FileNotFoundError"
        | "builtins.InterruptedError"
        | "builtins.IsADirectoryError"
        | "builtins.NotADirectoryError"
        | "builtins.PermissionError"
        | "builtins.ProcessLookupError"
        | "builtins.TimeoutError"
        | "builtins.ConnectionError"
        | "urllib.error.URLError" => &["builtins.OSError"],
        "builtins.BytesWarning"
        | "builtins.DeprecationWarning"
        | "builtins.EncodingWarning"
        | "builtins.FutureWarning"
        | "builtins.ImportWarning"
        | "builtins.PendingDeprecationWarning"
        | "builtins.ResourceWarning"
        | "builtins.RuntimeWarning"
        | "builtins.SyntaxWarning"
        | "builtins.UnicodeWarning"
        | "builtins.UserWarning" => &["builtins.Warning"],
        "builtins.ArithmeticError"
        | "builtins.AssertionError"
        | "builtins.AttributeError"
        | "builtins.BufferError"
        | "builtins.EOFError"
        | "builtins.ImportError"
        | "builtins.LookupError"
        | "builtins.MemoryError"
        | "builtins.NameError"
        | "builtins.OSError"
        | "builtins.ReferenceError"
        | "builtins.RuntimeError"
        | "builtins.StopAsyncIteration"
        | "builtins.StopIteration"
        | "builtins.SyntaxError"
        | "builtins.SystemError"
        | "builtins.TypeError"
        | "builtins.ValueError"
        | "builtins.Warning"
        | "builtins.EnvironmentError"
        | "builtins.IOError" => &["builtins.Exception"],
        _ => &[],
    };
    parents
        .iter()
        .map(|parent| ExceptionIdentity::Known((*parent).to_string()))
        .collect()
}
