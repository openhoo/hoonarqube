//!
//! Sonar resolves web-framework receivers through type matchers
//! (`fastapi.applications.FastAPI.include_router`,
//! `flask.app.Flask.route`, …). hoonarqube has no type inference, so the
//! web rules share this resolver: it reconstructs the same identities from
//! import provenance and from `name = Constructor(...)` bindings, honoring
//! the function/lambda scope chain the decompiled checks use
//! (`FUNCDEF | LAMBDA | FILE_INPUT`).

use crate::engine::file_context::FileContext;
use crate::support::stmt_store_names;
use ruff_python_ast::{Expr, ExprCall, Stmt, StmtClassDef, StmtFunctionDef};
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashSet;

/// How a bare name is bound at a read site.
pub(crate) enum NameResolution<'a> {
    /// Exactly one binding in the nearest scope, an assignment with a value.
    Value(&'a Expr),
    /// Exactly one binding in the nearest scope, an import alias.
    Import(String),
    /// Bound in the nearest scope by something else (multiple writes,
    /// parameters, `for`/`with` targets, `global`/`nonlocal`, defs).
    Bound,
    /// No binding found in any enclosing scope.
    Unbound,
}

/// Per-file framework binding facts; build once, share across web rules.
pub(crate) struct WebFrameworkFacts<'a> {
    functions: Vec<&'a StmtFunctionDef>,
    classes: Vec<&'a StmtClassDef>,
    lambdas: Vec<&'a ruff_python_ast::ExprLambda>,
    stmts: Vec<&'a Stmt>,
    stmt_scope: Vec<Option<TextRange>>,
}

impl<'a> WebFrameworkFacts<'a> {
    pub(crate) fn build(file_ctx: &FileContext<'a>) -> Self {
        let lambdas: Vec<&ruff_python_ast::ExprLambda> = file_ctx
            .exprs
            .iter()
            .filter_map(|expr| match *expr {
                Expr::Lambda(lambda) => Some(lambda),
                _ => None,
            })
            .collect();
        let mut facts = WebFrameworkFacts {
            functions: file_ctx.functions.clone(),
            classes: file_ctx.classes.clone(),
            lambdas,
            stmts: file_ctx.stmts.clone(),
            stmt_scope: Vec::new(),
        };
        facts.stmt_scope = facts
            .stmts
            .iter()
            .map(|stmt| facts.enclosing_scope(stmt.range()))
            .collect();
        facts
    }

    /// Innermost enclosing function/lambda scope of `at`; `None` = module.
    /// Class bodies are transparent, matching Sonar's scope kinds.
    pub(crate) fn enclosing_scope(&self, at: TextRange) -> Option<TextRange> {
        let mut best: Option<TextRange> = None;
        let mut best_len = u32::MAX;
        for function in &self.functions {
            let range = function.range();
            if range.contains_range(at) && range.len().to_u32() < best_len {
                best = Some(range);
                best_len = range.len().to_u32();
            }
        }
        for lambda in &self.lambdas {
            let range = lambda.range();
            if range.contains_range(at) && range.len().to_u32() < best_len {
                best = Some(range);
                best_len = range.len().to_u32();
            }
        }
        best
    }

    /// Enclosing scopes of `at`, innermost first, module (`None`) last.
    fn enclosing_chain(&self, at: TextRange) -> Vec<Option<TextRange>> {
        let mut scopes: Vec<TextRange> = self
            .functions
            .iter()
            .map(Ranged::range)
            .chain(self.lambdas.iter().map(Ranged::range))
            .filter(|range| range.contains_range(at))
            .collect();
        scopes.sort_by_key(|range| range.len().to_u32());
        let mut chain: Vec<Option<TextRange>> = scopes.into_iter().map(Some).collect();
        chain.push(None);
        chain
    }

    /// Resolves a bare `name` read at `at` through the scope chain.
    pub(crate) fn resolve_name(&self, name: &str, at: TextRange) -> NameResolution<'a> {
        for scope in self.enclosing_chain(at) {
            let bindings: Vec<&Stmt> = self
                .stmts
                .iter()
                .zip(&self.stmt_scope)
                .filter(|(stmt, stmt_scope)| {
                    **stmt_scope == scope && stmt_store_names(stmt).iter().any(|n| n == name)
                })
                .map(|(stmt, _)| *stmt)
                .collect();
            if bindings.is_empty() {
                if scope_has_parameter(self, scope, name) {
                    return NameResolution::Bound;
                }
                continue;
            }
            if bindings.len() != 1 {
                return NameResolution::Bound;
            }
            return match bindings[0] {
                Stmt::Assign(assign) => NameResolution::Value(assign.value.as_ref()),
                Stmt::AnnAssign(assign) => match assign.value.as_deref() {
                    Some(value) => NameResolution::Value(value),
                    None => NameResolution::Bound,
                },
                Stmt::Import(import) => plain_import_fqn(import, name)
                    .map_or(NameResolution::Bound, NameResolution::Import),
                Stmt::ImportFrom(import) => from_import_fqn(import, name)
                    .map_or(NameResolution::Bound, NameResolution::Import),
                _ => NameResolution::Bound,
            };
        }
        NameResolution::Unbound
    }

    /// The single assigned value of `name` at `at`, or `None` when the name
    /// is not provably bound to exactly one assignment.
    pub(crate) fn single_assigned_value(&self, name: &str, at: TextRange) -> Option<&'a Expr> {
        match self.resolve_name(name, at) {
            NameResolution::Value(value) => Some(value),
            _ => None,
        }
    }

    /// The single assigned value of `name` at `at` plus the binding
    /// statement's range, restricted to Sonar's
    /// `Expressions.singleAssignedValue` shape: the name must be bound by
    /// exactly one plain `name = value` (or `name: T = value`) assignment
    /// in the nearest scope. Tuple unpacking, attribute/subscript
    /// targets, augmented assignments, imports, parameters, and any
    /// second binding disqualify the name.
    pub(crate) fn strict_single_assignment(
        &self,
        name: &str,
        at: TextRange,
    ) -> Option<(&'a Expr, TextRange)> {
        for scope in self.enclosing_chain(at) {
            let bindings: Vec<&Stmt> = self
                .stmts
                .iter()
                .zip(&self.stmt_scope)
                .filter(|(stmt, stmt_scope)| {
                    **stmt_scope == scope && stmt_store_names(stmt).iter().any(|n| n == name)
                })
                .map(|(stmt, _)| *stmt)
                .collect();
            if bindings.is_empty() {
                if scope_has_parameter(self, scope, name) {
                    return None;
                }
                continue;
            }
            if bindings.len() != 1 {
                return None;
            }
            return match bindings[0] {
                Stmt::Assign(assign)
                    if assign
                        .targets
                        .iter()
                        .all(|target| matches!(target, Expr::Name(_))) =>
                {
                    Some((assign.value.as_ref(), assign.range()))
                }
                Stmt::AnnAssign(assign) if matches!(assign.target.as_ref(), Expr::Name(_)) => {
                    assign.value.as_deref().map(|value| (value, assign.range()))
                }
                _ => None,
            };
        }
        None
    }

    /// A top-level method `name` of `class`, including methods nested in
    /// compound statements (`if`, `try`, …) but not inside nested
    /// classes, functions, or lambdas — Sonar's
    /// `TreeUtils.topLevelFunctionDefs`. First definition wins.
    pub(crate) fn top_level_method(
        &self,
        class: &StmtClassDef,
        name: &str,
    ) -> Option<&'a StmtFunctionDef> {
        self.functions
            .iter()
            .filter(|function| function.name.as_str() == name)
            .filter(|function| class.range().contains_range(function.range()))
            .filter(|function| {
                !self
                    .functions
                    .iter()
                    .map(Ranged::range)
                    .chain(self.classes.iter().map(Ranged::range))
                    .chain(self.lambdas.iter().map(Ranged::range))
                    .any(|container| {
                        container != function.range()
                            && container != class.range()
                            && container.contains_range(function.range())
                            && class.range().contains_range(container)
                    })
            })
            .min_by_key(|function| function.range().start().to_u32())
            .copied()
    }

    /// The innermost class definition enclosing `at`, if any.
    pub(crate) fn enclosing_class(&self, at: TextRange) -> Option<&'a StmtClassDef> {
        self.classes
            .iter()
            .filter(|class| class.range().contains_range(at))
            .min_by_key(|class| class.range().len().to_u32())
            .copied()
    }

    /// Canonical FQN of `expr`: import aliases resolve to their module path
    /// (with FastAPI/Flask re-exports canonicalized to their defining
    /// module), names assigned a recognized constructor call resolve to the
    /// constructor's FQN, and attribute chains append their tail.
    pub(crate) fn expr_fqn(&self, expr: &Expr) -> Option<String> {
        self.expr_fqn_at(expr, expr.range(), 0)
    }

    fn expr_fqn_at(&self, expr: &Expr, at: TextRange, depth: u32) -> Option<String> {
        if depth > 8 {
            return None;
        }
        match expr {
            Expr::Name(name) => match self.resolve_name(name.id.as_str(), at) {
                NameResolution::Import(fqn) => Some(canonical_fqn(&fqn)),
                NameResolution::Value(value) => self.expr_fqn_at(value, at, depth + 1),
                _ => None,
            },
            Expr::Attribute(attribute) => {
                let base = self.expr_fqn_at(&attribute.value, at, depth + 1)?;
                Some(format!("{}.{}", base, attribute.attr.as_str()))
            }
            Expr::Call(call) => self.expr_fqn_at(&call.func, at, depth + 1),
            _ => None,
        }
    }

    /// Resolves a call's target to a same-file function definition visible
    /// from the call site (nearest binding scope wins, latest def on ties).
    pub(crate) fn resolve_function(&self, call: &ExprCall) -> Option<&'a StmtFunctionDef> {
        self.resolve_function_def(&call.func, call.range())
    }

    /// Resolves `expr` to a same-file function definition: a bare name
    /// resolves through the scope chain like a call target, and an
    /// attribute resolves to a same-named top-level method of the class
    /// the qualifier resolves to (`Depends(Deps.get_item)`).
    pub(crate) fn resolve_function_def(
        &self,
        expr: &Expr,
        at: TextRange,
    ) -> Option<&'a StmtFunctionDef> {
        match expr {
            Expr::Name(name) => {
                for scope in self.enclosing_chain(at) {
                    let candidate = self
                        .functions
                        .iter()
                        .filter(|function| function.name.as_str() == name.id.as_str())
                        .filter(|function| self.strict_parent_scope(function.range()) == scope)
                        .max_by_key(|function| function.range().start().to_u32());
                    if let Some(function) = candidate {
                        return Some(*function);
                    }
                }
                None
            }
            Expr::Attribute(attribute) => {
                let owner = self.resolve_local_alias_chain(&attribute.value);
                let class = self.resolve_class_def(owner, at)?;
                class.body.iter().find_map(|stmt| match stmt {
                    Stmt::FunctionDef(function)
                        if function.name.as_str() == attribute.attr.as_str() =>
                    {
                        Some(function)
                    }
                    _ => None,
                })
            }
            _ => None,
        }
    }

    /// Resolves `expr` to a same-file class definition: a bare name through
    /// the scope chain, an attribute to a nested class of the resolved
    /// qualifier class.
    pub(crate) fn resolve_class_def(&self, expr: &Expr, at: TextRange) -> Option<&'a StmtClassDef> {
        match expr {
            Expr::Name(name) => {
                for scope in self.enclosing_chain(at) {
                    let candidate = self
                        .classes
                        .iter()
                        .filter(|class| class.name.as_str() == name.id.as_str())
                        .filter(|class| self.strict_parent_scope(class.range()) == scope)
                        .max_by_key(|class| class.range().start().to_u32());
                    if let Some(class) = candidate {
                        return Some(*class);
                    }
                }
                None
            }
            Expr::Attribute(attribute) => {
                let owner = self.resolve_local_alias_chain(&attribute.value);
                let class = self.resolve_class_def(owner, at)?;
                class.body.iter().find_map(|stmt| match stmt {
                    Stmt::ClassDef(nested) if nested.name.as_str() == attribute.attr.as_str() => {
                        Some(nested)
                    }
                    _ => None,
                })
            }
            _ => None,
        }
    }

    /// Follows `name = value` alias chains from `expr`, each hop resolved
    /// at the name's own site, and returns the final expression. When the
    /// chain cycles or the name is not provably bound to one assignment,
    /// the name at which resolution stalls is returned.
    pub(crate) fn resolve_local_alias_chain<'b>(&self, mut expr: &'b Expr) -> &'b Expr
    where
        'a: 'b,
    {
        let mut visited: HashSet<TextRange> = HashSet::new();
        while let Expr::Name(name) = expr {
            let Some(value) = self.single_assigned_value(name.id.as_str(), name.range()) else {
                break;
            };
            if !visited.insert(value.range()) {
                break;
            }
            expr = value;
        }
        expr
    }

    /// The nearest function/lambda scope strictly enclosing `range`
    /// (the parent scope of a def whose own range is `range`).
    fn strict_parent_scope(&self, range: TextRange) -> Option<TextRange> {
        let mut best: Option<TextRange> = None;
        let mut best_len = u32::MAX;
        for scope in self
            .functions
            .iter()
            .map(Ranged::range)
            .chain(self.lambdas.iter().map(Ranged::range))
        {
            if scope.contains_range(range) && scope != range && scope.len().to_u32() < best_len {
                best = Some(scope);
                best_len = scope.len().to_u32();
            }
        }
        best
    }

    /// Lambda expressions in the file (nested-scope boundaries for rules
    /// that must not descend into them).
    pub(crate) fn lambdas(&self) -> impl Iterator<Item = &'a ruff_python_ast::ExprLambda> + '_ {
        self.lambdas.iter().copied()
    }
}

/// `fqn` is `member` of any of `bases` (`fastapi.applications.FastAPI` +
/// `include_router` → `fastapi.applications.FastAPI.include_router`).
pub(crate) fn fqn_is_member(fqn: &str, bases: &[&str], member: &str) -> bool {
    bases.iter().any(|base| {
        fqn.len() == base.len() + member.len() + 1
            && fqn.starts_with(base)
            && fqn.ends_with(member)
            && fqn.as_bytes()[base.len()] == b'.'
    })
}

/// `FastAPI`/`Starlette` `include_router` on an app or router receiver.
pub(crate) fn is_include_router(fqn: &str) -> bool {
    fqn_is_member(
        fqn,
        &[
            "fastapi.applications.FastAPI",
            "fastapi.routing.APIRouter",
            "starlette.applications.Starlette",
            "starlette.routing.APIRouter",
        ],
        "include_router",
    )
}

/// `FastAPI`/`Starlette` `add_middleware` on an application receiver.
pub(crate) fn is_add_middleware(fqn: &str) -> bool {
    fqn_is_member(
        fqn,
        &[
            "fastapi.applications.FastAPI",
            "starlette.applications.Starlette",
        ],
        "add_middleware",
    )
}

/// `FastAPI` `route` on an app or router receiver (the generic decorator).
pub(crate) fn is_fastapi_route(fqn: &str) -> bool {
    fqn_is_member(
        fqn,
        &["fastapi.applications.FastAPI", "fastapi.routing.APIRouter"],
        "route",
    )
}

/// `FastAPI` HTTP-verb route decorator (`get`, `post`, …, `trace`).
pub(crate) fn is_fastapi_verb(fqn: &str) -> bool {
    const VERBS: [&str; 8] = [
        "get", "post", "put", "delete", "patch", "options", "head", "trace",
    ];
    VERBS.iter().any(|verb| {
        fqn_is_member(
            fqn,
            &["fastapi.applications.FastAPI", "fastapi.routing.APIRouter"],
            verb,
        )
    })
}

/// `Flask` `route` on an application or blueprint receiver.
pub(crate) fn is_flask_route(fqn: &str) -> bool {
    fqn_is_member(
        fqn,
        &["flask.app.Flask", "flask.blueprints.Blueprint"],
        "route",
    )
}

/// `FastAPI`/`Starlette` `CORSMiddleware` class reference.
pub(crate) fn is_cors_middleware(fqn: &str) -> bool {
    fqn == "fastapi.middleware.cors.CORSMiddleware"
        || fqn == "starlette.middleware.cors.CORSMiddleware"
}

/// `FastAPI` `HTTPException` class reference.
pub(crate) fn is_http_exception(fqn: &str) -> bool {
    fqn == "fastapi.HTTPException" || fqn == "fastapi.exceptions.HTTPException"
}

/// `FastAPI` `APIRouter` constructor call.
pub(crate) fn is_api_router_call(facts: &WebFrameworkFacts<'_>, call: &ExprCall) -> bool {
    facts
        .expr_fqn(&call.func)
        .is_some_and(|fqn| fqn == "fastapi.routing.APIRouter")
}

/// Keyword argument `name` of `call`, or the `position`-th positional.
pub(crate) fn nth_or_keyword_argument<'a>(
    call: &'a ExprCall,
    position: usize,
    name: &str,
) -> Option<&'a Expr> {
    if let Some(expr) = call.arguments.args.get(position) {
        return Some(expr);
    }
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_deref() == Some(name))
        .map(|keyword| &keyword.value)
}

/// Keyword argument `name` of `call` (keyword-only lookup).
pub(crate) fn keyword_argument<'a>(call: &'a ExprCall, name: &str) -> Option<&'a Expr> {
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_deref() == Some(name))
        .map(|keyword| &keyword.value)
}

/// The `name` keyword's identifier range (Sonar anchors on the keyword
/// `Name`, not the whole argument).
pub(crate) fn keyword_name_range(call: &ExprCall, name: &str) -> Option<TextRange> {
    call.arguments
        .keywords
        .iter()
        .find(|keyword| keyword.arg.as_deref() == Some(name))
        .and_then(|keyword| keyword.arg.as_ref())
        .map(Ranged::range)
}

/// Whether `call` passes a `**mapping` argument.
pub(crate) fn has_dict_unpacking(call: &ExprCall) -> bool {
    call.arguments
        .keywords
        .iter()
        .any(|keyword| keyword.arg.is_none())
}

/// Whether `parameters` declares `name` (positional, keyword-only,
/// `*args`, or `**kwargs`).
fn parameters_include(parameters: &ruff_python_ast::Parameters, name: &str) -> bool {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .any(|param| param.parameter.name.as_str() == name)
        || parameters
            .vararg
            .as_ref()
            .is_some_and(|param| param.name.as_str() == name)
        || parameters
            .kwarg
            .as_ref()
            .is_some_and(|param| param.name.as_str() == name)
}

fn scope_has_parameter(
    facts: &WebFrameworkFacts<'_>,
    scope: Option<TextRange>,
    name: &str,
) -> bool {
    let Some(range) = scope else {
        return false;
    };
    if let Some(function) = facts
        .functions
        .iter()
        .find(|function| function.range() == range)
    {
        return parameters_include(&function.parameters, name);
    }
    if let Some(lambda) = facts.lambdas.iter().find(|lambda| lambda.range() == range) {
        return lambda
            .parameters
            .as_deref()
            .is_some_and(|parameters| parameters_include(parameters, name));
    }
    false
}

/// Local name bound by an import alias (`asname` or the imported name).
fn alias_local_name(alias: &ruff_python_ast::Alias) -> &str {
    alias
        .asname
        .as_ref()
        .map_or_else(|| alias.name.as_str(), ruff_python_ast::Identifier::as_str)
}

fn plain_import_fqn(import: &ruff_python_ast::StmtImport, name: &str) -> Option<String> {
    import
        .names
        .iter()
        .rev()
        .filter(|alias| alias.name.as_str() != "*")
        .find(|alias| {
            let local = alias.asname.as_ref().map_or_else(
                || alias.name.as_str().split('.').next().unwrap_or(""),
                ruff_python_ast::Identifier::as_str,
            );
            local == name
        })
        .map(|alias| alias.name.as_str().to_string())
}

fn from_import_fqn(import: &ruff_python_ast::StmtImportFrom, name: &str) -> Option<String> {
    if import.level != 0 {
        return None;
    }
    let module = import.module.as_ref()?.as_str();
    import
        .names
        .iter()
        .rev()
        .filter(|alias| alias.name.as_str() != "*")
        .find(|alias| alias_local_name(alias) == name)
        .map(|alias| format!("{module}.{}", alias.name.as_str()))
}

/// Re-exported framework names canonicalized to their defining module so a
/// single FQN set matches every import spelling.
fn canonical_fqn(fqn: &str) -> String {
    match fqn {
        "fastapi.FastAPI" => "fastapi.applications.FastAPI".to_string(),
        "fastapi.APIRouter" => "fastapi.routing.APIRouter".to_string(),
        "flask.Flask" => "flask.app.Flask".to_string(),
        "flask.Blueprint" => "flask.blueprints.Blueprint".to_string(),
        "starlette.Starlette" => "starlette.applications.Starlette".to_string(),
        _ => fqn.to_string(),
    }
}
