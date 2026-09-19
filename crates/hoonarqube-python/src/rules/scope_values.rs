//! Lexical single-assignment resolution shared by the Python 3.14 template
//! and `NotImplemented` rules (python:S7931, python:S7942).
//!
//! Mirrors `SonarPython`'s `Expressions.singleAssignedNonNameValue`: a `Name`
//! resolves to the value of its only plain `name = value` binding in the
//! enclosing lexical scope chain. With `allow_name_value = false` the value
//! must not itself be a bare name (Sonar's exact contract); `true` also
//! accepts name-valued assignments so callers can resolve aliases. Any other
//! binding of the name in a scope (rebinding, annotated/augmented
//! assignment, loop/with/except/match/walrus targets, imports, function or
//! class definitions, parameters, `global`/`nonlocal` declarations) makes
//! the name unresolvable. Function parameters bind in the function scope;
//! comprehension targets bind in their comprehension scope; class scopes are
//! skipped when resolving from inside a nested function, matching Python's
//! scoping rules.
use ruff_python_ast::{ExceptHandler, Expr, Pattern, Stmt};

/// Resolves `name` to its single assigned value along the lexical scope
/// chain of `scopes`, innermost first. `scopes` is ordered innermost to
/// outermost; class frames are skipped when the innermost real scope is a
/// function (class bodies never close over into methods).
pub(crate) fn resolve_in_scopes<'a>(
    scopes: &[(&'a [Stmt], &[&'a str], bool)],
    name: &str,
    allow_name_value: bool,
) -> NameResolution<'a> {
    let innermost_is_function = scopes.first().is_some_and(|(_, _, is_class)| !*is_class);
    for (body, bound, is_class) in scopes {
        if *is_class && innermost_is_function {
            continue;
        }
        if bound.contains(&name) {
            return NameResolution::Ambiguous;
        }
        match scope_resolution(body, name, allow_name_value) {
            ScopeResolution::Ambiguous => return NameResolution::Ambiguous,
            ScopeResolution::Single(value) => return NameResolution::Single(value),
            ScopeResolution::Unbound => {}
        }
    }
    NameResolution::Unbound
}

/// Outcome of resolving a name along the lexical scope chain.
pub(crate) enum NameResolution<'a> {
    /// The name is not bound anywhere in the scope chain.
    Unbound,
    /// The name is bound, but not by exactly one plain assignment of an
    /// acceptable value shape.
    Ambiguous,
    /// Exactly one `name = <expr>` binding exists.
    Single(&'a Expr),
}

/// Outcome of resolving a name inside one scope's statements.
enum ScopeResolution<'a> {
    /// No binding of the name exists in this scope; try the outer scope.
    Unbound,
    /// The name is bound, but not by exactly one plain assignment of an
    /// acceptable value shape.
    Ambiguous,
    /// Exactly one `name = <expr>` binding exists.
    Single(&'a Expr),
}

/// Resolves `name` within a single scope's statement suite.
fn scope_resolution<'a>(
    body: &'a [Stmt],
    name: &str,
    allow_name_value: bool,
) -> ScopeResolution<'a> {
    let mut assigned: Option<&'a Expr> = None;
    if binds_name(body, name, allow_name_value, &mut assigned) {
        return ScopeResolution::Ambiguous;
    }
    match assigned {
        Some(value) => ScopeResolution::Single(value),
        None => ScopeResolution::Unbound,
    }
}

/// Walks one scope's statements recording bindings of `name`. Returns `true`
/// as soon as the name is ambiguously bound; otherwise `assigned` holds the
/// value of the single plain assignment, if any.
fn binds_name<'a>(
    body: &'a [Stmt],
    name: &str,
    allow_name_value: bool,
    assigned: &mut Option<&'a Expr>,
) -> bool {
    for stmt in body {
        if stmt_binds(stmt, name, allow_name_value, assigned) {
            return true;
        }
    }
    false
}

/// Records the bindings `stmt` creates in the current scope and recurses into
/// same-scope suites. Nested function/class bodies are separate scopes, but
/// their names still bind here.
fn stmt_binds<'a>(
    stmt: &'a Stmt,
    name: &str,
    allow_name_value: bool,
    assigned: &mut Option<&'a Expr>,
) -> bool {
    match stmt {
        Stmt::Assign(assign) => assign_binds(assign, name, allow_name_value, assigned),
        Stmt::AugAssign(aug) => target_binds(&aug.target, name),
        Stmt::AnnAssign(ann) => target_binds(&ann.target, name),
        Stmt::FunctionDef(function) => function.name.as_str() == name,
        Stmt::ClassDef(class) => class.name.as_str() == name,
        Stmt::Import(import) => import.names.iter().any(|alias| alias_binds(alias, name)),
        Stmt::ImportFrom(import) => import.names.iter().any(|alias| alias_binds(alias, name)),
        Stmt::Global(global) => global.names.iter().any(|id| id.as_str() == name),
        Stmt::Nonlocal(nonlocal) => nonlocal.names.iter().any(|id| id.as_str() == name),
        Stmt::Delete(delete) => delete
            .targets
            .iter()
            .any(|target| target_binds(target, name)),
        _ => suite_binds(stmt, name, allow_name_value, assigned),
    }
}

/// Records an `Assign` binding: a single `name = <expr>` target with an
/// acceptable value shape is a candidate single binding; every other shape
/// binding `name` makes it ambiguous.
fn assign_binds<'a>(
    assign: &'a ruff_python_ast::StmtAssign,
    name: &str,
    allow_name_value: bool,
    assigned: &mut Option<&'a Expr>,
) -> bool {
    let binds_here = assign
        .targets
        .iter()
        .any(|target| target_binds(target, name));
    if !binds_here {
        return false;
    }
    if assign.targets.len() == 1
        && matches!(assign.targets[0], Expr::Name(_))
        && (allow_name_value || !matches!(assign.value.as_ref(), Expr::Name(_)))
        && assigned.is_none()
    {
        *assigned = Some(assign.value.as_ref());
        return false;
    }
    true
}

/// Records bindings inside a statement's same-scope suites and expression
/// walrus targets (nested function/class bodies are separate scopes, but
/// their names still bind here).
fn suite_binds<'a>(
    stmt: &'a Stmt,
    name: &str,
    allow_name_value: bool,
    assigned: &mut Option<&'a Expr>,
) -> bool {
    match stmt {
        Stmt::For(for_stmt) => {
            if target_binds(&for_stmt.target, name) {
                return true;
            }
            binds_name(&for_stmt.body, name, allow_name_value, assigned)
                || binds_name(&for_stmt.orelse, name, allow_name_value, assigned)
        }
        Stmt::While(while_stmt) => {
            binds_name(&while_stmt.body, name, allow_name_value, assigned)
                || binds_name(&while_stmt.orelse, name, allow_name_value, assigned)
        }
        Stmt::If(if_stmt) => {
            if binds_name(&if_stmt.body, name, allow_name_value, assigned) {
                return true;
            }
            if_stmt
                .elif_else_clauses
                .iter()
                .any(|clause| binds_name(&clause.body, name, allow_name_value, assigned))
        }
        Stmt::With(with_stmt) => {
            if with_stmt
                .items
                .iter()
                .filter_map(|item| item.optional_vars.as_deref())
                .any(|vars| target_binds(vars, name))
            {
                return true;
            }
            binds_name(&with_stmt.body, name, allow_name_value, assigned)
        }
        Stmt::Match(match_stmt) => match_stmt.cases.iter().any(|case| {
            pattern_binds(&case.pattern, name)
                || binds_name(&case.body, name, allow_name_value, assigned)
        }),
        Stmt::Try(try_stmt) => {
            if binds_name(&try_stmt.body, name, allow_name_value, assigned)
                || binds_name(&try_stmt.orelse, name, allow_name_value, assigned)
                || binds_name(&try_stmt.finalbody, name, allow_name_value, assigned)
            {
                return true;
            }
            try_stmt.handlers.iter().any(|handler| {
                let ExceptHandler::ExceptHandler(handler) = handler;
                handler
                    .name
                    .as_ref()
                    .is_some_and(|alias| alias.as_str() == name)
                    || binds_name(&handler.body, name, allow_name_value, assigned)
            })
        }
        _ => walrus_binds(stmt, name),
    }
}

/// Walrus targets inside a statement's expressions bind in the current
/// scope.
fn walrus_binds(stmt: &Stmt, name: &str) -> bool {
    for expr in crate::support::stmt_exprs(stmt) {
        let mut found = false;
        crate::support::for_each_expr(expr, &mut |node| {
            if let Expr::Named(named) = node
                && target_binds(&named.target, name)
            {
                found = true;
            }
        });
        if found {
            return true;
        }
    }
    false
}

/// Whether `alias` binds `name` (`import x`, `import x as y`,
/// `from m import x as y`).
fn alias_binds(alias: &ruff_python_ast::Alias, name: &str) -> bool {
    match &alias.asname {
        Some(asname) => asname.as_str() == name,
        None => alias.name.as_str().split('.').next() == Some(name),
    }
}

/// Whether an assignment target binds `name` (bare name, tuple/list/starred
/// destructuring; attribute/subscript stores never bind a plain name).
fn target_binds(target: &Expr, name: &str) -> bool {
    match target {
        Expr::Name(bound) => bound.id.as_str() == name,
        Expr::Tuple(tuple) => tuple.elts.iter().any(|elt| target_binds(elt, name)),
        Expr::List(list) => list.elts.iter().any(|elt| target_binds(elt, name)),
        Expr::Starred(starred) => target_binds(&starred.value, name),
        _ => false,
    }
}

/// Whether a match pattern captures `name`.
fn pattern_binds(pattern: &Pattern, name: &str) -> bool {
    match pattern {
        Pattern::MatchAs(as_pattern) => {
            as_pattern
                .name
                .as_ref()
                .is_some_and(|capture| capture.id.as_str() == name)
                || as_pattern
                    .pattern
                    .as_deref()
                    .is_some_and(|inner| pattern_binds(inner, name))
        }
        Pattern::MatchOr(or_pattern) => or_pattern
            .patterns
            .iter()
            .any(|inner| pattern_binds(inner, name)),
        Pattern::MatchSequence(sequence) => sequence
            .patterns
            .iter()
            .any(|inner| pattern_binds(inner, name)),
        Pattern::MatchMapping(mapping) => {
            mapping
                .rest
                .as_ref()
                .is_some_and(|rest| rest.id.as_str() == name)
                || mapping
                    .patterns
                    .iter()
                    .any(|inner| pattern_binds(inner, name))
        }
        Pattern::MatchClass(class_pattern) => class_pattern
            .arguments
            .patterns
            .iter()
            .chain(
                class_pattern
                    .arguments
                    .keywords
                    .iter()
                    .map(|kw| &kw.pattern),
            )
            .any(|inner| pattern_binds(inner, name)),
        Pattern::MatchStar(star) => star
            .name
            .as_ref()
            .is_some_and(|capture| capture.id.as_str() == name),
        _ => false,
    }
}

/// Names bound by a function's parameter list, in declaration order.
pub(crate) fn parameter_names(parameters: &ruff_python_ast::Parameters) -> Vec<&str> {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .map(|arg| arg.parameter.name.as_str())
        .chain(parameters.vararg.as_deref().map(|p| p.name.as_str()))
        .chain(parameters.kwarg.as_deref().map(|p| p.name.as_str()))
        .collect()
}

/// Names bound by a comprehension's `for` targets across all generators.
pub(crate) fn comprehension_target_names(
    generators: &[ruff_python_ast::Comprehension],
) -> Vec<&str> {
    let mut names = Vec::new();
    for generator in generators {
        collect_target_names(&generator.target, &mut names);
    }
    names
}

/// Collects every name a target expression binds (tuple/list destructuring).
pub(crate) fn collect_target_names<'a>(target: &'a Expr, names: &mut Vec<&'a str>) {
    match target {
        Expr::Name(bound) => names.push(bound.id.as_str()),
        Expr::Tuple(tuple) => {
            for elt in &tuple.elts {
                collect_target_names(elt, names);
            }
        }
        Expr::List(list) => {
            for elt in &list.elts {
                collect_target_names(elt, names);
            }
        }
        Expr::Starred(starred) => collect_target_names(&starred.value, names),
        _ => {}
    }
}

/// One lexical frame on the scope stack of an expression.
struct Frame<'a> {
    /// Statements evaluated in this scope (empty for lambda/comprehension
    /// frames, whose bindings come only from `bound`).
    body: &'a [Stmt],
    /// Names the scope binds without a statement (function parameters,
    /// comprehension targets).
    bound: Vec<&'a str>,
    is_class: bool,
}

/// Scope-aware expression walker: visits every expression in `body` with its
/// lexical scope chain (innermost first). `visit` receives the expression and
/// the scope stack as `(body, bound_names, is_class)` triples.
pub(crate) fn for_each_expr_scoped<'a>(
    body: &'a [Stmt],
    visit: &mut impl FnMut(&'a Expr, &[(&'a [Stmt], &[&'a str], bool)]),
) {
    let mut frames: Vec<Frame<'a>> = vec![Frame {
        body,
        bound: Vec::new(),
        is_class: false,
    }];
    walk_body(body, &mut frames, visit);
}

/// Scope-aware statement walker: visits every statement in `body` with the
/// lexical scope chain it executes in (innermost first). Function and class
/// bodies open new frames exactly like [`for_each_expr_scoped`].
pub(crate) fn for_each_stmt_scoped<'a>(
    body: &'a [Stmt],
    visit: &mut impl FnMut(&'a Stmt, &[(&'a [Stmt], &[&'a str], bool)]),
) {
    let mut frames: Vec<Frame<'a>> = vec![Frame {
        body,
        bound: Vec::new(),
        is_class: false,
    }];
    walk_body_stmts(body, &mut frames, visit);
}

/// `scopes` with one extra innermost frame that binds `bound` names but owns
/// no statements — the shape comprehension `if` clauses resolve against.
pub(crate) fn pushed_scope<'a, 'b>(
    scopes: &'b [(&'a [Stmt], &'b [&'a str], bool)],
    bound: &'b [&'a str],
) -> Vec<(&'a [Stmt], &'b [&'a str], bool)> {
    let mut extended: Vec<(&'a [Stmt], &'b [&'a str], bool)> = Vec::with_capacity(scopes.len() + 1);
    extended.push((&[][..], bound, false));
    extended.extend_from_slice(scopes);
    extended
}

fn scope_view<'a, 'b>(frames: &'b [Frame<'a>]) -> Vec<(&'a [Stmt], &'b [&'a str], bool)> {
    frames
        .iter()
        .rev()
        .map(|frame| (frame.body, frame.bound.as_slice(), frame.is_class))
        .collect()
}

fn walk_body<'a>(
    body: &'a [Stmt],
    frames: &mut Vec<Frame<'a>>,
    visit: &mut impl FnMut(&'a Expr, &[(&'a [Stmt], &[&'a str], bool)]),
) {
    for stmt in body {
        walk_stmt(stmt, frames, visit);
    }
}

fn walk_body_stmts<'a>(
    body: &'a [Stmt],
    frames: &mut Vec<Frame<'a>>,
    visit: &mut impl FnMut(&'a Stmt, &[(&'a [Stmt], &[&'a str], bool)]),
) {
    for stmt in body {
        visit(stmt, &scope_view(frames));
        match stmt {
            Stmt::FunctionDef(function) => {
                frames.push(Frame {
                    body: &function.body,
                    bound: parameter_names(&function.parameters),
                    is_class: false,
                });
                walk_body_stmts(&function.body, frames, visit);
                frames.pop();
            }
            Stmt::ClassDef(class) => {
                frames.push(Frame {
                    body: &class.body,
                    bound: Vec::new(),
                    is_class: true,
                });
                walk_body_stmts(&class.body, frames, visit);
                frames.pop();
            }
            _ => {
                for suite in crate::support::child_bodies(stmt) {
                    walk_body_stmts(suite, frames, visit);
                }
            }
        }
    }
}

fn walk_stmt<'a>(
    stmt: &'a Stmt,
    frames: &mut Vec<Frame<'a>>,
    visit: &mut impl FnMut(&'a Expr, &[(&'a [Stmt], &[&'a str], bool)]),
) {
    match stmt {
        Stmt::FunctionDef(function) => {
            // Decorators, defaults, and annotations evaluate in the enclosing
            // scope; the body opens a new function scope.
            for expr in crate::support::stmt_exprs(stmt) {
                walk_expr(expr, frames, visit);
            }
            frames.push(Frame {
                body: &function.body,
                bound: parameter_names(&function.parameters),
                is_class: false,
            });
            walk_body(&function.body, frames, visit);
            frames.pop();
        }
        Stmt::ClassDef(class) => {
            for expr in crate::support::stmt_exprs(stmt) {
                walk_expr(expr, frames, visit);
            }
            frames.push(Frame {
                body: &class.body,
                bound: Vec::new(),
                is_class: true,
            });
            walk_body(&class.body, frames, visit);
            frames.pop();
        }
        _ => {
            for expr in crate::support::stmt_exprs(stmt) {
                walk_expr(expr, frames, visit);
            }
            for suite in crate::support::child_bodies(stmt) {
                walk_body(suite, frames, visit);
            }
        }
    }
}

fn walk_expr<'a>(
    expr: &'a Expr,
    frames: &mut Vec<Frame<'a>>,
    visit: &mut impl FnMut(&'a Expr, &[(&'a [Stmt], &[&'a str], bool)]),
) {
    visit(expr, &scope_view(frames));
    match expr {
        Expr::Lambda(lambda) => {
            // Parameter defaults and annotations evaluate in the enclosing
            // scope; the body opens a new function scope.
            if let Some(parameters) = &lambda.parameters {
                let mut exprs = Vec::new();
                crate::support::push_parameter_exprs(parameters, &mut exprs);
                for child in exprs {
                    walk_expr(child, frames, visit);
                }
            }
            let bound = lambda
                .parameters
                .as_deref()
                .map(parameter_names)
                .unwrap_or_default();
            frames.push(Frame {
                body: &[],
                bound,
                is_class: false,
            });
            walk_expr(&lambda.body, frames, visit);
            frames.pop();
        }
        Expr::ListComp(comp) => walk_comprehension(&comp.elt, &comp.generators, frames, visit),
        Expr::SetComp(comp) => walk_comprehension(&comp.elt, &comp.generators, frames, visit),
        Expr::Generator(comp) => walk_comprehension(&comp.elt, &comp.generators, frames, visit),
        Expr::DictComp(comp) => {
            frames.push(Frame {
                body: &[],
                bound: comprehension_target_names(&comp.generators),
                is_class: false,
            });
            for generator in &comp.generators {
                walk_expr(&generator.target, frames, visit);
                walk_expr(&generator.iter, frames, visit);
                for condition in &generator.ifs {
                    walk_expr(condition, frames, visit);
                }
            }
            if let Some(key) = &comp.key {
                walk_expr(key, frames, visit);
            }
            walk_expr(&comp.value, frames, visit);
            frames.pop();
        }
        _ => {
            for child in crate::support::child_exprs(expr) {
                walk_expr(child, frames, visit);
            }
        }
    }
}

fn walk_comprehension<'a>(
    elt: &'a Expr,
    generators: &'a [ruff_python_ast::Comprehension],
    frames: &mut Vec<Frame<'a>>,
    visit: &mut impl FnMut(&'a Expr, &[(&'a [Stmt], &[&'a str], bool)]),
) {
    frames.push(Frame {
        body: &[],
        bound: comprehension_target_names(generators),
        is_class: false,
    });
    for generator in generators {
        walk_expr(&generator.target, frames, visit);
        walk_expr(&generator.iter, frames, visit);
        for condition in &generator.ifs {
            walk_expr(condition, frames, visit);
        }
    }
    walk_expr(elt, frames, visit);
    frames.pop();
}

/// Whether `expr` is the literal name `expected`.
pub(crate) fn is_name(expr: &Expr, expected: &str) -> bool {
    matches!(expr, Expr::Name(name) if name.id.as_str() == expected)
}
