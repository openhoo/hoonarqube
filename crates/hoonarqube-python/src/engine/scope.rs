use crate::support::called_name;
use crate::support::child_bodies;
use crate::support::child_exprs;
use crate::support::collect_string_contents;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::import_binding_name;
use crate::support::is_tf_function;
use crate::support::named_parameters;
use crate::support::push_parameter_exprs;
use crate::support::stmt_exprs;
use ruff_python_ast::Comprehension;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::ExprLambda;
use ruff_python_ast::ExprNamed;
use ruff_python_ast::ModModule;
use ruff_python_ast::Pattern;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtGlobal;
use ruff_python_ast::StmtIf;
use ruff_python_ast::StmtNonlocal;
use ruff_python_ast::StmtWith;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use std::collections::HashMap;
use std::collections::HashSet;

// --- python:S2772 — needless `pass` ----------------------------------------

#[derive(Clone, Copy)]
pub(crate) enum SuiteOwner {
    Module,
    Class,
    Other,
}

// --- python:S5704/S5747/S1143/S1716 — raise/jump flow placement ---------------

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum RaiseContext {
    Outside,
    InExcept,
    InFinally,
}

// ---------------------------------------------------------------------------
// Tier B — symbol / flow / value / effect groups.
//
// A minimal in-file symbol layer backs these rules: scopes (module, function,
// class, comprehension), per-scope bindings with source ranges, and name loads
// resolved through the scope chain. The layer is deliberately conservative:
//
// * a token-level "use net" vetoes unused-name reports whenever an identifier
//   appears anywhere else in the file (f-string interiors, keyword argument
//   names, and attribute names are invisible to the AST walk);
// * files using dynamic features (`locals`, `globals`, `eval`, `exec`) skip
//   resolution-based rules entirely;
// * class scopes are invisible to functions/comprehensions nested inside them;
// * comprehension scopes bind their own targets; the first iterable resolves
//   in the enclosing scope while later iterables resolve inside the
//   comprehension scope, where earlier targets are already visible.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ScopeKind {
    Module,
    Function,
    Class,
    Comprehension,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BindingKind {
    Import,
    Assignment,
    ExceptName,
    Parameter,
    Definition,
}

pub(crate) struct Binding {
    pub(crate) range: TextRange,
    pub(crate) kind: BindingKind,
    pub(crate) loop_depth: u32,
}

pub(crate) struct SymbolScope {
    pub(crate) kind: ScopeKind,
    pub(crate) parent: Option<usize>,
    pub(crate) bindings: HashMap<String, Vec<Binding>>,
    pub(crate) loads: Vec<(String, TextRange, bool)>,
    global_names: Vec<String>,
    nonlocal_names: Vec<String>,
}

impl SymbolScope {
    fn new(kind: ScopeKind, parent: Option<usize>) -> Self {
        Self {
            kind,
            parent,
            bindings: HashMap::new(),
            loads: Vec::new(),
            global_names: Vec::new(),
            nonlocal_names: Vec::new(),
        }
    }
}

pub(crate) struct LoadRecord {
    pub(crate) scope: usize,
    pub(crate) name: String,
    pub(crate) range: TextRange,
    pub(crate) target: Option<usize>,
    pub(crate) in_annotation: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefFlavor {
    Function,
    Class,
}

pub(crate) struct DefSite {
    pub(crate) enclosing_scope: usize,
    pub(crate) own_scope: usize,
    pub(crate) name: String,
    pub(crate) name_range: TextRange,
    pub(crate) flavor: DefFlavor,
    pub(crate) decorated: bool,
    pub(crate) tf_traced: bool,
    pub(crate) params: Vec<(String, TextRange)>,
}

pub(crate) struct SymbolTable {
    pub(crate) scopes: Vec<SymbolScope>,
    pub(crate) resolved_loads: Vec<LoadRecord>,
    pub(crate) def_sites: Vec<DefSite>,
    pub(crate) attr_writes: Vec<(String, TextRange)>,
}

/// Cross-file lexical facts used to veto reports conservatively.
pub(crate) struct FileFacts {
    pub(crate) token_names: Vec<(String, TextRange)>,
    pub(crate) attr_reads: Vec<(String, TextRange)>,
    pub(crate) called_names: HashSet<String>,
    pub(crate) string_texts: Vec<String>,
    pub(crate) dynamic_names: bool,
    pub(crate) has_wildcard_import: bool,
}

fn bind_symbol(
    scope: &mut SymbolScope,
    name: &str,
    range: TextRange,
    kind: BindingKind,
    loop_depth: u32,
) {
    scope
        .bindings
        .entry(name.to_string())
        .or_default()
        .push(Binding {
            range,
            kind,
            loop_depth,
        });
}

fn push_symbol_scope(table: &mut SymbolTable, kind: ScopeKind, parent: usize) -> usize {
    table.scopes.push(SymbolScope::new(kind, Some(parent)));
    table.scopes.len() - 1
}

pub(crate) fn build_symbol_table(parsed: &Parsed<ModModule>) -> SymbolTable {
    let mut table = SymbolTable {
        scopes: vec![SymbolScope::new(ScopeKind::Module, None)],
        resolved_loads: Vec::new(),
        def_sites: Vec::new(),
        attr_writes: Vec::new(),
    };
    collect_scope_stmts(&mut table, 0, parsed.syntax().body.as_slice(), 0);
    resolve_symbol_loads(&mut table);
    table
}

fn collect_scope_stmts(table: &mut SymbolTable, current: usize, suite: &[Stmt], loop_depth: u32) {
    for stmt in suite {
        collect_scope_stmt(table, current, stmt, loop_depth);
    }
}

fn collect_scope_stmt(table: &mut SymbolTable, current: usize, stmt: &Stmt, loop_depth: u32) {
    match stmt {
        Stmt::Assign(_) | Stmt::AnnAssign(_) | Stmt::AugAssign(_) => {
            record_assignment_stmt(table, current, stmt, loop_depth);
        }
        Stmt::Import(_) | Stmt::ImportFrom(_) => {
            record_import_stmt(table, current, stmt, loop_depth);
        }
        Stmt::Global(global_stmt) => record_global_stmt(table, current, global_stmt),
        Stmt::Nonlocal(nonlocal_stmt) => record_nonlocal_stmt(table, current, nonlocal_stmt),
        Stmt::For(loop_stmt) => {
            record_expr_loads(table, current, &loop_stmt.iter, false, loop_depth);
            record_store_target(
                table,
                current,
                &loop_stmt.target,
                BindingKind::Assignment,
                loop_depth + 1,
            );
            collect_scope_stmts(table, current, &loop_stmt.body, loop_depth + 1);
            collect_scope_stmts(table, current, &loop_stmt.orelse, loop_depth);
        }
        Stmt::While(while_stmt) => {
            record_expr_loads(table, current, &while_stmt.test, false, loop_depth);
            collect_scope_stmts(table, current, &while_stmt.body, loop_depth + 1);
            collect_scope_stmts(table, current, &while_stmt.orelse, loop_depth);
        }
        Stmt::If(if_stmt) => collect_if_stmt(table, current, if_stmt, loop_depth),
        Stmt::With(with_stmt) => collect_with_stmt(table, current, with_stmt, loop_depth),
        Stmt::Try(try_stmt) => {
            collect_try_stmt(table, current, try_stmt, loop_depth);
        }
        Stmt::FunctionDef(function) => {
            collect_function_def(table, current, function, loop_depth);
        }
        Stmt::ClassDef(class) => {
            collect_class_def(table, current, class, loop_depth);
        }
        Stmt::Match(match_stmt) => {
            record_expr_loads(table, current, &match_stmt.subject, false, loop_depth);
            for case in &match_stmt.cases {
                if let Some(guard) = case.guard.as_deref() {
                    record_expr_loads(table, current, guard, false, loop_depth);
                }
                record_pattern_bindings(table, current, &case.pattern, loop_depth);
                collect_scope_stmts(table, current, &case.body, loop_depth);
            }
        }
        _ => {
            for expr in stmt_exprs(stmt) {
                record_expr_loads(table, current, expr, false, loop_depth);
            }
            for body in child_bodies(stmt) {
                collect_scope_stmts(table, current, body, loop_depth);
            }
        }
    }
}

/// Records names exported to module/global scope by a `global` statement.
fn record_global_stmt(table: &mut SymbolTable, current: usize, global_stmt: &StmtGlobal) {
    table.scopes[current].global_names.extend(
        global_stmt
            .names
            .iter()
            .map(|name| name.as_str().to_string()),
    );
}

/// Records names bound to enclosing function scopes by a `nonlocal` statement.
fn record_nonlocal_stmt(table: &mut SymbolTable, current: usize, nonlocal_stmt: &StmtNonlocal) {
    table.scopes[current].nonlocal_names.extend(
        nonlocal_stmt
            .names
            .iter()
            .map(|name| name.as_str().to_string()),
    );
}

/// Scans an `if` statement: its test plus every elif/else clause body.
fn collect_if_stmt(table: &mut SymbolTable, current: usize, if_stmt: &StmtIf, loop_depth: u32) {
    record_expr_loads(table, current, &if_stmt.test, false, loop_depth);
    collect_scope_stmts(table, current, &if_stmt.body, loop_depth);
    for clause in &if_stmt.elif_else_clauses {
        if let Some(test) = clause.test.as_ref() {
            record_expr_loads(table, current, test, false, loop_depth);
        }
        collect_scope_stmts(table, current, &clause.body, loop_depth);
    }
}

/// Scans a `with` statement: context expressions, `as` targets, and body.
fn collect_with_stmt(
    table: &mut SymbolTable,
    current: usize,
    with_stmt: &StmtWith,
    loop_depth: u32,
) {
    for item in &with_stmt.items {
        record_expr_loads(table, current, &item.context_expr, false, loop_depth);
        if let Some(vars) = item.optional_vars.as_deref() {
            record_store_target(table, current, vars, BindingKind::Assignment, loop_depth);
        }
    }
    collect_scope_stmts(table, current, &with_stmt.body, loop_depth);
}

/// Walks a structural `match` pattern: binds capture names (`MatchAs.name`,
/// `MatchStar.name`, `MatchMapping.rest`) into the current scope and records
/// loads from the pattern's expressions (`MatchValue` values, mapping keys,
/// class patterns), mirroring PEP 634 evaluation order.
fn record_pattern_bindings(
    table: &mut SymbolTable,
    current: usize,
    pattern: &Pattern,
    loop_depth: u32,
) {
    match pattern {
        Pattern::MatchValue(value) => {
            record_expr_loads(table, current, &value.value, false, loop_depth);
        }
        Pattern::MatchSingleton(_) => {}
        Pattern::MatchSequence(sequence) => {
            for element in &sequence.patterns {
                record_pattern_bindings(table, current, element, loop_depth);
            }
        }
        Pattern::MatchMapping(mapping) => {
            for key in &mapping.keys {
                record_expr_loads(table, current, key, false, loop_depth);
            }
            for subpattern in &mapping.patterns {
                record_pattern_bindings(table, current, subpattern, loop_depth);
            }
            if let Some(rest) = &mapping.rest {
                bind_symbol(
                    &mut table.scopes[current],
                    rest.as_str(),
                    rest.range(),
                    BindingKind::Assignment,
                    loop_depth,
                );
            }
        }
        Pattern::MatchClass(class) => {
            record_expr_loads(table, current, &class.cls, false, loop_depth);
            for argument in &class.arguments.patterns {
                record_pattern_bindings(table, current, argument, loop_depth);
            }
            for keyword in &class.arguments.keywords {
                record_pattern_bindings(table, current, &keyword.pattern, loop_depth);
            }
        }
        Pattern::MatchStar(star) => {
            if let Some(name) = &star.name {
                bind_symbol(
                    &mut table.scopes[current],
                    name.as_str(),
                    name.range(),
                    BindingKind::Assignment,
                    loop_depth,
                );
            }
        }
        Pattern::MatchAs(as_pattern) => {
            if let Some(subpattern) = as_pattern.pattern.as_deref() {
                record_pattern_bindings(table, current, subpattern, loop_depth);
            }
            if let Some(name) = &as_pattern.name {
                bind_symbol(
                    &mut table.scopes[current],
                    name.as_str(),
                    name.range(),
                    BindingKind::Assignment,
                    loop_depth,
                );
            }
        }
        Pattern::MatchOr(or_pattern) => {
            for alternative in &or_pattern.patterns {
                record_pattern_bindings(table, current, alternative, loop_depth);
            }
        }
    }
}

fn record_assignment_stmt(table: &mut SymbolTable, current: usize, stmt: &Stmt, loop_depth: u32) {
    match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                record_store_target(table, current, target, BindingKind::Assignment, loop_depth);
            }
            record_expr_loads(table, current, &assign.value, false, loop_depth);
        }
        Stmt::AnnAssign(annotated) => {
            record_store_target(
                table,
                current,
                &annotated.target,
                BindingKind::Assignment,
                loop_depth,
            );
            record_expr_loads(table, current, &annotated.annotation, true, loop_depth);
            if let Some(value) = annotated.value.as_deref() {
                record_expr_loads(table, current, value, false, loop_depth);
            }
        }
        Stmt::AugAssign(augmented) => {
            if let Expr::Name(name) = augmented.target.as_ref() {
                table.scopes[current].loads.push((
                    name.id.as_str().to_string(),
                    name.range(),
                    false,
                ));
            }
            record_store_target(
                table,
                current,
                &augmented.target,
                BindingKind::Assignment,
                loop_depth,
            );
            record_expr_loads(table, current, &augmented.value, false, loop_depth);
        }
        _ => {}
    }
}

fn record_import_stmt(table: &mut SymbolTable, current: usize, stmt: &Stmt, loop_depth: u32) {
    let aliases: &[ruff_python_ast::Alias] = match stmt {
        Stmt::Import(import_stmt) => &import_stmt.names,
        Stmt::ImportFrom(import_from) => {
            if import_from
                .module
                .as_ref()
                .is_some_and(|module| module.as_str() == "__future__")
            {
                return;
            }
            &import_from.names
        }
        _ => return,
    };
    for alias in aliases {
        if let Some(binding_name) = import_binding_name(alias) {
            bind_symbol(
                &mut table.scopes[current],
                &binding_name,
                alias.range(),
                BindingKind::Import,
                loop_depth,
            );
        }
    }
}

fn collect_try_stmt(
    table: &mut SymbolTable,
    current: usize,
    try_stmt: &ruff_python_ast::StmtTry,
    loop_depth: u32,
) {
    collect_scope_stmts(table, current, &try_stmt.body, loop_depth);
    for handler in &try_stmt.handlers {
        let ExceptHandler::ExceptHandler(inner) = handler;
        if let Some(type_expr) = inner.type_.as_deref() {
            record_expr_loads(table, current, type_expr, false, loop_depth);
        }
        if let Some(bound) = &inner.name {
            bind_symbol(
                &mut table.scopes[current],
                bound.as_str(),
                bound.range(),
                BindingKind::ExceptName,
                loop_depth,
            );
        }
        collect_scope_stmts(table, current, &inner.body, loop_depth);
    }
    collect_scope_stmts(table, current, &try_stmt.orelse, loop_depth);
    collect_scope_stmts(table, current, &try_stmt.finalbody, loop_depth);
}

fn collect_function_def(
    table: &mut SymbolTable,
    current: usize,
    function: &ruff_python_ast::StmtFunctionDef,
    loop_depth: u32,
) {
    for decorator in &function.decorator_list {
        record_expr_loads(table, current, &decorator.expression, false, loop_depth);
    }
    bind_symbol(
        &mut table.scopes[current],
        function.name.as_str(),
        function.name.range(),
        BindingKind::Definition,
        loop_depth,
    );
    let fn_scope = push_symbol_scope(table, ScopeKind::Function, current);
    let mut header_exprs: Vec<&Expr> = Vec::new();
    push_parameter_exprs(&function.parameters, &mut header_exprs);
    for expr in header_exprs {
        record_expr_loads(table, current, expr, false, loop_depth);
    }
    for parameter in named_parameters(&function.parameters) {
        bind_symbol(
            &mut table.scopes[fn_scope],
            parameter.parameter.name.as_str(),
            parameter.parameter.name.range(),
            BindingKind::Parameter,
            0,
        );
    }
    table.def_sites.push(DefSite {
        enclosing_scope: current,
        own_scope: fn_scope,
        name: function.name.as_str().to_string(),
        name_range: function.name.range(),
        flavor: DefFlavor::Function,
        decorated: !function.decorator_list.is_empty(),
        tf_traced: is_tf_function(function),
        params: named_parameters(&function.parameters)
            .iter()
            .map(|parameter| {
                (
                    parameter.parameter.name.as_str().to_string(),
                    parameter.parameter.name.range(),
                )
            })
            .collect(),
    });
    collect_scope_stmts(table, fn_scope, &function.body, 0);
}

fn collect_class_def(
    table: &mut SymbolTable,
    current: usize,
    class: &ruff_python_ast::StmtClassDef,
    loop_depth: u32,
) {
    for decorator in &class.decorator_list {
        record_expr_loads(table, current, &decorator.expression, false, loop_depth);
    }
    if let Some(arguments) = &class.arguments {
        for base in &arguments.args {
            record_expr_loads(table, current, base, false, loop_depth);
        }
        for keyword in &arguments.keywords {
            record_expr_loads(table, current, &keyword.value, false, loop_depth);
        }
    }
    bind_symbol(
        &mut table.scopes[current],
        class.name.as_str(),
        class.name.range(),
        BindingKind::Definition,
        loop_depth,
    );
    let class_scope = push_symbol_scope(table, ScopeKind::Class, current);
    collect_scope_stmts(table, class_scope, &class.body, 0);
    table.def_sites.push(DefSite {
        enclosing_scope: current,
        own_scope: class_scope,
        name: class.name.as_str().to_string(),
        name_range: class.name.range(),
        flavor: DefFlavor::Class,
        decorated: !class.decorator_list.is_empty(),
        tf_traced: false,
        params: Vec::new(),
    });
}

/// Records a binding-position expression: plain names become stores while
/// attribute/subscript roots stay reads of their container.
fn record_store_target(
    table: &mut SymbolTable,
    current: usize,
    target: &Expr,
    kind: BindingKind,
    loop_depth: u32,
) {
    match target {
        Expr::Name(name) => {
            bind_symbol(
                &mut table.scopes[current],
                name.id.as_str(),
                name.range(),
                kind,
                loop_depth,
            );
        }
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                record_store_target(table, current, element, kind, loop_depth);
            }
        }
        Expr::List(list) => {
            for element in &list.elts {
                record_store_target(table, current, element, kind, loop_depth);
            }
        }
        Expr::Starred(starred) => {
            record_store_target(table, current, &starred.value, kind, loop_depth);
        }
        Expr::Attribute(attribute) => {
            record_self_attribute_write(table, attribute, target.range());
            record_expr_loads(table, current, &attribute.value, false, loop_depth);
        }
        Expr::Subscript(subscript) => {
            record_expr_loads(table, current, &subscript.value, false, loop_depth);
            record_expr_loads(table, current, &subscript.slice, false, loop_depth);
        }
        _ => {}
    }
}

fn record_self_attribute_write(
    table: &mut SymbolTable,
    attribute: &ruff_python_ast::ExprAttribute,
    range: TextRange,
) {
    let mut cursor = attribute.value.as_ref();
    while let Expr::Attribute(enclosed) = cursor {
        cursor = enclosed.value.as_ref();
    }
    if let Expr::Name(root) = cursor
        && matches!(root.id.as_str(), "self" | "cls")
    {
        table
            .attr_writes
            .push((attribute.attr.as_str().to_string(), range));
    }
}

fn record_expr_loads(
    table: &mut SymbolTable,
    current: usize,
    expr: &Expr,
    in_annotation: bool,
    loop_depth: u32,
) {
    match expr {
        Expr::Name(name) => match name.ctx {
            ruff_python_ast::ExprContext::Store => {
                bind_symbol(
                    &mut table.scopes[current],
                    name.id.as_str(),
                    name.range(),
                    BindingKind::Assignment,
                    loop_depth,
                );
            }
            ruff_python_ast::ExprContext::Load | ruff_python_ast::ExprContext::Del => {
                table.scopes[current].loads.push((
                    name.id.as_str().to_string(),
                    name.range(),
                    in_annotation,
                ));
            }
            ruff_python_ast::ExprContext::Invalid => {}
        },
        Expr::Named(_)
        | Expr::Lambda(_)
        | Expr::ListComp(_)
        | Expr::SetComp(_)
        | Expr::Generator(_)
        | Expr::DictComp(_) => {
            record_scope_creating_expr(table, current, expr, in_annotation, loop_depth);
        }
        _ => {
            for child in child_exprs(expr) {
                record_expr_loads(table, current, child, in_annotation, loop_depth);
            }
        }
    }
}

/// Handles the expressions that open a nested scope: walrus targets bind in
/// the nearest non-comprehension ancestor, lambdas bind their parameters, and
/// comprehensions evaluate their iterables in the enclosing scope.
fn record_scope_creating_expr(
    table: &mut SymbolTable,
    current: usize,
    expr: &Expr,
    in_annotation: bool,
    loop_depth: u32,
) {
    match expr {
        Expr::Named(named) => {
            record_walrus_binding(table, current, named, in_annotation, loop_depth);
        }
        Expr::Lambda(lambda) => {
            record_lambda_scope(table, current, lambda, in_annotation);
        }
        Expr::ListComp(comp) => {
            record_sequence_comprehension(
                table,
                current,
                &comp.elt,
                &comp.generators,
                in_annotation,
                loop_depth,
            );
        }
        Expr::SetComp(comp) => {
            record_sequence_comprehension(
                table,
                current,
                &comp.elt,
                &comp.generators,
                in_annotation,
                loop_depth,
            );
        }
        Expr::Generator(comp) => {
            record_sequence_comprehension(
                table,
                current,
                &comp.elt,
                &comp.generators,
                in_annotation,
                loop_depth,
            );
        }
        Expr::DictComp(comp) => {
            let mut results: Vec<&Expr> = Vec::new();
            if let Some(key) = &comp.key {
                results.push(key);
            }
            results.push(&comp.value);
            record_comprehension_scope(
                table,
                current,
                &results,
                &comp.generators,
                in_annotation,
                loop_depth,
            );
        }
        _ => {}
    }
}

/// Binds a walrus target in the nearest non-comprehension ancestor scope
/// after scanning its value in place.
fn record_walrus_binding(
    table: &mut SymbolTable,
    current: usize,
    named: &ExprNamed,
    in_annotation: bool,
    loop_depth: u32,
) {
    record_expr_loads(table, current, &named.value, in_annotation, loop_depth);
    let mut target_scope = current;
    while matches!(table.scopes[target_scope].kind, ScopeKind::Comprehension) {
        match table.scopes[target_scope].parent {
            Some(parent) => target_scope = parent,
            None => break,
        }
    }
    if let Expr::Name(target) = named.target.as_ref() {
        bind_symbol(
            &mut table.scopes[target_scope],
            target.id.as_str(),
            target.range(),
            BindingKind::Assignment,
            loop_depth,
        );
    }
}

/// Binds lambda parameters in a fresh function scope and scans its body there.
fn record_lambda_scope(
    table: &mut SymbolTable,
    current: usize,
    lambda: &ExprLambda,
    in_annotation: bool,
) {
    let fn_scope = push_symbol_scope(table, ScopeKind::Function, current);
    if let Some(parameters) = &lambda.parameters {
        for parameter in named_parameters(parameters) {
            bind_symbol(
                &mut table.scopes[fn_scope],
                parameter.parameter.name.as_str(),
                parameter.parameter.name.range(),
                BindingKind::Parameter,
                0,
            );
        }
    }
    record_expr_loads(table, fn_scope, &lambda.body, in_annotation, 0);
}

/// Shared path for list/set/generator comprehensions whose sole result
/// expression is evaluated inside the new comprehension scope.
fn record_sequence_comprehension(
    table: &mut SymbolTable,
    current: usize,
    elt: &Expr,
    generators: &[Comprehension],
    in_annotation: bool,
    loop_depth: u32,
) {
    let results = [elt];
    record_comprehension_scope(
        table,
        current,
        &results,
        generators,
        in_annotation,
        loop_depth,
    );
}

fn record_comprehension_scope(
    table: &mut SymbolTable,
    current: usize,
    results: &[&Expr],
    generators: &[ruff_python_ast::Comprehension],
    in_annotation: bool,
    loop_depth: u32,
) {
    let comp_scope = push_symbol_scope(table, ScopeKind::Comprehension, current);
    for (index, generator) in generators.iter().enumerate() {
        let iter_scope = if index == 0 { current } else { comp_scope };
        record_expr_loads(
            table,
            iter_scope,
            &generator.iter,
            in_annotation,
            loop_depth,
        );
        record_store_target(
            table,
            comp_scope,
            &generator.target,
            BindingKind::Assignment,
            loop_depth,
        );
        for condition in &generator.ifs {
            record_expr_loads(table, comp_scope, condition, in_annotation, loop_depth);
        }
    }
    for result in results {
        record_expr_loads(table, comp_scope, result, in_annotation, loop_depth);
    }
}

fn resolve_symbol_loads(table: &mut SymbolTable) {
    let mut resolved = Vec::new();
    for scope_idx in 0..table.scopes.len() {
        let entries: Vec<(String, TextRange, bool)> = table.scopes[scope_idx].loads.clone();
        for (name, range, in_annotation) in entries {
            let target = resolve_name(table, scope_idx, &name);
            resolved.push(LoadRecord {
                scope: scope_idx,
                name,
                range,
                target,
                in_annotation,
            });
        }
    }
    table.resolved_loads = resolved;
}

/// Resolves a name from `start` through the scope chain. Functions and
/// comprehensions cannot see through an intervening class scope; unresolved
/// names fall back to the builtin table (`None`).
fn resolve_name(table: &SymbolTable, start: usize, name: &str) -> Option<usize> {
    let mut cursor = start;
    loop {
        let scope = &table.scopes[cursor];
        if scope.bindings.contains_key(name)
            || scope.global_names.iter().any(|declared| declared == name)
            || scope.nonlocal_names.iter().any(|declared| declared == name)
        {
            return Some(cursor);
        }
        let mut next = scope.parent?;
        if matches!(scope.kind, ScopeKind::Function | ScopeKind::Comprehension)
            && matches!(table.scopes[next].kind, ScopeKind::Class)
        {
            next = table.scopes[next].parent?;
        }
        cursor = next;
    }
}

pub(crate) fn scope_is_within(table: &SymbolTable, scope: usize, ancestor: usize) -> bool {
    let mut cursor = Some(scope);
    while let Some(current) = cursor {
        if current == ancestor {
            return true;
        }
        cursor = table.scopes[current].parent;
    }
    false
}

pub(crate) fn collect_file_facts(parsed: &Parsed<ModModule>, source: &str) -> FileFacts {
    let mut facts = FileFacts {
        token_names: Vec::new(),
        attr_reads: Vec::new(),
        called_names: HashSet::new(),
        string_texts: Vec::new(),
        dynamic_names: false,
        has_wildcard_import: false,
    };
    for token in parsed.tokens() {
        if token.kind() == TokenKind::Name {
            facts
                .token_names
                .push((source[token.range()].to_string(), token.range()));
        }
    }
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ImportFrom(import_from) = stmt
            && import_from
                .names
                .iter()
                .any(|alias| alias.name.as_str() == "*")
        {
            facts.has_wildcard_import = true;
        }
    });
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Call(call) = expr {
            if let Some(name) = called_name(&call.func) {
                facts.called_names.insert(name.to_string());
            }
            if matches!(
                called_name(&call.func),
                Some("locals" | "globals" | "eval" | "exec")
            ) {
                facts.dynamic_names = true;
            }
        }
        if let Expr::Attribute(attribute) = expr
            && matches!(attribute.ctx, ruff_python_ast::ExprContext::Load)
        {
            facts
                .attr_reads
                .push((attribute.attr.as_str().to_string(), expr.range()));
        }
    });
    facts.string_texts = collect_string_contents(parsed.syntax().body.as_slice())
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    facts
}

/// Token-net veto: `true` when the identifier appears anywhere outside the
/// excluded (definition) ranges. Never produces false positives for
/// unused-name rules because every plausible textual use counts.
pub(crate) fn name_used_in_tokens(facts: &FileFacts, name: &str, excluded: &[TextRange]) -> bool {
    facts.token_names.iter().any(|(token_name, range)| {
        token_name == name
            && !excluded.iter().any(|excluded_range| {
                excluded_range.start() <= range.start() && range.end() <= excluded_range.end()
            })
    })
}

pub(crate) fn scope_has_dynamic_declaration(scope: &SymbolScope, name: &str) -> bool {
    scope.global_names.iter().any(|n| n == name) || scope.nonlocal_names.iter().any(|n| n == name)
}

// --- python:S3985 / python:S5603 — unused nested definitions ------------------

pub(crate) fn definition_is_used(table: &SymbolTable, facts: &FileFacts, site: &DefSite) -> bool {
    table
        .resolved_loads
        .iter()
        .any(|load| load.target == Some(site.enclosing_scope) && load.name == site.name)
        || facts.called_names.contains(&site.name)
        || facts
            .string_texts
            .iter()
            .any(|text| text.contains(&site.name))
        || name_used_in_tokens(facts, &site.name, &[site.name_range])
}
