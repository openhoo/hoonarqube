use crate::engine::file_context::FileContext;
use crate::support::child_bodies;
use crate::support::for_each_expr;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use crate::support::string_value_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Pattern;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_constant_conditions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    collect_scope_issues(index, source, file_ctx.module_body, &mut issues);
    issues
}

// --- python:S5797 — constant conditions ---------------------------------------------------

pub(crate) fn constant_truth(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::BooleanLiteral(literal) => Some(literal.value),
        Expr::NoneLiteral(_) => Some(false),
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64().map(|value| value != 0),
            ruff_python_ast::Number::Float(value) => Some(*value != 0.0),
            ruff_python_ast::Number::Complex { .. } => None,
        },
        Expr::StringLiteral(literal) => Some(!string_value_text(&literal.value).is_empty()),
        Expr::BoolOp(bool_op) => {
            let operands: Option<Vec<bool>> = bool_op.values.iter().map(constant_truth).collect();
            operands.map(|operands| match bool_op.op {
                ruff_python_ast::BoolOp::And => operands.iter().all(|value| *value),
                ruff_python_ast::BoolOp::Or => operands.iter().any(|value| *value),
            })
        }
        _ => None,
    }
}

/// One binding fact inside a lexical scope. `block`/`pos` place the binding
/// statement within the scope's block numbering; `OPAQUE_BLOCK` marks facts
/// without a meaningful position (parameters, nested-scope mutations).
struct NameEvent<'a> {
    name: &'a str,
    kind: NameEventKind,
    block: u32,
    pos: usize,
}

#[derive(Clone, Copy)]
enum NameEventKind {
    /// Plain `name = <constant>` with exactly one bare-name target.
    Constant(bool),
    /// Any other bind or unbind: aug-assign, for/with targets, imports,
    /// tuple unpacking, `del`, walrus, annotations, nested definitions.
    OtherBinding,
    /// Names that must never propagate: parameters and `global`/`nonlocal`
    /// declarations.
    Opaque,
}

/// Block id for events whose position cannot anchor propagation.
const OPAQUE_BLOCK: u32 = u32::MAX;

#[derive(Default)]
struct ScopeFacts<'a> {
    events: Vec<NameEvent<'a>>,
}

impl<'a> ScopeFacts<'a> {
    fn push(&mut self, name: &'a str, kind: NameEventKind, block: u32, pos: usize) {
        self.events.push(NameEvent {
            name,
            kind,
            block,
            pos,
        });
    }
}

/// Reports constant conditions for one lexical scope, then recurses into the
/// scopes of nested `def`/`class` bodies with fresh facts.
fn collect_scope_issues<'a>(
    index: &LineIndex,
    source: &str,
    body: &'a [Stmt],
    issues: &mut Vec<Issue>,
) {
    let facts = collect_scope_facts(body);
    let mut nested_bodies: Vec<&'a [Stmt]> = Vec::new();
    let mut next_block = 0;
    for_each_scope_stmt(body, &mut next_block, &mut |stmt, block, pos| {
        report_condition_issue(stmt, block, pos, &facts, index, source, issues);
        if let Some(nested_body) = nested_scope_body(stmt) {
            nested_bodies.push(nested_body);
        }
    });
    for nested_body in nested_bodies {
        collect_scope_issues(index, source, nested_body, issues);
    }
}

/// Gathers every binding fact of one scope: its own statement lists, the
/// parameters of nested functions, and every binding inside nested
/// `def`/`class` subtrees (opaque mutations).
fn collect_scope_facts(body: &[Stmt]) -> ScopeFacts<'_> {
    let mut facts = ScopeFacts::default();
    let mut next_block = 0;
    for_each_scope_stmt(body, &mut next_block, &mut |stmt, block, pos| {
        record_binding(stmt, block, pos, &mut facts);
        if let Stmt::FunctionDef(function) = stmt {
            record_parameters(&function.parameters, &mut facts);
            record_nested_mutations(&function.body, &mut facts);
        } else if let Stmt::ClassDef(class) = stmt {
            record_nested_mutations(&class.body, &mut facts);
        }
    });
    facts
}

/// Visits every statement of the scope's own statement lists in pre-order,
/// handing each its block id and position. Nested `def`/`class` bodies are
/// separate scopes and are not entered.
fn for_each_scope_stmt<'a>(
    body: &'a [Stmt],
    next_block: &mut u32,
    visit: &mut impl FnMut(&'a Stmt, u32, usize),
) {
    let block = *next_block;
    *next_block += 1;
    for (pos, stmt) in body.iter().enumerate() {
        visit(stmt, block, pos);
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        for child in child_bodies(stmt) {
            for_each_scope_stmt(child, next_block, visit);
        }
    }
}

fn nested_scope_body(stmt: &Stmt) -> Option<&[Stmt]> {
    match stmt {
        Stmt::FunctionDef(function) => Some(function.body.as_slice()),
        Stmt::ClassDef(class) => Some(class.body.as_slice()),
        _ => None,
    }
}

fn report_condition_issue(
    stmt: &Stmt,
    block: u32,
    pos: usize,
    facts: &ScopeFacts,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let test = match stmt {
        Stmt::If(if_stmt) => &if_stmt.test,
        Stmt::While(while_stmt) => &while_stmt.test,
        _ => return,
    };
    if condition_truth(test, block, pos, facts).is_none() {
        return;
    }
    // `while <constant>:` is the idiomatic infinite/dead loop, not a
    // defect — Sonar exempts literal while conditions entirely.
    if matches!(stmt, Stmt::While(_)) && constant_truth(test).is_some() {
        return;
    }
    issues.push(issue_at(
        "python:S5797",
        "Replace this expression; used as a condition it will always be constant.",
        test.range(),
        index,
        source,
    ));
}

fn condition_truth(test: &Expr, block: u32, pos: usize, facts: &ScopeFacts) -> Option<bool> {
    if let Some(truth) = constant_truth(test) {
        return Some(truth);
    }
    let Expr::Name(name) = test else {
        return None;
    };
    propagated_truth(name.id.as_str(), block, pos, facts)
}

/// The single scope-wide binding of `name` decides propagation: exactly one
/// event, a constant assignment, in the same block strictly before the
/// condition. Any other binding anywhere in the scope — reassignment,
/// parameter, `global`/`nonlocal`, or a nested `def`/`class` mutation —
/// keeps the name open.
fn propagated_truth(name: &str, block: u32, pos: usize, facts: &ScopeFacts) -> Option<bool> {
    let mut matching = facts.events.iter().filter(|event| event.name == name);
    let event = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    match event.kind {
        NameEventKind::Constant(truth) if event.block == block && event.pos < pos => Some(truth),
        _ => None,
    }
}

fn record_binding<'a>(stmt: &'a Stmt, block: u32, pos: usize, facts: &mut ScopeFacts<'a>) {
    for_each_bound_name(stmt, &mut |name, kind| facts.push(name, kind, block, pos));
}

/// Records every binding inside a nested `def`/`class` subtree as opaque:
/// whether the inner binding is local or reaches the outer variable through
/// `nonlocal`/`global`, the outer constant can no longer be trusted (the
/// Click `join_options` case).
fn record_nested_mutations<'a>(body: &'a [Stmt], facts: &mut ScopeFacts<'a>) {
    for_each_stmt(body, &mut |stmt| {
        for_each_bound_name(stmt, &mut |name, _| {
            facts.push(name, NameEventKind::Opaque, OPAQUE_BLOCK, 0);
        });
    });
}

fn record_parameters<'a>(parameters: &'a ruff_python_ast::Parameters, facts: &mut ScopeFacts<'a>) {
    for param in parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
    {
        facts.push(
            param.parameter.name.as_str(),
            NameEventKind::Opaque,
            OPAQUE_BLOCK,
            0,
        );
    }
    for param in [&parameters.vararg, &parameters.kwarg]
        .into_iter()
        .flatten()
    {
        facts.push(param.name.as_str(), NameEventKind::Opaque, OPAQUE_BLOCK, 0);
    }
}

/// Yields every name bound or unbound by `stmt` together with its binding
/// kind: `Constant` only for a plain assignment whose single bare-name
/// target receives one constant value, `OtherBinding` otherwise.
fn for_each_bound_name<'a>(stmt: &'a Stmt, visit: &mut impl FnMut(&'a str, NameEventKind)) {
    for_each_target_binding(stmt, visit);
    for_each_header_binding(stmt, visit);
    // A walrus inside any expression of the statement rebinds its target in
    // this scope (lambda/comprehension-internal walruses conservatively
    // count as extra bindings, which only ever suppresses propagation).
    for expr in stmt_exprs(stmt) {
        for_each_expr(expr, &mut |expr| {
            if let Expr::Named(named) = expr {
                for_each_target_name(&named.target, NameEventKind::OtherBinding, visit);
            }
        });
    }
}

/// Target-style binders: the assignment family, loop/with targets, and `del`.
fn for_each_target_binding<'a>(stmt: &'a Stmt, visit: &mut impl FnMut(&'a str, NameEventKind)) {
    match stmt {
        Stmt::Assign(assign) => {
            let kind = constant_binding_kind(&assign.value);
            for target in &assign.targets {
                for_each_target_name(target, kind, visit);
            }
        }
        Stmt::AnnAssign(assign) => {
            if assign.value.is_some() {
                for_each_target_name(&assign.target, NameEventKind::OtherBinding, visit);
            }
        }
        Stmt::AugAssign(assign) => {
            for_each_target_name(assign.target.as_ref(), NameEventKind::OtherBinding, visit);
        }
        Stmt::For(loop_stmt) => {
            for_each_target_name(&loop_stmt.target, NameEventKind::OtherBinding, visit);
        }
        Stmt::With(with_stmt) => {
            for item in &with_stmt.items {
                if let Some(vars) = item.optional_vars.as_deref() {
                    for_each_target_name(vars, NameEventKind::OtherBinding, visit);
                }
            }
        }
        Stmt::Delete(delete) => {
            for target in &delete.targets {
                for_each_target_name(target, NameEventKind::OtherBinding, visit);
            }
        }
        _ => {}
    }
}

/// Header-style binders: match captures, `except as` names, imports,
/// def/class names, and `global`/`nonlocal` declarations.
fn for_each_header_binding<'a>(stmt: &'a Stmt, visit: &mut impl FnMut(&'a str, NameEventKind)) {
    match stmt {
        Stmt::Match(match_stmt) => {
            for case in &match_stmt.cases {
                for_each_pattern_name(&case.pattern, visit);
            }
        }
        Stmt::Try(try_stmt) => record_handler_names(&try_stmt.handlers, visit),
        Stmt::Import(import) => {
            for alias in &import.names {
                record_import_name(alias, visit);
            }
        }
        Stmt::ImportFrom(import_from) => {
            for alias in &import_from.names {
                record_import_name(alias, visit);
            }
        }
        Stmt::FunctionDef(function) => visit(function.name.as_str(), NameEventKind::OtherBinding),
        Stmt::ClassDef(class) => visit(class.name.as_str(), NameEventKind::OtherBinding),
        Stmt::Global(global) => {
            for name in &global.names {
                visit(name.as_str(), NameEventKind::Opaque);
            }
        }
        Stmt::Nonlocal(nonlocal) => {
            for name in &nonlocal.names {
                visit(name.as_str(), NameEventKind::Opaque);
            }
        }
        _ => {}
    }
}

fn constant_binding_kind(value: &Expr) -> NameEventKind {
    match constant_truth(value) {
        Some(truth) => NameEventKind::Constant(truth),
        None => NameEventKind::OtherBinding,
    }
}

/// Recurses through assignment-target shapes, yielding bare names; attribute
/// and subscript targets bind nothing in the local scope.
fn for_each_target_name<'a>(
    target: &'a Expr,
    kind: NameEventKind,
    visit: &mut impl FnMut(&'a str, NameEventKind),
) {
    match target {
        Expr::Name(name) => visit(name.id.as_str(), kind),
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                for_each_target_name(element, kind, visit);
            }
        }
        Expr::List(list) => {
            for element in &list.elts {
                for_each_target_name(element, kind, visit);
            }
        }
        Expr::Starred(starred) => for_each_target_name(&starred.value, kind, visit),
        _ => {}
    }
}

fn for_each_pattern_name<'a>(pattern: &'a Pattern, visit: &mut impl FnMut(&'a str, NameEventKind)) {
    match pattern {
        Pattern::MatchValue(_) | Pattern::MatchSingleton(_) => {}
        Pattern::MatchSequence(sequence) => {
            for element in &sequence.patterns {
                for_each_pattern_name(element, visit);
            }
        }
        Pattern::MatchMapping(mapping) => for_each_mapping_pattern_name(mapping, visit),
        Pattern::MatchClass(class) => for_each_class_pattern_name(class, visit),
        Pattern::MatchStar(star) => record_optional_pattern_name(star.name.as_ref(), visit),
        Pattern::MatchAs(as_pattern) => for_each_as_pattern_name(as_pattern, visit),
        Pattern::MatchOr(or_pattern) => {
            for alternative in &or_pattern.patterns {
                for_each_pattern_name(alternative, visit);
            }
        }
    }
}

fn for_each_mapping_pattern_name<'a>(
    mapping: &'a ruff_python_ast::PatternMatchMapping,
    visit: &mut impl FnMut(&'a str, NameEventKind),
) {
    for subpattern in &mapping.patterns {
        for_each_pattern_name(subpattern, visit);
    }
    record_optional_pattern_name(mapping.rest.as_ref(), visit);
}

fn for_each_class_pattern_name<'a>(
    class: &'a ruff_python_ast::PatternMatchClass,
    visit: &mut impl FnMut(&'a str, NameEventKind),
) {
    for argument in &class.arguments.patterns {
        for_each_pattern_name(argument, visit);
    }
    for keyword in &class.arguments.keywords {
        for_each_pattern_name(&keyword.pattern, visit);
    }
}

fn for_each_as_pattern_name<'a>(
    as_pattern: &'a ruff_python_ast::PatternMatchAs,
    visit: &mut impl FnMut(&'a str, NameEventKind),
) {
    if let Some(subpattern) = as_pattern.pattern.as_deref() {
        for_each_pattern_name(subpattern, visit);
    }
    record_optional_pattern_name(as_pattern.name.as_ref(), visit);
}

fn record_optional_pattern_name<'a>(
    name: Option<&'a ruff_python_ast::Identifier>,
    visit: &mut impl FnMut(&'a str, NameEventKind),
) {
    if let Some(name) = name {
        visit(name.as_str(), NameEventKind::OtherBinding);
    }
}

fn record_handler_names<'a>(
    handlers: &'a [ruff_python_ast::ExceptHandler],
    visit: &mut impl FnMut(&'a str, NameEventKind),
) {
    for handler in handlers {
        let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
        if let Some(name) = &handler.name {
            visit(name.as_str(), NameEventKind::OtherBinding);
        }
    }
}

/// The name a single import alias binds: the `as` name, or for plain
/// imports the first segment of the dotted module path.
fn import_alias_name(alias: &ruff_python_ast::Alias) -> Option<&str> {
    if let Some(as_name) = &alias.asname {
        return Some(as_name.as_str());
    }
    alias.name.as_str().split('.').next()
}

fn record_import_name<'a>(
    alias: &'a ruff_python_ast::Alias,
    visit: &mut impl FnMut(&'a str, NameEventKind),
) {
    if let Some(name) = import_alias_name(alias) {
        visit(name, NameEventKind::OtherBinding);
    }
}
