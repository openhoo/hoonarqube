use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::{
    child_bodies, child_exprs, collect_target_names, issue_at, named_parameters, stmt_exprs,
    stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, FStringPart, InterpolatedStringElement, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};
use std::collections::{HashMap, HashSet};

// --- python:S2077 — SQL queries built through string formatting ----------------

const MESSAGE: &str = "Make sure that formatting this SQL query is safe here.";

pub(crate) fn check_s2077_sql_formatting(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !is_s2077_execute_sink(call, file_ctx) {
            continue;
        }
        let Some(query) = query_argument(call) else {
            continue;
        };
        let mut resolver = QueryResolver::new(file_ctx);
        if resolver.formatted_query(query) {
            issues.push(issue_at(
                "python:S2077",
                MESSAGE,
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn is_s2077_execute_sink(call: &ExprCall, file_ctx: &FileContext) -> bool {
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return false;
    };
    attribute.attr.as_str() == "execute"
        && file_ctx.known_bindings.resolve_call(call) == KnownBinding::DjangoCursorExecute
}

fn query_argument(call: &ExprCall) -> Option<&Expr> {
    call.arguments.args.first().or_else(|| {
        call.arguments
            .keywords
            .iter()
            .find_map(|keyword| (keyword.arg.as_deref() == Some("sql")).then_some(&keyword.value))
    })
}

/// Mirrors `SonarPython`'s `FormattedStringVisitor`: the query itself is the
/// interesting value, not whether it happens to begin with an SQL keyword.
fn is_formatted_expression(expr: &Expr) -> bool {
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        match expr {
            Expr::FString(f_string)
                if f_string.value.iter().any(|part| {
                    matches!(
                        part,
                        FStringPart::FString(interpolated)
                            if interpolated.elements.iter().any(|element| {
                                matches!(element, InterpolatedStringElement::Interpolation(_))
                            })
                    )
                }) =>
            {
                return true;
            }
            Expr::Call(call)
                if matches!(
                    call.func.as_ref(),
                    Expr::Attribute(attribute)
                        if attribute.attr.as_str() == "format"
                            && matches!(attribute.value.as_ref(), Expr::StringLiteral(_))
                ) =>
            {
                return true;
            }
            Expr::BinOp(binop)
                if matches!(binop.left.as_ref(), Expr::StringLiteral(_))
                    || matches!(binop.right.as_ref(), Expr::StringLiteral(_)) =>
            {
                return true;
            }
            _ => pending.extend(child_exprs(expr)),
        }
    }
    false
}

const MAX_REACHING_VALUES: usize = 8;
const MAX_NAME_RESOLUTION_DEPTH: usize = 32;

#[derive(Clone, Copy)]
struct Definition<'a> {
    value: &'a Expr,
    range: TextRange,
}

#[derive(Clone, Copy)]
enum ReachingValue<'a> {
    Unknown,
    Definition(Definition<'a>),
}

#[derive(Clone)]
struct FlowState<'a> {
    bindings: HashMap<String, Vec<ReachingValue<'a>>>,
}

impl<'a> FlowState<'a> {
    fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    fn mark_unknown(&mut self, name: &str) {
        self.bindings
            .insert(name.to_string(), vec![ReachingValue::Unknown]);
    }

    fn set_definition(&mut self, name: &str, definition: Definition<'a>) {
        self.bindings.insert(
            name.to_string(),
            vec![ReachingValue::Definition(definition)],
        );
    }

    fn values(&self, name: &str) -> Option<&[ReachingValue<'a>]> {
        self.bindings.get(name).map(Vec::as_slice)
    }

    fn join(&self, other: &Self) -> Self {
        let mut joined = self.clone();
        joined.join_in_place(other);
        joined
    }

    fn join_in_place(&mut self, other: &Self) {
        let names: HashSet<String> = self
            .bindings
            .keys()
            .chain(other.bindings.keys())
            .cloned()
            .collect();
        for name in names {
            let left = self.bindings.get(&name).cloned();
            let right = other.bindings.get(&name).cloned();
            let mut values = Vec::new();
            append_reaching_values(left.as_deref(), &mut values);
            append_reaching_values(right.as_deref(), &mut values);
            self.bindings.insert(name, values);
        }
    }
}

fn append_reaching_values<'a>(
    source: Option<&[ReachingValue<'a>]>,
    target: &mut Vec<ReachingValue<'a>>,
) {
    let Some(source) = source else {
        push_reaching_value(target, ReachingValue::Unknown);
        return;
    };
    for value in source {
        push_reaching_value(target, *value);
    }
}

fn push_reaching_value<'a>(target: &mut Vec<ReachingValue<'a>>, value: ReachingValue<'a>) {
    if target
        .iter()
        .any(|existing| same_reaching_value(*existing, value))
    {
        return;
    }
    if target.len() == MAX_REACHING_VALUES {
        target.clear();
        target.push(ReachingValue::Unknown);
        return;
    }
    target.push(value);
}

fn same_reaching_value<'a>(left: ReachingValue<'a>, right: ReachingValue<'a>) -> bool {
    match (left, right) {
        (ReachingValue::Unknown, ReachingValue::Unknown) => true,
        (ReachingValue::Definition(left), ReachingValue::Definition(right)) => {
            left.range == right.range
        }
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Function,
    Class,
}

#[derive(Clone, Copy)]
struct ScopeRef<'a> {
    kind: ScopeKind,
    body: &'a [Stmt],
    range: TextRange,
    owner: Option<TextRange>,
}

struct QueryResolver<'ctx, 'ast> {
    file_ctx: &'ctx FileContext<'ast>,
    visiting: HashSet<(String, TextRange)>,
}

impl<'ctx, 'ast> QueryResolver<'ctx, 'ast> {
    fn new(file_ctx: &'ctx FileContext<'ast>) -> Self {
        Self {
            file_ctx,
            visiting: HashSet::new(),
        }
    }

    fn formatted_query(&mut self, expr: &Expr) -> bool {
        self.formatted_expression(expr, expr.range())
    }

    fn formatted_expression(&mut self, expr: &Expr, use_range: TextRange) -> bool {
        match expr {
            Expr::Name(name) => {
                if self.visiting.len() >= MAX_NAME_RESOLUTION_DEPTH {
                    return false;
                }
                let state = self.state_before_expression(expr);
                let chain = self.scope_chain(expr.range());
                self.resolve_name(name.id.as_str(), &state, &chain, 0, use_range)
            }
            Expr::Named(named) => self.formatted_expression(&named.value, use_range),
            _ => is_formatted_expression(expr),
        }
    }

    fn resolve_name(
        &mut self,
        name: &str,
        state: &FlowState<'ast>,
        chain: &[ScopeRef<'ast>],
        scope_index: usize,
        use_range: TextRange,
    ) -> bool {
        let Some(values) = state.values(name) else {
            return scope_index
                .checked_add(1)
                .filter(|next| *next < chain.len())
                .is_some_and(|next| {
                    if chain[scope_index].owner.is_none() {
                        return false;
                    }
                    let parent_state = self.state_before_scope(chain[next], use_range);
                    self.resolve_name(name, &parent_state, chain, next, use_range)
                });
        };
        let [ReachingValue::Definition(definition)] = values else {
            return false;
        };
        let key = (name.to_string(), definition.range);
        if !self.visiting.insert(key.clone()) {
            return false;
        }
        let result = self.formatted_expression(definition.value, definition.range);
        self.visiting.remove(&key);
        result
    }

    fn state_before_expression(&self, expr: &Expr) -> FlowState<'ast> {
        let chain = self.scope_chain(expr.range());
        self.state_before_scope(chain[0], expr.range())
    }

    fn state_before_scope(&self, scope: ScopeRef<'ast>, target: TextRange) -> FlowState<'ast> {
        let mut state = self.initial_state(scope);
        if let Some(found) = self.walk_suite(scope.body, &mut state, target) {
            found
        } else {
            state
        }
    }

    fn initial_state(&self, scope: ScopeRef<'ast>) -> FlowState<'ast> {
        let mut state = FlowState::new();
        if scope.kind != ScopeKind::Function {
            return state;
        }
        let mut names = HashSet::new();
        let mut globals = HashSet::new();
        let mut nonlocals = HashSet::new();
        collect_scope_names(scope.body, &mut names, &mut globals, &mut nonlocals);
        if let Some(owner) = scope.owner
            && let Some(function) = self
                .file_ctx
                .functions
                .iter()
                .find(|function| function.range() == owner)
        {
            for parameter in named_parameters(&function.parameters) {
                names.insert(parameter.parameter.name.as_str().to_string());
            }
            for parameter in [
                function.parameters.vararg.as_deref(),
                function.parameters.kwarg.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                names.insert(parameter.name.as_str().to_string());
            }
        }
        names.retain(|name| !globals.contains(name) && !nonlocals.contains(name));
        for name in names {
            state.mark_unknown(&name);
        }
        state
    }

    fn scope_chain(&self, range: TextRange) -> Vec<ScopeRef<'ast>> {
        let mut nested = Vec::new();
        for function in &self.file_ctx.functions {
            let scope_range = body_range(&function.body, function.range());
            if contains_range(scope_range, range) {
                nested.push(ScopeRef {
                    kind: ScopeKind::Function,
                    body: function.body.as_slice(),
                    range: scope_range,
                    owner: Some(function.range()),
                });
            }
        }
        for class in &self.file_ctx.classes {
            let scope_range = body_range(&class.body, class.range());
            if contains_range(scope_range, range) {
                nested.push(ScopeRef {
                    kind: ScopeKind::Class,
                    body: class.body.as_slice(),
                    range: scope_range,
                    owner: Some(class.range()),
                });
            }
        }
        nested.sort_by_key(|scope| u32::from(scope.range.end()) - u32::from(scope.range.start()));
        nested.push(ScopeRef {
            kind: ScopeKind::Module,
            body: self.file_ctx.module_body,
            range: TextRange::new(TextSize::new(0), TextSize::new(u32::MAX)),
            owner: None,
        });

        let mut chain = Vec::new();
        let mut index = 0;
        while index < nested.len() {
            let scope = nested[index];
            chain.push(scope);
            index += 1;
            if scope.kind == ScopeKind::Function {
                while index < nested.len() && nested[index].kind == ScopeKind::Class {
                    index += 1;
                }
            }
        }
        chain
    }

    fn walk_suite(
        &self,
        body: &'ast [Stmt],
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        for statement in body {
            if target.end() <= statement.range().start() {
                break;
            }
            if let Some(found) = self.visit_statement(statement, state, target) {
                return Some(found);
            }
        }
        None
    }

    fn visit_statement(
        &self,
        statement: &'ast Stmt,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        match statement {
            Stmt::Assign(assign) => self.visit_assign_statement(assign, state, target),
            Stmt::AnnAssign(assign) => self.visit_ann_assign_statement(assign, state, target),
            Stmt::AugAssign(assign) => self.visit_aug_assign_statement(assign, state, target),
            Stmt::Delete(delete) => self.visit_delete_statement(delete, state, target),
            Stmt::If(if_stmt) => self.visit_if_statement(if_stmt, state, target),
            Stmt::For(for_stmt) => self.visit_for_statement(for_stmt, state, target),
            Stmt::While(while_stmt) => self.visit_while_statement(while_stmt, state, target),
            Stmt::With(with_stmt) => self.visit_with_statement(with_stmt, state, target),
            Stmt::Try(try_stmt) => self.visit_try_statement(try_stmt, state, target),
            Stmt::Match(match_stmt) => self.visit_match_statement(match_stmt, state, target),
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {
                self.visit_definition_statement(statement, state, target)
            }
            Stmt::Import(_) | Stmt::ImportFrom(_) => {
                Self::visit_import_statement(statement, state, target)
            }
            Stmt::TypeAlias(type_alias) => {
                self.visit_type_alias_statement(type_alias, state, target)
            }
            _ => self.visit_other_statement(statement, state, target),
        }
    }

    fn visit_assign_statement(
        &self,
        assign: &'ast ruff_python_ast::StmtAssign,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&assign.value, state, target) {
            return Some(found);
        }
        let definition = Definition {
            value: assign.value.as_ref(),
            range: assign.value.range(),
        };
        for target_expr in &assign.targets {
            Self::assign_target(target_expr, state, definition);
        }
        None
    }

    fn visit_ann_assign_statement(
        &self,
        assign: &'ast ruff_python_ast::StmtAnnAssign,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&assign.annotation, state, target) {
            return Some(found);
        }
        if let Some(value) = assign.value.as_deref() {
            if let Some(found) = self.visit_expression(value, state, target) {
                return Some(found);
            }
            let definition = Definition {
                value,
                range: value.range(),
            };
            Self::assign_target(&assign.target, state, definition);
        } else {
            Self::mark_target_unknown(&assign.target, state);
        }
        None
    }

    fn visit_aug_assign_statement(
        &self,
        assign: &'ast ruff_python_ast::StmtAugAssign,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&assign.target, state, target) {
            return Some(found);
        }
        if let Some(found) = self.visit_expression(&assign.value, state, target) {
            return Some(found);
        }
        Self::mark_target_unknown(&assign.target, state);
        None
    }

    fn visit_delete_statement(
        &self,
        delete: &'ast ruff_python_ast::StmtDelete,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        for target_expr in &delete.targets {
            if let Some(found) = self.visit_expression(target_expr, state, target) {
                return Some(found);
            }
            Self::mark_target_unknown(target_expr, state);
        }
        None
    }

    fn visit_if_statement(
        &self,
        if_stmt: &'ast ruff_python_ast::StmtIf,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&if_stmt.test, state, target) {
            return Some(found);
        }
        let incoming = state.clone();
        let mut outputs = Vec::new();
        let mut branch = incoming.clone();
        if let Some(found) = self.walk_suite(&if_stmt.body, &mut branch, target) {
            return Some(found);
        }
        outputs.push(branch);
        if let Some(found) = self.visit_if_clauses(if_stmt, &incoming, &mut outputs, target) {
            return Some(found);
        }
        if if_stmt
            .elif_else_clauses
            .last()
            .is_none_or(|clause| clause.test.is_some())
        {
            outputs.push(incoming);
        }
        *state = join_states(outputs);
        None
    }

    fn visit_if_clauses(
        &self,
        if_stmt: &'ast ruff_python_ast::StmtIf,
        incoming: &FlowState<'ast>,
        outputs: &mut Vec<FlowState<'ast>>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        for clause in &if_stmt.elif_else_clauses {
            let mut clause_state = incoming.clone();
            if let Some(test) = clause.test.as_ref()
                && let Some(found) = self.visit_expression(test, &mut clause_state, target)
            {
                return Some(found);
            }
            if let Some(found) = self.walk_suite(&clause.body, &mut clause_state, target) {
                return Some(found);
            }
            outputs.push(clause_state);
        }
        None
    }

    fn visit_for_statement(
        &self,
        for_stmt: &'ast ruff_python_ast::StmtFor,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&for_stmt.iter, state, target) {
            return Some(found);
        }
        let incoming = state.clone();
        let mut body_state = incoming.clone();
        Self::mark_target_unknown(&for_stmt.target, &mut body_state);
        if let Some(found) = self.walk_suite(&for_stmt.body, &mut body_state, target) {
            return Some(found);
        }
        let mut orelse_state = body_state.clone();
        if let Some(found) = self.walk_suite(&for_stmt.orelse, &mut orelse_state, target) {
            return Some(found);
        }
        *state = incoming.join(&body_state).join(&orelse_state);
        None
    }

    fn visit_while_statement(
        &self,
        while_stmt: &'ast ruff_python_ast::StmtWhile,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&while_stmt.test, state, target) {
            return Some(found);
        }
        let incoming = state.clone();
        let mut body_state = incoming.clone();
        if let Some(found) = self.walk_suite(&while_stmt.body, &mut body_state, target) {
            return Some(found);
        }
        let mut orelse_state = body_state.clone();
        if let Some(found) = self.walk_suite(&while_stmt.orelse, &mut orelse_state, target) {
            return Some(found);
        }
        *state = incoming.join(&body_state).join(&orelse_state);
        None
    }

    fn visit_with_statement(
        &self,
        with_stmt: &'ast ruff_python_ast::StmtWith,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        let incoming = state.clone();
        for item in &with_stmt.items {
            if let Some(found) = self.visit_expression(&item.context_expr, state, target) {
                return Some(found);
            }
            if let Some(target_expr) = item.optional_vars.as_deref() {
                Self::mark_target_unknown(target_expr, state);
            }
        }
        if let Some(found) = self.walk_suite(&with_stmt.body, state, target) {
            return Some(found);
        }
        *state = incoming.join(state);
        None
    }

    fn visit_try_statement(
        &self,
        try_stmt: &'ast ruff_python_ast::StmtTry,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        let incoming = state.clone();
        let mut normal = incoming.clone();
        if let Some(found) = self.walk_suite(&try_stmt.body, &mut normal, target) {
            return Some(found);
        }
        if !try_stmt.orelse.is_empty()
            && let Some(found) = self.walk_suite(&try_stmt.orelse, &mut normal, target)
        {
            return Some(found);
        }
        let mut outputs = vec![normal];
        if let Some(found) = self.visit_try_handlers(try_stmt, &incoming, &mut outputs, target) {
            return Some(found);
        }
        *state = join_states(outputs);
        if let Some(found) = self.walk_suite(&try_stmt.finalbody, state, target) {
            return Some(found);
        }
        None
    }

    fn visit_try_handlers(
        &self,
        try_stmt: &'ast ruff_python_ast::StmtTry,
        incoming: &FlowState<'ast>,
        outputs: &mut Vec<FlowState<'ast>>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        for handler in &try_stmt.handlers {
            let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
            let mut handler_state = incoming.clone();
            if let Some(type_) = handler.type_.as_deref()
                && let Some(found) = self.visit_expression(type_, &mut handler_state, target)
            {
                return Some(found);
            }
            if let Some(name) = &handler.name {
                handler_state.mark_unknown(name.as_str());
            }
            if let Some(found) = self.walk_suite(&handler.body, &mut handler_state, target) {
                return Some(found);
            }
            outputs.push(handler_state);
        }
        None
    }

    fn visit_match_statement(
        &self,
        match_stmt: &'ast ruff_python_ast::StmtMatch,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&match_stmt.subject, state, target) {
            return Some(found);
        }
        let incoming = state.clone();
        let mut outputs = Vec::new();
        for case in &match_stmt.cases {
            let mut case_state = incoming.clone();
            if let Some(guard) = case.guard.as_deref()
                && let Some(found) = self.visit_expression(guard, &mut case_state, target)
            {
                return Some(found);
            }
            if let Some(found) = self.walk_suite(&case.body, &mut case_state, target) {
                return Some(found);
            }
            outputs.push(case_state);
        }
        outputs.push(incoming);
        *state = join_states(outputs);
        None
    }

    fn visit_definition_statement(
        &self,
        statement: &'ast Stmt,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        for expression in stmt_exprs(statement) {
            if let Some(found) = self.visit_expression(expression, state, target) {
                return Some(found);
            }
        }
        for name in stmt_store_names(statement) {
            state.mark_unknown(&name);
        }
        None
    }

    fn visit_import_statement(
        statement: &'ast Stmt,
        state: &mut FlowState<'ast>,
        _target: TextRange,
    ) -> Option<FlowState<'ast>> {
        for name in stmt_store_names(statement) {
            state.mark_unknown(&name);
        }
        None
    }

    fn visit_type_alias_statement(
        &self,
        type_alias: &'ast ruff_python_ast::StmtTypeAlias,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&type_alias.value, state, target) {
            return Some(found);
        }
        Self::mark_target_unknown(&type_alias.name, state);
        None
    }

    fn visit_other_statement(
        &self,
        statement: &'ast Stmt,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        for expression in stmt_exprs(statement) {
            if let Some(found) = self.visit_expression(expression, state, target) {
                return Some(found);
            }
        }
        for body in child_bodies(statement) {
            if let Some(found) = self.walk_suite(body, state, target) {
                return Some(found);
            }
        }
        None
    }

    fn visit_expression(
        &self,
        expression: &'ast Expr,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if expression.range() == target {
            return Some(state.clone());
        }
        match expression {
            Expr::Named(named) => self.visit_named_expression(named, state, target),
            Expr::If(if_expr) => self.visit_if_expression(if_expr, state, target),
            Expr::Lambda(_)
            | Expr::ListComp(_)
            | Expr::SetComp(_)
            | Expr::Generator(_)
            | Expr::DictComp(_) => None,
            _ => {
                for child in child_exprs(expression) {
                    if let Some(found) = self.visit_expression(child, state, target) {
                        return Some(found);
                    }
                }
                None
            }
        }
    }

    fn visit_named_expression(
        &self,
        named: &'ast ruff_python_ast::ExprNamed,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&named.value, state, target) {
            return Some(found);
        }
        if let Expr::Name(name) = named.target.as_ref() {
            let definition = Definition {
                value: named.value.as_ref(),
                range: named.value.range(),
            };
            state.set_definition(name.id.as_str(), definition);
        }
        None
    }

    fn visit_if_expression(
        &self,
        if_expr: &'ast ruff_python_ast::ExprIf,
        state: &mut FlowState<'ast>,
        target: TextRange,
    ) -> Option<FlowState<'ast>> {
        if let Some(found) = self.visit_expression(&if_expr.test, state, target) {
            return Some(found);
        }
        let incoming = state.clone();
        let mut then_state = incoming.clone();
        if let Some(found) = self.visit_expression(&if_expr.body, &mut then_state, target) {
            return Some(found);
        }
        let mut else_state = incoming;
        if let Some(found) = self.visit_expression(&if_expr.orelse, &mut else_state, target) {
            return Some(found);
        }
        *state = then_state.join(&else_state);
        None
    }

    fn assign_target(target: &Expr, state: &mut FlowState<'ast>, definition: Definition<'ast>) {
        if let Expr::Name(name) = target {
            state.set_definition(name.id.as_str(), definition);
        } else {
            Self::mark_target_unknown(target, state);
        }
    }

    fn mark_target_unknown(target: &Expr, state: &mut FlowState<'ast>) {
        let mut names = Vec::new();
        collect_target_names(target, &mut names);
        for name in names {
            state.mark_unknown(&name);
        }
    }
}

fn join_states(mut states: Vec<FlowState<'_>>) -> FlowState<'_> {
    let Some(mut joined) = states.pop() else {
        return FlowState::new();
    };
    for state in states {
        joined.join_in_place(&state);
    }
    joined
}

fn collect_scope_names(
    body: &[Stmt],
    names: &mut HashSet<String>,
    globals: &mut HashSet<String>,
    nonlocals: &mut HashSet<String>,
) {
    for statement in body {
        names.extend(stmt_store_names(statement));
        match statement {
            Stmt::Global(global) => {
                globals.extend(global.names.iter().map(ToString::to_string));
            }
            Stmt::Nonlocal(nonlocal) => {
                nonlocals.extend(nonlocal.names.iter().map(ToString::to_string));
            }
            Stmt::Try(try_stmt) => {
                for handler in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
                    if let Some(name) = &handler.name {
                        names.insert(name.as_str().to_string());
                    }
                }
            }
            _ => {}
        }
        collect_expression_names(&stmt_exprs(statement), names);
        if matches!(statement, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        for child in child_bodies(statement) {
            collect_scope_names(child, names, globals, nonlocals);
        }
    }
}

fn collect_expression_names(expressions: &[&Expr], names: &mut HashSet<String>) {
    let mut pending = expressions.to_vec();
    while let Some(expression) = pending.pop() {
        if matches!(
            expression,
            Expr::Lambda(_)
                | Expr::ListComp(_)
                | Expr::SetComp(_)
                | Expr::Generator(_)
                | Expr::DictComp(_)
        ) {
            continue;
        }
        if let Expr::Named(named) = expression
            && let Expr::Name(name) = named.target.as_ref()
        {
            names.insert(name.id.as_str().to_string());
        }
        pending.extend(child_exprs(expression));
    }
}

fn contains_range(container: TextRange, nested: TextRange) -> bool {
    container.start() <= nested.start() && nested.end() <= container.end()
}

fn body_range(body: &[Stmt], fallback: TextRange) -> TextRange {
    body.first()
        .zip(body.last())
        .map_or(fallback, |(first, last)| {
            TextRange::new(first.range().start(), last.range().end())
        })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s2077_matches_django_cursor_formatted_query_only() {
        let attack = concat!(
            "from django.db import connection\n",
            "value = input()\n",
            "with connection.cursor() as cursor:\n",
            "    cursor.execute(\"{0}\".format(value))\n",
        );
        let report = scan(attack);
        let issues = findings(&report, "python:S2077");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Make sure that formatting this SQL query is safe here."
        );
        assert_eq!(issues[0].range.start, pos(4, 4));
        assert_eq!(issues[0].range.end, pos(4, 39));

        let safe = concat!(
            "from django.db import connection\n",
            "value = input()\n",
            "with connection.cursor() as cursor:\n",
            "    cursor.execute(\"SELECT * FROM users WHERE id=%s\", (value,))\n",
        );
        assert!(findings(&scan(safe), "python:S2077").is_empty());

        let near_miss = concat!(
            "from django.db import connection\n",
            "value = input()\n",
            "def run(cursor, value):\n",
            "    query = \"SELECT * FROM users WHERE id=%s\"\n",
            "    cursor.execute(query, (value,))\n",
            "with connection.cursor() as cursor:\n",
            "    run(cursor, value)\n",
        );
        assert!(findings(&scan(near_miss), "python:S2077").is_empty());
    }

    #[test]
    fn s2077_tracks_one_formatted_assignment_without_method_name_heuristics() {
        let source = concat!(
            "from django.db import connection as db\n",
            "value = input()\n",
            "query = \"{0}\".format(value)\n",
            "with db.cursor() as cursor:\n",
            "    cursor.execute(query)\n",
            "class Cursor:\n",
            "    def execute(self, query):\n",
            "        return query\n",
            "Cursor().execute(query)\n",
        );
        assert_eq!(findings(&scan(source), "python:S2077").len(), 1);
    }

    #[test]
    fn s2077_resolves_keyword_reassignment_enclosing_and_walrus_queries() {
        let keyword = concat!(
            "from django.db import connection\n",
            "connection.cursor().execute(sql=\"SELECT * FROM t WHERE id={}\".format(input()))\n",
        );
        assert_eq!(findings(&scan(keyword), "python:S2077").len(), 1);

        let reassigned = concat!(
            "from django.db import connection\n",
            "def run(value):\n",
            "    query = \"SELECT 1\"\n",
            "    query = \"SELECT * FROM t WHERE id={}\".format(value)\n",
            "    connection.cursor().execute(query)\n",
            "run(input())\n",
        );
        assert_eq!(findings(&scan(reassigned), "python:S2077").len(), 1);

        let enclosing = concat!(
            "from django.db import connection\n",
            "query = \"SELECT * FROM t WHERE id={}\".format(input())\n",
            "def run():\n",
            "    connection.cursor().execute(query)\n",
            "run()\n",
        );
        assert_eq!(findings(&scan(enclosing), "python:S2077").len(), 1);

        let walrus = concat!(
            "from django.db import connection\n",
            "query = \"SELECT * FROM t WHERE id={}\".format(input())\n",
            "connection.cursor().execute(saved := query)\n",
        );
        assert_eq!(findings(&scan(walrus), "python:S2077").len(), 1);
    }

    #[test]
    fn s2077_rejects_ambiguous_and_shadowed_query_overwrites() {
        let safe_overwrite = concat!(
            "from django.db import connection\n",
            "query = \"SELECT * FROM t WHERE id={}\".format(input())\n",
            "query = \"SELECT 1\"\n",
            "connection.cursor().execute(query)\n",
        );
        assert!(findings(&scan(safe_overwrite), "python:S2077").is_empty());

        let ambiguous_branch = concat!(
            "from django.db import connection\n",
            "query = \"SELECT 1\"\n",
            "if flag:\n",
            "    query = \"SELECT * FROM t WHERE id={}\".format(input())\n",
            "connection.cursor().execute(query)\n",
        );
        assert!(findings(&scan(ambiguous_branch), "python:S2077").is_empty());

        let shadowed_enclosing = concat!(
            "from django.db import connection\n",
            "query = \"SELECT * FROM t WHERE id={}\".format(input())\n",
            "def run():\n",
            "    query = \"SELECT 1\"\n",
            "    connection.cursor().execute(query)\n",
            "run()\n",
        );
        assert!(findings(&scan(shadowed_enclosing), "python:S2077").is_empty());

        let safe_keyword = concat!(
            "from django.db import connection\n",
            "connection.cursor().execute(sql=\"SELECT * FROM users WHERE id=%s\", params=(value,))\n",
        );
        assert!(findings(&scan(safe_keyword), "python:S2077").is_empty());
    }
}
