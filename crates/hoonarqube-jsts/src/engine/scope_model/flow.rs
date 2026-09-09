use super::{
    ArrowFunctionBody, ArrowFunctionExpression, AssignmentExpression, AssignmentOperator,
    AssignmentTarget, AssignmentTargetPropertyIdentifier, AssignmentTargetPropertyProperty,
    AssignmentTargetWithDefault, BindingIdentifier, BindingPattern, BlockStatement, BreakStatement,
    CallExpression, CatchClause, ConditionalExpression, ContinueStatement, DoWhileStatement,
    Expression, ForInStatement, ForOfStatement, ForStatement, FormalParameters, Function, GetSpan,
    HashMap, IfStatement, IssueSink, LogicalExpression, MemberExpression, ReturnStatement,
    RuleScope, ScopeFlags, SimpleAssignmentTarget, Span, Statement, StaticBlock, SwitchStatement,
    ThrowStatement, TryStatement, UpdateExpression, VariableDeclaration, VariableDeclarationKind,
    VariableDeclarator, Visit, WhileStatement, source_slice, unparenthesized, walk_call_expression,
    walk_member_expression, walk_variable_declaration,
};

const INVOKED_CLOSURE_DEPTH: u32 = u32::MAX;

/// Reachability of the code following the current point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TbHalt {
    Live,
    /// `break` exits the innermost switch or loop.
    Broken,
    /// `continue` skips the rest of the innermost loop body.
    Jumped,
    /// `return`/`throw`: everything after is unreachable.
    Exited,
}

/// One tracked value: where it was written and what it came from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TbPending<'a> {
    /// Identifier that received this value.
    pub(crate) site: Span,
    /// Value expression; `None` for compound writes and updates.
    pub(crate) value: Option<Span>,
    /// Value arrived from a parameter or loop variable (`S1226`).
    pub(crate) initial: bool,
    /// Function expression assigned to this binding, when known.
    pub(crate) closure: Option<&'a Expression<'a>>,
    /// Binding came from an object/array destructuring declaration.
    pub(crate) destructured: bool,
    /// Binding is a per-iteration loop-local during closure replay.
    pub(crate) loop_local: bool,
}

pub(crate) type TbEnv<'a> = HashMap<&'a str, TbPending<'a>>;

/// Straight-line per-function value tracker feeding `S1854`, `S2123`,
/// `S1226`, and `S4165`. Writes inside a branch are recorded but never
/// reported there; branch joins keep an entry only when both paths hold the
/// same write, so conditionally-live values are never flagged.
pub(crate) struct TbFlow<'p, 's, 'i> {
    pub(crate) source: &'s str,
    pub(crate) sink: &'s mut IssueSink<'i>,
    pub(crate) env: TbEnv<'p>,
    pub(crate) status: TbHalt,
    /// Branch nesting depth; findings emit only at depth 0.
    pub(crate) depth: u32,
    /// Kind of the declaration whose declarators are currently visited.
    pub(crate) decl_kind: VariableDeclarationKind,
    /// Positive while identifiers in a destructuring assignment target are
    /// writes. Member objects/keys and default expressions temporarily reset
    /// this depth because they are reads.
    pub(crate) target_write_depth: u32,
}

impl<'p> TbFlow<'p, '_, '_> {
    pub(crate) fn read(&mut self, name: &'p str) {
        self.env.remove(name);
    }

    pub(crate) fn write(&mut self, name: &'p str, site: Span, value: Option<Span>, initial: bool) {
        self.write_with_metadata(
            name,
            TbPending {
                site,
                value,
                initial,
                closure: None,
                destructured: false,
                loop_local: false,
            },
        );
    }

    fn write_with_metadata(&mut self, name: &'p str, pending: TbPending<'p>) {
        let TbPending {
            site,
            value,
            initial,
            ..
        } = pending;
        let previous = self.env.get(name).copied();
        if self.depth == 0
            && let Some(previous) = previous
            && !initial
        {
            if previous.initial {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1226",
                    &format!(
                        "Introduce a new variable or use its initial value before reassigning \"{name}\"."
                    ),
                    value.map_or(site, |value| Span::new(site.start, value.end)),
                );
            } else {
                let same_value = matches!(
                    (previous.value, value),
                    (Some(old), Some(new))
                        if source_slice(self.source, old) == source_slice(self.source, new)
                );
                if same_value {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S4165",
                        &format!("Remove this redundant assignment of the same value to '{name}'."),
                        site,
                    );
                } else {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S1854",
                        &format!("Remove this useless assignment to variable \"{name}\"."),
                        previous.site,
                    );
                }
            }
        }
        self.env.insert(name, pending);
    }

    pub(crate) fn seed_parameter(&mut self, pattern: Option<&BindingPattern<'p>>) {
        let Some(pattern) = pattern else {
            return;
        };
        for name in bound_names(pattern) {
            self.env.insert(
                name,
                TbPending {
                    site: pattern.span(),
                    value: None,
                    initial: true,
                    closure: None,
                    destructured: false,
                    loop_local: false,
                },
            );
        }
    }

    pub(crate) fn enter_function(&mut self, parameters: &FormalParameters<'p>) {
        self.env.clear();
        self.status = TbHalt::Live;
        for parameter in &parameters.items {
            self.seed_parameter(Some(&parameter.pattern));
        }
        if let Some(rest) = &parameters.rest {
            self.seed_parameter(Some(&rest.rest.argument));
        }
    }

    pub(crate) fn process_statements(&mut self, statements: &[Statement<'p>]) {
        for statement in statements {
            if self.status != TbHalt::Live {
                return;
            }
            self.visit_statement(statement);
        }
    }

    /// Merges two branch outcomes; `pre` is the environment before branching.
    pub(crate) fn join(
        &mut self,
        then_state: (TbEnv<'p>, TbHalt),
        else_state: (TbEnv<'p>, TbHalt),
        pre: TbEnv<'p>,
    ) {
        match (then_state.1, else_state.1) {
            (TbHalt::Live, TbHalt::Live) => {
                self.env = intersect_envs(then_state.0, &else_state.0);
                self.status = TbHalt::Live;
            }
            (TbHalt::Live, _) => {
                self.env = then_state.0;
                self.status = TbHalt::Live;
            }
            (_, TbHalt::Live) => {
                self.env = else_state.0;
                self.status = TbHalt::Live;
            }
            (_, TbHalt::Exited) | (TbHalt::Exited, _) => {
                self.env = pre;
                self.status = TbHalt::Exited;
            }
            (TbHalt::Broken, TbHalt::Broken) => {
                self.env = pre;
                self.status = TbHalt::Broken;
            }
            _ => {
                self.env = pre;
                self.status = TbHalt::Jumped;
            }
        }
    }

    /// Loop bodies may re-read every value on the next iteration, and values
    /// written inside may be read by the test or update expressions, so all
    /// tracking is dropped at the loop boundary. During closure replay, retain
    /// only bindings that existed before the loop so loop locals do not leak.
    fn end_loop_with_locals(&mut self, replay_env: Option<&TbEnv<'p>>, loop_locals: &[&'p str]) {
        if let Some(pre) = replay_env {
            self.env.retain(|name, pending| {
                pre.contains_key(name) && !pending.loop_local && !loop_locals.contains(name)
            });
            for name in loop_locals {
                if let Some(pending) = pre.get(name) {
                    self.env.insert(name, *pending);
                } else {
                    self.env.remove(name);
                }
            }
        } else {
            self.env.clear();
        }
        if self.status != TbHalt::Exited {
            self.status = TbHalt::Live;
        }
    }

    fn track_identifier_declaration(
        &mut self,
        identifier: &BindingIdentifier<'p>,
        init: Option<&Expression<'p>>,
    ) {
        let name = identifier.name.as_str();
        let closure = init.and_then(|value| match unparenthesized(value) {
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
                Some(self.alloc(value))
            }
            _ => None,
        });
        match (self.decl_kind, init) {
            (VariableDeclarationKind::Var, Some(value)) => {
                // A `var` redeclaration writes the existing function-scoped
                // binding rather than shadowing it.
                self.write_with_metadata(
                    name,
                    TbPending {
                        site: identifier.span,
                        value: Some(value.span()),
                        initial: false,
                        closure,
                        destructured: false,
                        loop_local: false,
                    },
                );
            }
            (VariableDeclarationKind::Var, None) => {
                // An initializer-less `var` is a runtime no-op, including
                // when it redeclares an existing function-scoped binding.
            }
            (VariableDeclarationKind::Const, Some(value)) if closure.is_some() => {
                self.env.insert(
                    name,
                    TbPending {
                        site: identifier.span,
                        value: Some(value.span()),
                        initial: false,
                        closure,
                        destructured: false,
                        loop_local: false,
                    },
                );
            }
            (VariableDeclarationKind::Const, _) | (_, None) => {
                self.env.remove(name);
            }
            (_, Some(value)) => {
                // Block-scoped declarations shadow like-named outer bindings:
                // a fresh scope entry, not an overwrite.
                self.env.insert(
                    name,
                    TbPending {
                        site: identifier.span,
                        value: Some(value.span()),
                        initial: false,
                        closure,
                        destructured: false,
                        loop_local: false,
                    },
                );
            }
        }
    }

    fn track_pattern_declaration(
        &mut self,
        pattern: &BindingPattern<'p>,
        value: Option<&Expression<'p>>,
    ) {
        // Binding-pattern property keys and defaults are evaluated reads.
        self.visit_binding_pattern(pattern);
        let value = value.map(GetSpan::span);
        self.track_pattern_bindings(pattern, value);
    }

    fn track_pattern_bindings(&mut self, pattern: &BindingPattern<'p>, value: Option<Span>) {
        match pattern {
            BindingPattern::BindingIdentifier(identifier) => {
                let name = identifier.name.as_str();
                if self.decl_kind == VariableDeclarationKind::Var {
                    self.write_with_metadata(
                        name,
                        TbPending {
                            site: identifier.span,
                            value,
                            initial: false,
                            closure: None,
                            destructured: true,
                            loop_local: false,
                        },
                    );
                } else {
                    self.env.insert(
                        name,
                        TbPending {
                            site: identifier.span,
                            value,
                            initial: false,
                            closure: None,
                            destructured: true,
                            loop_local: false,
                        },
                    );
                }
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    self.track_pattern_bindings(&property.value, value);
                }
                if let Some(rest) = &object.rest {
                    self.track_pattern_bindings(&rest.argument, value);
                }
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    self.track_pattern_bindings(element, value);
                }
                if let Some(rest) = &array.rest {
                    self.track_pattern_bindings(&rest.argument, value);
                }
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.track_pattern_bindings(&assignment.left, value);
            }
        }
    }

    fn finish_destructuring_scope(&mut self, locals: Option<&[&'p str]>) {
        if self.depth != 0 {
            return;
        }
        for (name, pending) in &self.env {
            if pending.destructured && locals.is_none_or(|names| names.contains(name)) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1854",
                    &format!("Remove this useless assignment to variable \"{name}\"."),
                    pending.site,
                );
            }
        }
    }
    fn invoke_with_locals<F>(&mut self, locals: &[&'p str], body: F)
    where
        F: FnOnce(&mut Self),
    {
        let saved_env = self.env.clone();
        let saved_status = self.status;
        let saved_depth = self.depth;
        let saved_target_depth = self.target_write_depth;
        for name in locals {
            self.env.remove(name);
        }
        self.status = TbHalt::Live;
        self.depth = INVOKED_CLOSURE_DEPTH;
        self.target_write_depth = 0;
        body(self);
        self.restore_scope(&saved_env, locals);
        self.status = saved_status;
        self.depth = saved_depth;
        self.target_write_depth = saved_target_depth;
    }

    fn visit_invoked_parameters(&mut self, parameters: &FormalParameters<'p>) {
        for parameter in &parameters.items {
            self.seed_parameter(Some(&parameter.pattern));
            self.visit_pattern_defaults(&parameter.pattern);
            if let Some(initializer) = &parameter.initializer {
                self.visit_expression(initializer);
            }
        }
        if let Some(rest) = &parameters.rest {
            self.seed_parameter(Some(&rest.rest.argument));
        }
    }
    fn invoke_function_closure(&mut self, function: &Function<'p>) {
        let Some(body) = &function.body else {
            return;
        };
        let mut locals = Vec::new();
        for parameter in &function.params.items {
            locals.extend(bound_names(&parameter.pattern));
        }
        if let Some(rest) = &function.params.rest {
            locals.extend(bound_names(&rest.rest.argument));
        }
        locals.extend(direct_scope_names(&body.statements, true));
        locals.extend(function_var_names(&body.statements));
        self.invoke_with_locals(&locals, |flow| {
            flow.visit_invoked_parameters(&function.params);
            flow.process_statements(&body.statements);
        });
    }

    fn invoke_arrow_closure(&mut self, arrow: &ArrowFunctionExpression<'p>) {
        let mut locals = Vec::new();
        for parameter in &arrow.params.items {
            locals.extend(bound_names(&parameter.pattern));
        }
        if let Some(rest) = &arrow.params.rest {
            locals.extend(bound_names(&rest.rest.argument));
        }
        if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
            locals.extend(direct_scope_names(&body.statements, true));
            locals.extend(function_var_names(&body.statements));
        }
        self.invoke_with_locals(&locals, |flow| {
            flow.visit_invoked_parameters(&arrow.params);
            match &arrow.body {
                ArrowFunctionBody::FunctionBody(body) => {
                    flow.process_statements(&body.statements);
                }
                body => {
                    if let Some(expression) = body.as_expression() {
                        flow.visit_expression(expression);
                    }
                }
            }
        });
    }

    fn invoke_closure(&mut self, expression: &'p Expression<'p>) {
        match unparenthesized(expression) {
            Expression::FunctionExpression(function) => self.invoke_function_closure(function),
            Expression::ArrowFunctionExpression(arrow) => self.invoke_arrow_closure(arrow),
            _ => {}
        }
    }

    fn visit_pattern_defaults(&mut self, pattern: &BindingPattern<'p>) {
        match pattern {
            BindingPattern::BindingIdentifier(_) => {}
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    self.visit_pattern_defaults(&property.value);
                }
                if let Some(rest) = &object.rest {
                    self.visit_pattern_defaults(&rest.argument);
                }
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    self.visit_pattern_defaults(element);
                }
                if let Some(rest) = &array.rest {
                    self.visit_pattern_defaults(&rest.argument);
                }
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.visit_expression(&assignment.right);
                self.visit_pattern_defaults(&assignment.left);
            }
        }
    }

    fn restore_scope(&mut self, saved: &TbEnv<'p>, locals: &[&'p str]) {
        for name in locals {
            if let Some(pending) = saved.get(name) {
                self.env.insert(name, *pending);
            } else {
                self.env.remove(name);
            }
        }
    }

    fn seed_loop_declaration(
        &mut self,
        declaration: &VariableDeclaration<'p>,
        value: Option<&Expression<'p>>,
    ) {
        for declarator in &declaration.declarations {
            if let Some(init) = &declarator.init {
                self.visit_expression(init);
            }
            self.visit_pattern_defaults(&declarator.id);
            for name in bound_names(&declarator.id) {
                self.write_with_metadata(
                    name,
                    TbPending {
                        site: declarator.id.span(),
                        value: value.map(GetSpan::span),
                        initial: true,
                        closure: None,
                        destructured: false,
                        loop_local: self.depth == INVOKED_CLOSURE_DEPTH
                            && declaration.kind != VariableDeclarationKind::Var,
                    },
                );
            }
        }
    }

    fn visit_for_head(&mut self, left: &oxc_ast::ast::ForStatementLeft<'p>) {
        match left {
            oxc_ast::ast::ForStatementLeft::VariableDeclaration(declaration) => {
                self.seed_loop_declaration(declaration, None);
            }
            left => {
                self.target_write_depth += 1;
                self.visit_for_statement_left(left);
                self.target_write_depth -= 1;
            }
        }
    }

    fn visit_for_init(&mut self, init: &oxc_ast::ast::ForStatementInit<'p>) {
        match init {
            oxc_ast::ast::ForStatementInit::VariableDeclaration(declaration) => {
                self.seed_loop_declaration(declaration, None);
            }
            init => self.visit_for_statement_init(init),
        }
    }
    fn visit_scoped_statements(&mut self, statements: &[Statement<'p>], include_var: bool) {
        let locals = direct_scope_names(statements, include_var);
        let saved = self.env.clone();
        for name in &locals {
            self.env.remove(name);
        }
        self.process_statements(statements);
        self.finish_destructuring_scope(Some(&locals));
        self.restore_scope(&saved, &locals);
    }

    fn forget_local_bindings(&mut self, names: &[&'p str]) {
        for name in names {
            self.env.remove(name);
        }
    }
}

impl<'p> Visit<'p> for TbFlow<'p, '_, '_> {
    fn visit_program(&mut self, program: &oxc_ast::ast::Program<'p>) {
        self.process_statements(&program.body);
        self.finish_destructuring_scope(None);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        let callee = unparenthesized(&call.callee);
        if let Expression::Identifier(identifier) = callee {
            let name = identifier.name.as_str();
            let pending = self.env.get(name).copied();
            if let Some(closure) = pending.and_then(|pending| pending.closure) {
                self.visit_expression(&call.callee);
                self.visit_arguments(&call.arguments);
                self.invoke_closure(closure);
                if let Some(pending) = pending
                    && !self.env.contains_key(name)
                {
                    self.env.insert(name, pending);
                }
                return;
            }
        } else if matches!(
            callee,
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
        ) {
            self.visit_expression(&call.callee);
            self.visit_arguments(&call.arguments);
            self.invoke_closure(self.alloc(callee));
            return;
        }
        walk_call_expression(self, call);
    }

    fn visit_block_statement(&mut self, block: &BlockStatement<'p>) {
        self.visit_scoped_statements(&block.body, false);
    }

    fn visit_static_block(&mut self, block: &StaticBlock<'p>) {
        let locals = direct_scope_names(&block.body, true);
        let saved_env = self.env.clone();
        let saved_status = self.status;
        let saved_depth = self.depth;
        self.forget_local_bindings(&locals);
        self.status = TbHalt::Live;
        self.process_statements(&block.body);
        self.finish_destructuring_scope(Some(&locals));
        self.restore_scope(&saved_env, &locals);
        self.status = saved_status;
        self.depth = saved_depth;
    }

    fn visit_function(&mut self, function: &Function<'p>, _flags: ScopeFlags) {
        let saved = (std::mem::take(&mut self.env), self.status, self.depth);
        let replaying = saved.2 == INVOKED_CLOSURE_DEPTH;
        self.depth = if replaying { INVOKED_CLOSURE_DEPTH } else { 0 };
        self.enter_function(&function.params);
        if let Some(body) = &function.body {
            self.process_statements(&body.statements);
            if !replaying {
                self.finish_destructuring_scope(None);
            }
        }
        self.env = saved.0;
        self.status = saved.1;
        self.depth = saved.2;
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'p>) {
        let saved = (std::mem::take(&mut self.env), self.status, self.depth);
        let replaying = saved.2 == INVOKED_CLOSURE_DEPTH;
        self.depth = if replaying { INVOKED_CLOSURE_DEPTH } else { 0 };
        self.enter_function(&arrow.params);
        match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => {
                self.process_statements(&body.statements);
                if !replaying {
                    self.finish_destructuring_scope(None);
                }
            }
            body => {
                if let Some(expression) = body.as_expression() {
                    self.visit_expression(expression);
                }
            }
        }
        self.env = saved.0;
        self.status = saved.1;
        self.depth = saved.2;
    }

    fn visit_catch_clause(&mut self, clause: &CatchClause<'p>) {
        let locals = clause
            .param
            .as_ref()
            .map(|param| bound_names(&param.pattern))
            .unwrap_or_default();
        let saved_env = self.env.clone();
        let saved_status = self.status;
        let saved_depth = self.depth;
        self.forget_local_bindings(&locals);
        self.seed_parameter(clause.param.as_ref().map(|param| &param.pattern));
        self.process_statements(&clause.body.body);
        self.restore_scope(&saved_env, &locals);
        self.status = saved_status;
        self.depth = saved_depth;
    }

    fn visit_if_statement(&mut self, node: &IfStatement<'p>) {
        self.visit_expression(&node.test);
        let pre = self.env.clone();
        let saved_depth = self.depth;
        self.depth = self.depth.saturating_add(1);
        self.visit_statement(&node.consequent);
        let then_state = (std::mem::replace(&mut self.env, pre.clone()), self.status);
        let else_state = match &node.alternate {
            Some(alternate) => {
                self.status = TbHalt::Live;
                self.visit_statement(alternate);
                (std::mem::replace(&mut self.env, pre.clone()), self.status)
            }
            None => (pre.clone(), TbHalt::Live),
        };
        self.depth = saved_depth;
        self.join(then_state, else_state, pre);
    }

    fn visit_conditional_expression(&mut self, node: &ConditionalExpression<'p>) {
        self.visit_expression(&node.test);
        let pre = self.env.clone();
        let saved_depth = self.depth;
        self.depth = self.depth.saturating_add(1);
        self.visit_expression(&node.consequent);
        let then_state = (std::mem::replace(&mut self.env, pre.clone()), self.status);
        self.status = TbHalt::Live;
        self.visit_expression(&node.alternate);
        let else_state = (std::mem::replace(&mut self.env, pre.clone()), self.status);
        self.depth = saved_depth;
        self.join(then_state, else_state, pre);
    }

    /// Short-circuit right-hand sides run conditionally, so their writes are
    /// recorded but never reported there and cannot leak into the join.
    fn visit_logical_expression(&mut self, node: &LogicalExpression<'p>) {
        self.visit_expression(&node.left);
        let pre = self.env.clone();
        let saved_depth = self.depth;
        let saved_status = self.status;
        self.depth = self.depth.saturating_add(1);
        self.visit_expression(&node.right);
        let rhs = std::mem::take(&mut self.env);
        self.depth = saved_depth;
        self.status = saved_status;
        self.env = intersect_envs(pre, &rhs);
    }

    fn visit_switch_statement(&mut self, node: &SwitchStatement<'p>) {
        self.visit_expression(&node.discriminant);
        let pre = self.env.clone();
        let saved_depth = self.depth;
        let no_match = node.cases.iter().all(|case| case.test.is_some());
        self.depth = self.depth.saturating_add(1);
        let mut joined: Option<TbEnv<'p>> = None;
        for case in &node.cases {
            self.env = pre.clone();
            self.status = TbHalt::Live;
            if let Some(test) = &case.test {
                self.visit_expression(test);
            }
            self.process_statements(&case.consequent);
            if matches!(self.status, TbHalt::Live | TbHalt::Broken) {
                let current = std::mem::replace(&mut self.env, pre.clone());
                joined = Some(match joined {
                    None => current,
                    Some(existing) => intersect_envs(existing, &current),
                });
            }
        }
        self.depth = saved_depth;
        self.status = TbHalt::Live;
        self.env = match joined {
            Some(joined) if no_match => intersect_envs(joined, &pre),
            Some(joined) => joined,
            None => pre,
        };
    }

    fn visit_try_statement(&mut self, node: &TryStatement<'p>) {
        let pre = self.env.clone();
        let saved_depth = self.depth;
        self.depth = self.depth.saturating_add(1);
        self.process_statements(&node.block.body);
        let try_state = (std::mem::replace(&mut self.env, pre.clone()), self.status);
        let handler_state = match &node.handler {
            Some(handler) => {
                self.status = TbHalt::Live;
                // The catch body runs on its own straight-line path, so its
                // writes are reportable even though the try block is not.
                let handler_depth = std::mem::replace(&mut self.depth, 0);
                self.visit_catch_clause(handler);
                self.depth = handler_depth;
                (std::mem::replace(&mut self.env, pre.clone()), self.status)
            }
            None => (pre.clone(), TbHalt::Live),
        };
        self.depth = saved_depth;
        self.join(try_state, handler_state, pre);
        if let Some(finalizer) = &node.finalizer {
            self.visit_block_statement(finalizer);
        }
    }

    fn visit_while_statement(&mut self, node: &WhileStatement<'p>) {
        let replay_env = (self.depth == INVOKED_CLOSURE_DEPTH).then(|| self.env.clone());
        for name in subtree_names(&[&node.test], &[&node.body]) {
            self.env.remove(name);
        }
        self.visit_expression(&node.test);
        self.visit_statement(&node.body);
        self.end_loop_with_locals(replay_env.as_ref(), &[]);
    }

    fn visit_do_while_statement(&mut self, node: &DoWhileStatement<'p>) {
        let replay_env = (self.depth == INVOKED_CLOSURE_DEPTH).then(|| self.env.clone());
        for name in subtree_names(&[&node.test], &[&node.body]) {
            self.env.remove(name);
        }
        self.visit_statement(&node.body);
        self.visit_expression(&node.test);
        self.end_loop_with_locals(replay_env.as_ref(), &[]);
    }

    fn visit_for_statement(&mut self, node: &ForStatement<'p>) {
        let replaying = self.depth == INVOKED_CLOSURE_DEPTH;
        let replay_env = replaying.then(|| self.env.clone());
        let loop_locals = match &node.init {
            Some(oxc_ast::ast::ForStatementInit::VariableDeclaration(declaration)) => {
                lexical_loop_names(declaration)
            }
            _ => Vec::new(),
        };
        let mut parts: Vec<&Expression<'p>> = Vec::new();
        if let Some(test) = &node.test {
            parts.push(test);
        }
        if let Some(update) = &node.update {
            parts.push(update);
        }
        for name in subtree_names(&parts, &[&node.body]) {
            self.env.remove(name);
        }
        if replaying {
            for name in &loop_locals {
                self.env.remove(name);
            }
        }
        if let Some(init) = &node.init {
            self.visit_for_init(init);
        }
        if let Some(test) = &node.test {
            self.visit_expression(test);
        }
        if self.status == TbHalt::Live {
            self.visit_statement(&node.body);
        }
        if self.status == TbHalt::Live
            && let Some(update) = &node.update
        {
            self.visit_expression(update);
        }
        self.end_loop_with_locals(replay_env.as_ref(), &loop_locals);
    }

    fn visit_for_in_statement(&mut self, node: &ForInStatement<'p>) {
        let replaying = self.depth == INVOKED_CLOSURE_DEPTH;
        let loop_locals = lexical_loop_names_from_left(&node.left);
        if replaying {
            self.visit_expression(&node.right);
        } else {
            for name in subtree_names(&[&node.right], &[&node.body]) {
                self.env.remove(name);
            }
            self.visit_expression(&node.right);
        }
        let replay_env = replaying.then(|| self.env.clone());
        for name in subtree_names(&[], &[&node.body]) {
            self.env.remove(name);
        }
        for name in &loop_locals {
            self.env.remove(name);
        }
        self.visit_for_head(&node.left);
        if self.status == TbHalt::Live {
            self.visit_statement(&node.body);
        }
        self.end_loop_with_locals(replay_env.as_ref(), &loop_locals);
    }

    fn visit_for_of_statement(&mut self, node: &ForOfStatement<'p>) {
        let replaying = self.depth == INVOKED_CLOSURE_DEPTH;
        let loop_locals = lexical_loop_names_from_left(&node.left);
        if replaying {
            self.visit_expression(&node.right);
        } else {
            for name in subtree_names(&[&node.right], &[&node.body]) {
                self.env.remove(name);
            }
            self.visit_expression(&node.right);
        }
        let replay_env = replaying.then(|| self.env.clone());
        for name in subtree_names(&[], &[&node.body]) {
            self.env.remove(name);
        }
        for name in &loop_locals {
            self.env.remove(name);
        }
        self.visit_for_head(&node.left);
        if self.status == TbHalt::Live {
            self.visit_statement(&node.body);
        }
        self.end_loop_with_locals(replay_env.as_ref(), &loop_locals);
    }

    fn visit_break_statement(&mut self, _: &BreakStatement<'p>) {
        self.status = TbHalt::Broken;
    }

    fn visit_continue_statement(&mut self, _: &ContinueStatement<'p>) {
        self.status = TbHalt::Jumped;
    }

    fn visit_return_statement(&mut self, node: &ReturnStatement<'p>) {
        if let Some(argument) = &node.argument {
            self.visit_expression(argument);
        }
        self.status = TbHalt::Exited;
    }

    fn visit_throw_statement(&mut self, node: &ThrowStatement<'p>) {
        self.visit_expression(&node.argument);
        self.status = TbHalt::Exited;
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'p>) {
        if let Some(update_span) = self_overwrite_target(assign) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2123",
                "Remove this increment or correct the code not to waste it.",
                update_span,
            );
            if let Some((name, _)) = tb_assignment_target(&assign.left) {
                self.read(name);
            }
            return;
        }
        if let Some((name, span)) = tb_assignment_target(&assign.left) {
            let closure = (assign.operator == AssignmentOperator::Assign
                && matches!(
                    unparenthesized(&assign.right),
                    Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                ))
            .then_some(self.alloc(&assign.right));
            if assign.operator != AssignmentOperator::Assign {
                // Compound assignments read the old left-hand value before
                // evaluating the RHS.
                self.read(name);
            }
            self.visit_expression(&assign.right);
            self.write_with_metadata(
                name,
                TbPending {
                    site: span,
                    value: Some(assign.right.span()),
                    initial: false,
                    closure,
                    destructured: false,
                    loop_local: false,
                },
            );
        } else if let Some(simple) = assign.left.as_simple_assignment_target() {
            // Member objects and computed keys evaluate before the RHS.
            self.visit_simple_assignment_target(simple);
            self.visit_expression(&assign.right);
        } else {
            // Destructuring evaluates the RHS first, then performs writes and
            // evaluates any default initializers left-to-right.
            self.visit_expression(&assign.right);
            self.target_write_depth += 1;
            self.visit_assignment_target(&assign.left);
            self.target_write_depth -= 1;
        }
    }

    fn visit_update_expression(&mut self, update: &UpdateExpression<'p>) {
        match &update.argument {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) => {
                let name = identifier.name.as_str();
                self.read(name);
                self.write(name, identifier.span, None, false);
            }
            other => self.visit_simple_assignment_target(other),
        }
    }

    fn visit_identifier_reference(&mut self, reference: &oxc_ast::ast::IdentifierReference<'p>) {
        if self.target_write_depth > 0 {
            self.write(reference.name.as_str(), reference.span, None, false);
        } else {
            self.read(reference.name.as_str());
        }
    }

    fn visit_member_expression(&mut self, member: &MemberExpression<'p>) {
        let saved = std::mem::replace(&mut self.target_write_depth, 0);
        walk_member_expression(self, member);
        self.target_write_depth = saved;
    }

    fn visit_assignment_target_with_default(&mut self, target: &AssignmentTargetWithDefault<'p>) {
        let saved = std::mem::replace(&mut self.target_write_depth, 0);
        self.visit_expression(&target.init);
        self.target_write_depth = saved;
        self.visit_assignment_target(&target.binding);
    }

    fn visit_assignment_target_property_identifier(
        &mut self,
        property: &AssignmentTargetPropertyIdentifier<'p>,
    ) {
        let saved = std::mem::replace(&mut self.target_write_depth, 0);
        if let Some(init) = &property.init {
            self.visit_expression(init);
        }
        self.target_write_depth = saved;
        self.visit_identifier_reference(&property.binding);
    }
    fn visit_assignment_target_property_property(
        &mut self,
        property: &AssignmentTargetPropertyProperty<'p>,
    ) {
        let saved = std::mem::replace(&mut self.target_write_depth, 0);
        self.visit_property_key(&property.name);
        self.target_write_depth = saved;
        self.visit_assignment_target_maybe_default(&property.binding);
    }

    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'p>) {
        let saved = self.decl_kind;
        self.decl_kind = declaration.kind;
        for declarator in &declaration.declarations {
            self.visit_variable_declarator(declarator);
        }
        self.decl_kind = saved;
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'p>) {
        if let Some(init) = &declarator.init {
            self.visit_expression(init);
        }
        match &declarator.id {
            BindingPattern::BindingIdentifier(identifier) => {
                self.track_identifier_declaration(identifier, declarator.init.as_ref());
            }
            pattern => self.track_pattern_declaration(pattern, declarator.init.as_ref()),
        }
    }
}

pub(crate) fn intersect_envs<'p>(left: TbEnv<'p>, right: &TbEnv<'p>) -> TbEnv<'p> {
    left.into_iter()
        .filter(|(name, pending)| {
            right
                .get(name)
                .is_some_and(|other| other.site == pending.site)
        })
        .collect()
}

pub(crate) fn tb_assignment_target<'data>(
    target: &AssignmentTarget<'data>,
) -> Option<(&'data str, Span)> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
            Some((identifier.name.as_str(), identifier.span))
        }
        _ => None,
    }
}

/// Span of the `++`/`--` when an assignment overwrites its own updated
/// operand (`x = x++`, `x += x--`): the update's effect is discarded (`S2123`).
pub(crate) fn self_overwrite_target(assign: &AssignmentExpression<'_>) -> Option<Span> {
    let (target_name, _) = tb_assignment_target(&assign.left)?;
    let Expression::UpdateExpression(update) = unparenthesized(&assign.right) else {
        return None;
    };
    let SimpleAssignmentTarget::AssignmentTargetIdentifier(operand) = &update.argument else {
        return None;
    };
    (operand.name.as_str() == target_name).then_some(update.span)
}

#[derive(Default)]
pub(crate) struct TbReferenceNames<'a> {
    pub(crate) names: Vec<&'a str>,
}

impl<'a> Visit<'a> for TbReferenceNames<'a> {
    fn visit_identifier_reference(&mut self, reference: &oxc_ast::ast::IdentifierReference<'a>) {
        self.names.push(reference.name.as_str());
    }
}

#[derive(Default)]
pub(crate) struct TbBoundNames<'a> {
    pub(crate) names: Vec<&'a str>,
}

impl<'a> Visit<'a> for TbBoundNames<'a> {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        self.names.push(identifier.name.as_str());
    }
}

#[derive(Default)]
struct TbFunctionVarNames<'a> {
    names: Vec<&'a str>,
}

impl<'a> Visit<'a> for TbFunctionVarNames<'a> {
    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'a>) {
        if declaration.kind == VariableDeclarationKind::Var {
            for declarator in &declaration.declarations {
                self.names.extend(bound_names(&declarator.id));
            }
        }
        walk_variable_declaration(self, declaration);
    }

    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}

    fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
}

fn function_var_names<'a>(statements: &[Statement<'a>]) -> Vec<&'a str> {
    let mut collector = TbFunctionVarNames::default();
    for statement in statements {
        collector.visit_statement(statement);
    }
    collector.names
}

pub(crate) fn bound_names<'a>(pattern: &BindingPattern<'a>) -> Vec<&'a str> {
    let mut collector = TbBoundNames::default();
    collector.visit_binding_pattern(pattern);
    collector.names
}

/// Names read or written anywhere in the given expression/statement parts.
pub(crate) fn subtree_names<'a>(
    expressions: &[&Expression<'a>],
    statements: &[&Statement<'a>],
) -> Vec<&'a str> {
    let mut collector = TbReferenceNames::default();
    for expression in expressions {
        collector.visit_expression(expression);
    }
    for statement in statements {
        collector.visit_statement(statement);
    }
    collector.names
}

pub(crate) fn member_optional(member: &MemberExpression<'_>) -> bool {
    match member {
        MemberExpression::StaticMemberExpression(expression) => expression.optional,
        MemberExpression::ComputedMemberExpression(expression) => expression.optional,
        MemberExpression::PrivateFieldExpression(expression) => expression.optional,
    }
}
fn lexical_loop_names<'a>(declaration: &VariableDeclaration<'a>) -> Vec<&'a str> {
    if declaration.kind == VariableDeclarationKind::Var {
        return Vec::new();
    }
    declaration
        .declarations
        .iter()
        .flat_map(|declarator| bound_names(&declarator.id))
        .collect()
}

fn lexical_loop_names_from_left<'a>(left: &oxc_ast::ast::ForStatementLeft<'a>) -> Vec<&'a str> {
    match left {
        oxc_ast::ast::ForStatementLeft::VariableDeclaration(declaration) => {
            lexical_loop_names(declaration)
        }
        _ => Vec::new(),
    }
}

fn direct_scope_names<'p>(statements: &[Statement<'p>], include_var: bool) -> Vec<&'p str> {
    let mut names = Vec::new();
    for statement in statements {
        match statement {
            Statement::VariableDeclaration(declaration)
                if include_var || declaration.kind != VariableDeclarationKind::Var =>
            {
                for declarator in &declaration.declarations {
                    names.extend(bound_names(&declarator.id));
                }
            }
            Statement::FunctionDeclaration(function) => {
                if let Some(identifier) = &function.id {
                    names.push(identifier.name.as_str());
                }
            }
            Statement::ClassDeclaration(class) => {
                if let Some(identifier) = &class.id {
                    names.push(identifier.name.as_str());
                }
            }
            _ => {}
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JstsLanguage;
    use crate::support::LineIndex;
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;

    fn flow_ids(source: &str) -> Vec<String> {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
        let index = LineIndex::new(source);
        let mut sink = IssueSink {
            index: &index,
            language: JstsLanguage::JavaScript,
            issues: Vec::new(),
        };
        let mut flow = TbFlow {
            source,
            sink: &mut sink,
            env: HashMap::new(),
            status: TbHalt::Live,
            depth: 0,
            decl_kind: VariableDeclarationKind::Let,
            target_write_depth: 0,
        };
        flow.visit_program(&parsed.program);
        sink.issues
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect()
    }

    #[test]
    fn static_block_reads_outer_binding() {
        let source = "let x = a(); class C { static { use(x); } } x = b();";
        assert!(!flow_ids(source).contains(&"javascript:S1854".to_owned()));
    }

    #[test]
    fn loop_heads_seed_initial_values_for_reassignments() {
        for source in [
            "for (let item of items) { item = normalize(); }",
            "for (let item in items) { item = normalize(); }",
            "for (let item = initial();;) { item = normalize(); break; }",
        ] {
            assert!(flow_ids(source).contains(&"javascript:S1226".to_owned()));
        }
    }

    #[test]
    fn loop_destructuring_defaults_participate_in_flow() {
        let with_default =
            "let target; for (let [value = (target = a(), target = b())] of values) {}";
        assert!(flow_ids(with_default).contains(&"javascript:S1854".to_owned()));

        let without_default = "let target; for (let [value] of values) {}";
        assert!(!flow_ids(without_default).contains(&"javascript:S1854".to_owned()));
    }

    #[test]
    fn defaultless_switch_keeps_no_match_path() {
        let source = "function f(kind) { let x = a(); switch (kind) { case 1: use(x); x = b(); use(x); break; } x = c(); use(x); }";
        assert!(!flow_ids(source).contains(&"javascript:S1854".to_owned()));
    }
    #[test]
    fn update_reads_previous_value_before_recording_write() {
        let overwritten = "let x = a(); x++; x = b();";
        assert!(flow_ids(overwritten).contains(&"javascript:S1854".to_owned()));
        let consumed = "let x = a(); x++; use(x); x = b();";
        assert!(!flow_ids(consumed).contains(&"javascript:S1854".to_owned()));
    }
    #[test]
    fn computed_assignment_and_loop_keys_are_reads_not_writes() {
        let assignment = "let key = get(); let value; ({ [key]: value } = source);";
        assert!(!flow_ids(assignment).contains(&"javascript:S1854".to_owned()));

        let loop_head = "let key = get(); for ({ [key]: value } of values) {}";
        assert!(!flow_ids(loop_head).contains(&"javascript:S1854".to_owned()));
    }
    #[test]
    fn destructuring_defaults_read_prior_values_before_forgetting_bindings() {
        let with_default =
            "let fallback = a(); let { value = fallback } = source; use(value); fallback = b();";
        assert!(!flow_ids(with_default).contains(&"javascript:S1854".to_owned()));

        let without_default =
            "let fallback = a(); let { value } = source; use(value); fallback = b();";
        assert!(flow_ids(without_default).contains(&"javascript:S1854".to_owned()));
    }

    #[test]
    fn destructuring_reports_each_unread_binding() {
        let object = "function f() { const { unused, used } = load(); use(used); }\nf();\n";
        let array = "function f() { const [unused, used] = load(); use(used); }\nf();\n";
        for source in [object, array] {
            assert_eq!(
                flow_ids(source)
                    .iter()
                    .filter(|rule| rule.as_str() == "javascript:S1854")
                    .count(),
                1
            );
        }
    }

    #[test]
    fn invoked_closure_reads_capture_before_overwrite() {
        let invoked = "function f() { let value = 1; const read = () => value; consume(read()); value = 2; }\nf();\n";
        assert!(!flow_ids(invoked).contains(&"javascript:S1854".to_owned()));

        let not_invoked =
            "function f() { let value = 1; const read = () => value; value = 2; }\nf();\n";
        assert!(flow_ids(not_invoked).contains(&"javascript:S1854".to_owned()));

        let shadowed = "function f() { let value = 1; const read = () => { const value = 2; return value; }; consume(read()); value = 2; }\nf();\n";
        assert!(flow_ids(shadowed).contains(&"javascript:S1854".to_owned()));
    }

    #[test]
    fn repeated_invoked_closure_reads_do_not_report_capture_writes() {
        let source = "function f() { let value = 1; const read = () => value; consume(read()); value = 2; consume(read()); value = 3; }\nf();\n";
        assert!(!flow_ids(source).contains(&"javascript:S1854".to_owned()));
    }

    #[test]
    fn replayed_loop_locals_restore_captured_bindings() {
        let shadowed = "function f() { let item = 1; const run = () => { for (let item of items) { item = normalize(); } }; run(); item = 2; }\nf();\n";
        assert_eq!(
            flow_ids(shadowed)
                .iter()
                .filter(|rule| rule.as_str() == "javascript:S1854")
                .count(),
            1
        );

        let local_only = "function f() { const run = () => { for (let item of items) { item = normalize(); } }; run(); item = 2; }\nf();\n";
        assert!(!flow_ids(local_only).contains(&"javascript:S1854".to_owned()));
        let iterable_capture = "function f() { let item = 1; const run = () => { for (let item of [item]) {} }; run(); item = 2; }\nf();\n";
        assert!(!flow_ids(iterable_capture).contains(&"javascript:S1854".to_owned()));
    }
}
