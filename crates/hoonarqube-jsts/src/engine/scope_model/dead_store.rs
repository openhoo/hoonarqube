//! Backward dead-store tracking for `S1854` overwrites the straight-line
//! forward tracker cannot see: assignments whose value is provably
//! overwritten before any read on *every* path, including writes sunk inside
//! branches, loops, and rejoined parser paths (the pinned Markdown-It cases).
//!
//! The pass reports a store only when a later write of the same binding kills
//! it on every path: stores that merely die at scope end stay under the
//! forward tracker's contract. Liveness is a name-level may-analysis with
//! these conservative rules:
//!
//! - closure bodies contribute generous reads of captured region bindings,
//!   so captured values are never reported;
//! - loop heads seed their per-iteration reads, and loop-head declarations
//!   are never reported (`S1226` territory);
//! - `break`/`continue` pass the current state through unchanged;
//! - a store is reportable when the name is neither read nor live on any
//!   path after it and at least one path hits a further write.
//!
//! Same-value rewrites that follow on a straight line (no branch join in
//! between) are skipped because the forward tracker reports those as
//! redundant assignment (`S4165`) instead.

use super::{
    AssignmentOperator, AssignmentTarget, BindingPattern, BlockStatement, CatchClause, Expression,
    ForInStatement, ForOfStatement, ForStatement, FormalParameters, Function, IfStatement,
    MethodDefinition, SimpleAssignmentTarget, Span, Statement, StaticBlock, SwitchStatement,
    TryStatement, UpdateExpression, VariableDeclaration, VariableDeclarationKind,
    VariableDeclarator, Visit, bound_names, source_slice, walk_arrow_function_expression,
    walk_block_statement, walk_catch_clause, walk_expression, walk_for_statement, walk_function,
    walk_method_definition, walk_program, walk_static_block,
};
use oxc_ast::ast::{
    Argument, ArrayAssignmentTarget, ArrowFunctionBody, ArrowFunctionExpression,
    AssignmentTargetMaybeDefault, AssignmentTargetProperty, ForStatementInit, ForStatementLeft,
    IdentifierReference, ImportDeclarationSpecifier, ObjectAssignmentTarget, Program, PropertyKey,
};
use oxc_ast_visit::walk::{
    walk_assignment_expression, walk_assignment_target, walk_for_in_statement,
    walk_for_of_statement, walk_simple_assignment_target,
};
use oxc_span::GetSpan;
use oxc_syntax::scope::ScopeFlags;
use std::collections::HashSet;

/// One provably overwritten store.
pub(crate) struct DeadStore {
    pub(crate) name: String,
    /// Span of the stored binding; the `S1854` finding position.
    pub(crate) site: Span,
}

/// Liveness flowing backward through one region. `live` holds names that may
/// be read before any further write on some path; `rewritten` holds names
/// that may hit a further write; `kill_values` records the nearest later
/// write per name with a `merged` flag marking branch joins between that
/// write and the current point (the same-value straight-line rule).
#[derive(Clone, Default, PartialEq)]
struct Flow<'p> {
    live: HashSet<&'p str>,
    rewritten: HashSet<&'p str>,
    /// `(name, killer value, merged by a branch join, killer at top level)`
    kill_values: Vec<(&'p str, Option<Span>, bool, bool)>,
    exits: bool,
}

impl<'p> Flow<'p> {
    fn kill_value(&self, name: &str) -> Option<(Option<Span>, bool, bool)> {
        self.kill_values
            .iter()
            .find(|(own, _, _, _)| *own == name)
            .map(|(_, value, merged, top)| (*value, *merged, *top))
    }

    fn set_kill(&mut self, name: &'p str, value: Option<Span>, top_level: bool) {
        self.kill_values.retain(|(own, _, _, _)| *own != name);
        self.kill_values.push((name, value, false, top_level));
    }

    fn union(&mut self, other: &Flow<'p>) {
        self.live.extend(other.live.iter().copied());
        self.rewritten.extend(other.rewritten.iter().copied());
        for (name, value, merged, top) in &other.kill_values {
            match self
                .kill_values
                .iter_mut()
                .find(|(own, _, _, _)| own == name)
            {
                Some((_, own_value, own_merged, _)) => {
                    if own_value != value {
                        *own_merged = true;
                    }
                }
                None => self.kill_values.push((name, *value, *merged, *top)),
            }
        }
        self.exits = self.exits && other.exits;
    }

    /// State stamped by `return`/`throw`: everything after it is unreachable,
    /// so only the exiting statement's own reads survive.
    fn exit_flow(&mut self) {
        self.rewritten.clear();
        self.kill_values.clear();
        self.exits = true;
    }
}

/// Entry point: every provably overwritten local store in the program.
///
/// The analyzer doubles as the forward walker: the program body is analyzed
/// as one region, and every function-like node found during the walk gets its
/// own backward pass, so nested regions are analyzed exactly once each.
pub(crate) fn dead_stores(program: &Program<'_>, source: &str) -> Vec<DeadStore> {
    let mut analyzer = Analyzer {
        source,
        visible: HashSet::default(),
        recording: true,
        nesting: 0,
        depth: 0,
        out: Vec::new(),
    };
    analyzer.visit_program(program);
    analyzer.out
}

/// Collects identifier reads for one subtree, resolving shadowing with a
/// scope stack. Plain assignment targets are not reads; compound targets and
/// update operands are.
struct ReadCollector<'p> {
    refs: Vec<&'p str>,
    plain_left_depth: u32,
    shadows: Vec<HashSet<&'p str>>,
}

impl ReadCollector<'_> {
    fn shadowed(&self, name: &str) -> bool {
        self.shadows.iter().any(|set| set.contains(name))
    }
}

impl<'p> Visit<'p> for ReadCollector<'p> {
    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'p>) {
        if !self.shadowed(identifier.name.as_str()) {
            self.refs.push(identifier.name.as_str());
        }
    }

    fn visit_assignment_expression(&mut self, assign: &super::AssignmentExpression<'p>) {
        if assign.operator == AssignmentOperator::Assign {
            self.plain_left_depth += 1;
            walk_assignment_target(self, &assign.left);
            self.plain_left_depth -= 1;
            walk_expression(self, &assign.right);
        } else {
            walk_assignment_expression(self, assign);
        }
    }

    fn visit_simple_assignment_target(&mut self, target: &SimpleAssignmentTarget<'p>) {
        if self.plain_left_depth > 0
            && matches!(
                target,
                SimpleAssignmentTarget::AssignmentTargetIdentifier(_)
            )
        {
            return;
        }
        walk_simple_assignment_target(self, target);
    }

    fn visit_function(&mut self, function: &Function<'p>, flags: ScopeFlags) {
        let mut set = HashSet::default();
        set.extend(parameter_names(&function.params));
        if let Some(body) = &function.body {
            collect_block_scoped_names(&body.statements, &mut set);
            collect_region_names(&body.statements, &mut set);
        }
        self.shadows.push(set);
        walk_function(self, function, flags);
        self.shadows.pop();
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'p>) {
        let mut set = HashSet::default();
        set.extend(parameter_names(&arrow.params));
        if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
            collect_block_scoped_names(&body.statements, &mut set);
            collect_region_names(&body.statements, &mut set);
        }
        self.shadows.push(set);
        walk_arrow_function_expression(self, arrow);
        self.shadows.pop();
    }

    fn visit_block_statement(&mut self, block: &BlockStatement<'p>) {
        let mut set = HashSet::default();
        collect_block_scoped_names(&block.body, &mut set);
        self.shadows.push(set);
        walk_block_statement(self, block);
        self.shadows.pop();
    }

    fn visit_catch_clause(&mut self, clause: &CatchClause<'p>) {
        let mut set = HashSet::default();
        if let Some(parameter) = &clause.param {
            set.extend(bound_names(&parameter.pattern));
        }
        self.shadows.push(set);
        walk_catch_clause(self, clause);
        self.shadows.pop();
    }

    fn visit_for_statement(&mut self, for_: &ForStatement<'p>) {
        let mut set = HashSet::default();
        if let Some(ForStatementInit::VariableDeclaration(declaration)) = &for_.init {
            collect_declaration_names(declaration, &mut set);
        }
        self.shadows.push(set);
        walk_for_statement(self, for_);
        self.shadows.pop();
    }

    fn visit_for_in_statement(&mut self, for_: &ForInStatement<'p>) {
        let mut set = HashSet::default();
        if let ForStatementLeft::VariableDeclaration(declaration) = &for_.left {
            collect_declaration_names(declaration, &mut set);
        }
        self.shadows.push(set);
        walk_for_in_statement(self, for_);
        self.shadows.pop();
    }

    fn visit_for_of_statement(&mut self, for_: &ForOfStatement<'p>) {
        let mut set = HashSet::default();
        if let ForStatementLeft::VariableDeclaration(declaration) = &for_.left {
            collect_declaration_names(declaration, &mut set);
        }
        self.shadows.push(set);
        walk_for_of_statement(self, for_);
        self.shadows.pop();
    }
}

/// Backward recursion bound. Real code sits far below it; pathological
/// nesting keeps the pass bounded so the forward tracker (which runs on the
/// same bounded analyzer stack) stays the only deep-recursion participant.
const MAX_BACKWARD_DEPTH: u32 = 96;

struct Analyzer<'p, 's> {
    source: &'s str,
    /// Region bindings visible for captured reads and tracked stores.
    visible: HashSet<&'p str>,
    recording: bool,
    /// Branch/loop nesting of the point currently processed backward; the
    /// forward tracker's redundant-assignment rule only covers top level.
    nesting: u32,
    /// Current backward recursion depth (construct statements only).
    depth: u32,
    out: Vec<DeadStore>,
}

impl<'p> Analyzer<'p, '_> {
    fn analyze_function_node<'a>(
        &mut self,
        parameters: &'a FormalParameters<'p>,
        body: Option<&'a [Statement<'p>]>,
    ) {
        if let Some(statements) = body {
            self.analyze_region(Some(parameter_names(parameters)), statements);
        }
    }
}

impl<'p> Visit<'p> for Analyzer<'p, '_> {
    fn visit_program(&mut self, program: &oxc_ast::ast::Program<'p>) {
        self.analyze_region(None, &program.body);
        walk_program(self, program);
    }

    fn visit_function(&mut self, function: &Function<'p>, flags: ScopeFlags) {
        self.analyze_function_node(
            &function.params,
            function
                .body
                .as_ref()
                .map(|body| body.statements.as_slice()),
        );
        walk_function(self, function, flags);
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'p>) {
        let names = parameter_names(&arrow.params);
        if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
            self.analyze_region(Some(names), &body.statements);
        } else if let Some(expression) = arrow.body.as_expression() {
            let saved_visible = std::mem::take(&mut self.visible);
            self.visible = names.into_iter().collect();
            self.expression_backward(expression, Flow::default());
            self.visible = saved_visible;
        }
        walk_arrow_function_expression(self, arrow);
    }

    fn visit_method_definition(&mut self, definition: &MethodDefinition<'p>) {
        self.analyze_function_node(
            &definition.value.params,
            definition
                .value
                .body
                .as_ref()
                .map(|body| body.statements.as_slice()),
        );
        walk_method_definition(self, definition);
    }

    fn visit_static_block(&mut self, block: &StaticBlock<'p>) {
        self.analyze_region(None, &block.body);
        walk_static_block(self, block);
    }
}

impl<'p> Analyzer<'p, '_> {
    /// Runs one backward pass over a function-like region (or the program).
    fn analyze_region(
        &mut self,
        parameter_names: Option<Vec<&'p str>>,
        statements: &[Statement<'p>],
    ) {
        let mut names = parameter_names.unwrap_or_default();
        collect_region_names(statements, &mut names);
        let saved_visible = std::mem::take(&mut self.visible);
        self.visible = names.into_iter().collect();
        self.statements_backward(statements, Flow::default());
        self.visible = saved_visible;
    }

    // --- backward statement transfer ---

    fn statements_backward(
        &mut self,
        statements: &[Statement<'p>],
        mut after: Flow<'p>,
    ) -> Flow<'p> {
        for statement in statements.iter().rev() {
            after = self.statement_backward(statement, after);
        }
        after
    }

    fn statement_backward(&mut self, statement: &Statement<'p>, after: Flow<'p>) -> Flow<'p> {
        let nested = matches!(
            statement,
            Statement::BlockStatement(_)
                | Statement::IfStatement(_)
                | Statement::WhileStatement(_)
                | Statement::DoWhileStatement(_)
                | Statement::ForStatement(_)
                | Statement::ForInStatement(_)
                | Statement::ForOfStatement(_)
                | Statement::SwitchStatement(_)
                | Statement::TryStatement(_)
                | Statement::LabeledStatement(_)
        );
        if nested {
            if self.depth >= MAX_BACKWARD_DEPTH {
                // Pathological nesting: degrade to generous reads and let the
                // forward tracker handle this subtree.
                return self.subtree_reads_statement(statement, after);
            }
            self.depth += 1;
        }
        let result = self.statement_backward_inner(statement, after);
        if nested {
            self.depth -= 1;
        }
        result
    }

    fn statement_backward_inner(&mut self, statement: &Statement<'p>, after: Flow<'p>) -> Flow<'p> {
        match statement {
            Statement::ExpressionStatement(expression) => {
                self.expression_backward(&expression.expression, after)
            }
            Statement::VariableDeclaration(declaration) => {
                self.variable_declaration_backward(declaration, after)
            }
            Statement::BlockStatement(block) => self.block_backward(block, after),
            Statement::IfStatement(if_) => self.if_backward(if_, &after),
            Statement::WhileStatement(while_) => self.loop_backward(
                Some(&while_.test),
                None,
                std::slice::from_ref(&while_.body),
                &[],
                &after,
            ),
            Statement::DoWhileStatement(do_) => self.loop_backward(
                Some(&do_.test),
                None,
                std::slice::from_ref(&do_.body),
                &[],
                &after,
            ),
            Statement::ForStatement(for_) => self.for_statement_backward(for_, &after),
            Statement::ForInStatement(for_) => {
                self.for_in_of_backward(&for_.right, Some(&for_.left), &for_.body, &after)
            }
            Statement::ForOfStatement(for_) => {
                self.for_in_of_backward(&for_.right, Some(&for_.left), &for_.body, &after)
            }
            Statement::SwitchStatement(switch) => self.switch_backward(switch, &after),
            Statement::TryStatement(try_) => self.try_backward(try_, after),
            Statement::ReturnStatement(return_) => {
                let mut flow = after;
                if let Some(argument) = &return_.argument {
                    flow = self.subtree_reads_expression(argument, flow);
                }
                flow.exit_flow();
                flow
            }
            Statement::ThrowStatement(throw) => {
                let mut flow = self.subtree_reads_expression(&throw.argument, after);
                flow.exit_flow();
                flow
            }
            Statement::BreakStatement(_) | Statement::ContinueStatement(_) => after,
            Statement::FunctionDeclaration(function) => match &function.body {
                Some(body) => self.closure_reads(&body.statements, after),
                None => after,
            },
            Statement::LabeledStatement(labeled) => self.statement_backward(&labeled.body, after),
            other => self.subtree_reads_statement(other, after),
        }
    }

    fn block_backward(&mut self, block: &BlockStatement<'p>, after: Flow<'p>) -> Flow<'p> {
        let mut names: Vec<&'p str> = Vec::new();
        collect_block_scoped_names(&block.body, &mut names);
        let saved_visible = self.visible.clone();
        for name in &names {
            self.visible.remove(name);
        }
        let flow = self.statements_backward(&block.body, after);
        self.visible = saved_visible;
        flow
    }

    fn if_backward(&mut self, if_: &IfStatement<'p>, after: &Flow<'p>) -> Flow<'p> {
        self.nesting += 1;
        let then_flow = self.statement_backward(&if_.consequent, after.clone());
        let else_flow = match &if_.alternate {
            Some(alternate) => self.statement_backward(alternate, after.clone()),
            None => after.clone(),
        };
        self.nesting -= 1;
        let mut merged = then_flow;
        merged.union(&else_flow);
        self.expression_reads(&if_.test, merged)
    }

    /// Backward transfer for loops with a per-iteration fixpoint. Phase one
    /// runs without recording until the loop-head state converges; phase two
    /// makes one recording pass against the stabilized head so no store is
    /// judged before its downstream reads are known.
    fn loop_backward(
        &mut self,
        test: Option<&Expression<'p>>,
        update: Option<&Expression<'p>>,
        body: &[Statement<'p>],
        shadow: &[&'p str],
        after: &Flow<'p>,
    ) -> Flow<'p> {
        let saved_visible = self.visible.clone();
        for name in shadow {
            self.visible.remove(name);
        }
        self.nesting += 1;
        let mut head = self.apply_loop_parts(after.clone(), test, update);
        let mut converged = false;
        for _ in 0..16 {
            let saved = std::mem::replace(&mut self.recording, false);
            let body_before = self.statements_backward(body, head.clone());
            self.recording = saved;
            let mut next = self.apply_loop_parts(body_before, test, update);
            next.union(after);
            if next == head {
                converged = true;
                break;
            }
            head = next;
        }
        let mut result = if converged {
            let body_before = self.statements_backward(body, head);
            self.apply_loop_parts(body_before, test, update)
        } else {
            // Non-converging loop: keep the accumulated reads but never
            // report stores inside it.
            head
        };
        result.union(after);
        self.nesting -= 1;
        self.visible = saved_visible;
        result
    }

    fn apply_loop_parts(
        &mut self,
        mut flow: Flow<'p>,
        test: Option<&Expression<'p>>,
        update: Option<&Expression<'p>>,
    ) -> Flow<'p> {
        if let Some(test) = test {
            flow = self.expression_reads(test, flow);
        }
        if let Some(update) = update {
            flow = self.expression_reads(update, flow);
        }
        flow
    }

    fn for_statement_backward(&mut self, for_: &ForStatement<'p>, after: &Flow<'p>) -> Flow<'p> {
        let shadow: Vec<&'p str> = match &for_.init {
            Some(ForStatementInit::VariableDeclaration(declaration)) => {
                let mut names: Vec<&'p str> = Vec::new();
                collect_declaration_names(declaration, &mut names);
                names
            }
            _ => Vec::new(),
        };
        let body = std::slice::from_ref(&for_.body);
        let head_after = self.loop_backward(
            for_.test.as_ref(),
            for_.update.as_ref(),
            body,
            &shadow,
            after,
        );
        // The init runs once, before the loop. Declared names are shadowed
        // (invisible), so their seeds are never reported; expression inits
        // follow the forward tracker's initial-value contract and stay
        // unreported as well.
        match &for_.init {
            Some(ForStatementInit::VariableDeclaration(declaration)) => {
                self.variable_declaration_backward(declaration, head_after)
            }
            Some(other_init) => {
                let saved = std::mem::replace(&mut self.recording, false);
                let mut collector = ReadCollector {
                    refs: Vec::new(),
                    plain_left_depth: 0,
                    shadows: Vec::new(),
                };
                collector.visit_for_statement_init(other_init);
                let flow = self.fold_reads(collector, head_after);
                self.recording = saved;
                flow
            }
            None => head_after,
        }
    }

    fn for_in_of_backward(
        &mut self,
        right: &Expression<'p>,
        left: Option<&ForStatementLeft<'p>>,
        body: &Statement<'p>,
        after: &Flow<'p>,
    ) -> Flow<'p> {
        // The iterable evaluates before the head binding takes effect.
        let mut head = self.expression_reads(right, after.clone());
        let mut shadow: Vec<&'p str> = Vec::new();
        match left {
            Some(ForStatementLeft::VariableDeclaration(declaration)) => {
                head = self.variable_declaration_backward(declaration, head);
                collect_declaration_names(declaration, &mut shadow);
            }
            Some(other_left) => {
                for name in for_left_target_names(other_left) {
                    head.rewritten.insert(name);
                }
            }
            None => {}
        }
        self.loop_backward(None, None, std::slice::from_ref(body), &shadow, &head)
    }

    fn switch_backward(&mut self, switch: &SwitchStatement<'p>, after: &Flow<'p>) -> Flow<'p> {
        // Cases fall through, so their bodies chain; the no-match path skips
        // straight to the state after the switch.
        self.nesting += 1;
        let mut current = after.clone();
        for case in switch.cases.iter().rev() {
            current = self.statements_backward(&case.consequent, current);
        }
        self.nesting -= 1;
        let mut result = current;
        result.union(after);
        result.exits = false;
        self.expression_reads(&switch.discriminant, result)
    }

    fn try_backward(&mut self, try_: &TryStatement<'p>, after: Flow<'p>) -> Flow<'p> {
        self.nesting += 1;
        let finalizer_flow = match &try_.finalizer {
            Some(finalizer) => self.block_backward(finalizer, after),
            None => after,
        };
        let try_flow = self.block_backward(&try_.block, finalizer_flow.clone());
        let catch_flow = match &try_.handler {
            Some(handler) => self.block_backward(&handler.body, finalizer_flow),
            None => finalizer_flow,
        };
        let mut result = try_flow;
        result.union(&catch_flow);
        self.nesting -= 1;
        result
    }

    fn variable_declaration_backward(
        &mut self,
        declaration: &VariableDeclaration<'p>,
        mut after: Flow<'p>,
    ) -> Flow<'p> {
        for declarator in declaration.declarations.iter().rev() {
            after = self.variable_declarator_backward(declarator, declaration.kind, after);
        }
        after
    }

    fn variable_declarator_backward(
        &mut self,
        declarator: &VariableDeclarator<'p>,
        kind: VariableDeclarationKind,
        mut after: Flow<'p>,
    ) -> Flow<'p> {
        if let Some(init) = &declarator.init {
            after = self.expression_backward(init, after);
        }
        self.pattern_declaration_stores(&declarator.id, declarator.init.as_ref(), kind, after)
    }

    fn pattern_declaration_stores(
        &mut self,
        pattern: &BindingPattern<'p>,
        init: Option<&Expression<'p>>,
        kind: VariableDeclarationKind,
        mut after: Flow<'p>,
    ) -> Flow<'p> {
        match pattern {
            BindingPattern::BindingIdentifier(identifier) => {
                let name = identifier.name.as_str();
                match init {
                    None => {
                        if kind == VariableDeclarationKind::Var {
                            // An initializer-less `var` is a runtime no-op.
                            return after;
                        }
                        // A block-scoped declaration without initializer
                        // stops the prior value from reaching later reads.
                        after.live.remove(name);
                        after.kill_values.retain(|(own, _, _, _)| *own != name);
                        after
                    }
                    Some(init) => {
                        let value = init.span();
                        self.store_transfer(name, identifier.span, Some(value), after)
                    }
                }
            }
            BindingPattern::ObjectPattern(object) => {
                for property in object.properties.iter().rev() {
                    if property.computed {
                        after = self.property_key_reads(&property.key, after);
                    }
                    after = self.pattern_declaration_stores(&property.value, init, kind, after);
                }
                if let Some(rest) = &object.rest {
                    after = self.pattern_declaration_stores(&rest.argument, init, kind, after);
                }
                after
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().rev().flatten() {
                    after = self.pattern_declaration_stores(element, init, kind, after);
                }
                if let Some(rest) = &array.rest {
                    after = self.pattern_declaration_stores(&rest.argument, init, kind, after);
                }
                after
            }
            BindingPattern::AssignmentPattern(assignment) => {
                after = self.expression_backward(&assignment.right, after);
                self.pattern_declaration_stores(&assignment.left, init, kind, after)
            }
        }
    }

    // --- expression transfer ---

    fn expression_backward(&mut self, expression: &Expression<'p>, after: Flow<'p>) -> Flow<'p> {
        match expression {
            Expression::AssignmentExpression(assign) => {
                // `x = x++`: the update's effect is discarded (S2123
                // territory); only the read is tracked.
                if assign.operator == AssignmentOperator::Assign
                    && let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left
                    && let Expression::UpdateExpression(update) = &assign.right
                    && let SimpleAssignmentTarget::AssignmentTargetIdentifier(inner) =
                        &update.argument
                    && inner.name == id.name
                {
                    return self.subtree_reads_expression(&assign.right, after);
                }
                if assign.operator == AssignmentOperator::Assign {
                    // The store kills first; the RHS reads (which may read the
                    // variable itself, as in `x = f(x)`) generate afterwards.
                    let after = self.assignment_target_backward(
                        &assign.left,
                        assign.span,
                        assign.operator,
                        Some(assign.right.span()),
                        after,
                    );
                    self.expression_backward(&assign.right, after)
                } else {
                    // Compound operators read the old value first.
                    let after = self.expression_backward(&assign.right, after);
                    self.assignment_target_backward(
                        &assign.left,
                        assign.span,
                        assign.operator,
                        Some(assign.right.span()),
                        after,
                    )
                }
            }
            Expression::SequenceExpression(sequence) => {
                let mut after = after;
                for expression in sequence.expressions.iter().rev() {
                    after = self.expression_backward(expression, after);
                }
                after
            }
            Expression::ConditionalExpression(conditional) => {
                let consequent = self.expression_backward(&conditional.consequent, after.clone());
                let alternate = self.expression_backward(&conditional.alternate, after.clone());
                let mut merged = consequent;
                merged.union(&alternate);
                self.expression_reads(&conditional.test, merged)
            }
            Expression::LogicalExpression(logical) => {
                // The right-hand side runs conditionally: its stores stay
                // unreported, but its reads still count for may-liveness.
                let saved = std::mem::replace(&mut self.recording, false);
                let _ = self.expression_backward(&logical.right, after.clone());
                self.recording = saved;
                let after = self.subtree_reads_expression(&logical.right, after);
                self.expression_reads(&logical.left, after)
            }
            Expression::UpdateExpression(update) => self.update_backward(update, after),
            Expression::CallExpression(call) => {
                let mut after = self.expression_backward(&call.callee, after);
                for argument in call.arguments.iter().rev() {
                    if let Argument::SpreadElement(spread) = argument {
                        after = self.expression_backward(&spread.argument, after);
                    } else if let Some(expression) = argument.as_expression() {
                        after = self.expression_backward(expression, after);
                    }
                }
                after
            }
            other => self.subtree_reads_expression(other, after),
        }
    }

    fn update_backward(&mut self, update: &UpdateExpression<'p>, after: Flow<'p>) -> Flow<'p> {
        if let SimpleAssignmentTarget::AssignmentTargetIdentifier(id) = &update.argument {
            let name = id.name.as_str();
            let site = id.span;
            let mut after = after;
            self.store_transfer_inner(name, site, None, &mut after);
            // The update reads the prior value, so it stays live upstream.
            after.live.insert(name);
            after
        } else {
            let mut collector = ReadCollector {
                refs: Vec::new(),
                plain_left_depth: 0,
                shadows: Vec::new(),
            };
            collector.visit_simple_assignment_target(&update.argument);
            self.fold_reads(collector, after)
        }
    }

    fn assignment_target_backward(
        &mut self,
        target: &AssignmentTarget<'p>,
        assign_span: Span,
        operator: AssignmentOperator,
        rhs_span: Option<Span>,
        after: Flow<'p>,
    ) -> Flow<'p> {
        match target {
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                let name = id.name.as_str();
                if operator == AssignmentOperator::Assign {
                    self.store_transfer(name, id.span, rhs_span, after)
                } else {
                    // Compound operators read the old value before writing.
                    let mut after = self.read_name(name, after);
                    self.store_transfer_inner(name, assign_span, None, &mut after);
                    after.live.insert(name);
                    after
                }
            }
            AssignmentTarget::ArrayAssignmentTarget(array) => {
                let store_kind = pattern_store_kind(operator, rhs_span);
                let mut after = after;
                for element in array.elements.iter().rev().flatten() {
                    after = self.assignment_maybe_default_backward(
                        element,
                        store_kind,
                        assign_span,
                        after,
                    );
                }
                if let Some(rest) = &array.rest {
                    after = self.assignment_target_backward(
                        &rest.target,
                        assign_span,
                        store_kind,
                        None,
                        after,
                    );
                }
                after
            }
            AssignmentTarget::ObjectAssignmentTarget(object) => {
                let store_kind = pattern_store_kind(operator, rhs_span);
                let mut after = after;
                for property in object.properties.iter().rev() {
                    after =
                        self.assignment_property_backward(property, store_kind, assign_span, after);
                }
                if let Some(rest) = &object.rest {
                    after = self.assignment_target_backward(
                        &rest.target,
                        assign_span,
                        store_kind,
                        None,
                        after,
                    );
                }
                after
            }
            other => self.subtree_reads_assignment_target(other, after),
        }
    }

    fn assignment_maybe_default_backward(
        &mut self,
        maybe: &AssignmentTargetMaybeDefault<'p>,
        operator: AssignmentOperator,
        assign_span: Span,
        after: Flow<'p>,
    ) -> Flow<'p> {
        match maybe {
            AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(with_default) => {
                // The store kills first; the default expression may read the
                // prior value of the target itself (`[x = use(x)] = []`), so
                // its reads generate afterwards.
                let after = self.assignment_target_backward(
                    &with_default.binding,
                    with_default.span,
                    operator,
                    None,
                    after,
                );
                self.expression_backward(&with_default.init, after)
            }
            AssignmentTargetMaybeDefault::AssignmentTargetIdentifier(id) => {
                let name = id.name.as_str();
                if operator == AssignmentOperator::Assign {
                    self.store_transfer(name, id.span, None, after)
                } else {
                    let mut after = self.read_name(name, after);
                    self.store_transfer_inner(name, assign_span, None, &mut after);
                    after
                }
            }
            AssignmentTargetMaybeDefault::ArrayAssignmentTarget(array) => {
                let mut after = after;
                for element in array.elements.iter().rev().flatten() {
                    after = self.assignment_maybe_default_backward(
                        element,
                        operator,
                        assign_span,
                        after,
                    );
                }
                after
            }
            AssignmentTargetMaybeDefault::ObjectAssignmentTarget(object) => {
                let mut after = after;
                for property in object.properties.iter().rev() {
                    after =
                        self.assignment_property_backward(property, operator, assign_span, after);
                }
                after
            }
            _ => after,
        }
    }

    fn assignment_property_backward(
        &mut self,
        property: &AssignmentTargetProperty<'p>,
        operator: AssignmentOperator,
        assign_span: Span,
        mut after: Flow<'p>,
    ) -> Flow<'p> {
        match property {
            AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(identifier) => {
                if let Some(init) = &identifier.init {
                    after = self.expression_backward(init, after);
                }
                let name = identifier.binding.name.as_str();
                if operator == AssignmentOperator::Assign {
                    self.store_transfer(name, identifier.binding.span, None, after)
                } else {
                    after = self.read_name(name, after);
                    self.store_transfer_inner(name, assign_span, None, &mut after);
                    after.live.insert(name);
                    after
                }
            }
            AssignmentTargetProperty::AssignmentTargetPropertyProperty(property) => {
                after = self.property_key_reads(&property.name, after);
                self.assignment_maybe_default_backward(
                    &property.binding,
                    operator,
                    assign_span,
                    after,
                )
            }
        }
    }

    fn property_key_reads(&mut self, key: &PropertyKey<'p>, after: Flow<'p>) -> Flow<'p> {
        match key {
            PropertyKey::StaticIdentifier(_) | PropertyKey::PrivateIdentifier(_) => after,
            other => self.subtree_reads_property_key(other, after),
        }
    }

    /// Records one store: reportable when the name may be rewritten later
    /// and is read on no path in between; always kills the prior value.
    fn store_transfer(
        &mut self,
        name: &'p str,
        site: Span,
        value: Option<Span>,
        mut after: Flow<'p>,
    ) -> Flow<'p> {
        self.store_transfer_inner(name, site, value, &mut after);
        after
    }

    fn store_transfer_inner(
        &mut self,
        name: &'p str,
        site: Span,
        value: Option<Span>,
        after: &mut Flow<'p>,
    ) {
        if !self.visible.contains(name) {
            return;
        }
        // Reportable only when the name is provably rewritten later and read
        // on no path in between. (Unreachable-code pollution is already
        // handled by the exit statement's fresh state stamp.)
        if self.recording && after.rewritten.contains(name) && !after.live.contains(name) {
            // Same-value rewrites the forward tracker already covers (its
            // redundant-assignment rule runs on straight-line top-level
            // flow) are left to it.
            let suppress = after.kill_value(name).is_some_and(|(killer, merged, top)| {
                !merged && top && same_value(killer, value, self.source)
            });
            if !suppress {
                self.out.push(DeadStore {
                    name: name.to_string(),
                    site,
                });
            }
        }
        after.live.remove(name);
        after.rewritten.insert(name);
        after.set_kill(name, value, self.nesting == 0);
    }

    // --- read folding ---

    fn expression_reads(&mut self, expression: &Expression<'p>, after: Flow<'p>) -> Flow<'p> {
        self.subtree_reads_expression(expression, after)
    }

    fn read_name(&mut self, name: &'p str, mut after: Flow<'p>) -> Flow<'p> {
        if self.visible.contains(name) {
            after.live.insert(name);
            if let Some(entry) = after
                .kill_values
                .iter_mut()
                .find(|(own, _, _, _)| *own == name)
            {
                entry.2 = true;
            }
        }
        after
    }

    fn fold_reads(&mut self, collector: ReadCollector<'p>, mut after: Flow<'p>) -> Flow<'p> {
        for name in collector.refs {
            if self.visible.contains(name) {
                after.live.insert(name);
            }
        }
        after
    }

    /// Folds the generous reads of one expression subtree into `after`.
    fn subtree_reads_expression(
        &mut self,
        expression: &Expression<'p>,
        after: Flow<'p>,
    ) -> Flow<'p> {
        let mut collector = ReadCollector {
            refs: Vec::new(),
            plain_left_depth: 0,
            shadows: Vec::new(),
        };
        collector.visit_expression(expression);
        self.fold_reads(collector, after)
    }

    fn subtree_reads_statement(&mut self, statement: &Statement<'p>, after: Flow<'p>) -> Flow<'p> {
        let mut collector = ReadCollector {
            refs: Vec::new(),
            plain_left_depth: 0,
            shadows: Vec::new(),
        };
        collector.visit_statement(statement);
        self.fold_reads(collector, after)
    }

    fn subtree_reads_assignment_target(
        &mut self,
        target: &AssignmentTarget<'p>,
        after: Flow<'p>,
    ) -> Flow<'p> {
        let mut collector = ReadCollector {
            refs: Vec::new(),
            plain_left_depth: 0,
            shadows: Vec::new(),
        };
        collector.visit_assignment_target(target);
        self.fold_reads(collector, after)
    }

    fn subtree_reads_property_key(&mut self, key: &PropertyKey<'p>, after: Flow<'p>) -> Flow<'p> {
        let mut collector = ReadCollector {
            refs: Vec::new(),
            plain_left_depth: 0,
            shadows: Vec::new(),
        };
        collector.visit_property_key(key);
        self.fold_reads(collector, after)
    }

    /// Closure bodies contribute reads of captured region bindings.
    fn closure_reads(&mut self, statements: &[Statement<'p>], after: Flow<'p>) -> Flow<'p> {
        let mut collector = ReadCollector {
            refs: Vec::new(),
            plain_left_depth: 0,
            shadows: Vec::new(),
        };
        for statement in statements {
            collector.visit_statement(statement);
        }
        self.fold_reads(collector, after)
    }
}

/// Destructuring stores keep `None` values (no same-value suppression).
fn pattern_store_kind(operator: AssignmentOperator, rhs_span: Option<Span>) -> AssignmentOperator {
    let _ = rhs_span;
    operator
}

fn same_value(left: Option<Span>, right: Option<Span>, source: &str) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => source_slice(source, left) == source_slice(source, right),
        _ => false,
    }
}

fn parameter_names<'p>(parameters: &FormalParameters<'p>) -> Vec<&'p str> {
    let mut names: Vec<&'p str> = parameters
        .items
        .iter()
        .flat_map(|parameter| bound_names(&parameter.pattern))
        .collect();
    if let Some(rest) = &parameters.rest {
        names.extend(bound_names(&rest.rest.argument));
    }
    names
}

fn collect_declaration_names<'p, E: Extend<&'p str>>(
    declaration: &VariableDeclaration<'p>,
    out: &mut E,
) {
    for declarator in &declaration.declarations {
        out.extend(bound_names(&declarator.id));
    }
}

/// Names bound directly in one statement list (parameters handled by the
/// caller): all declaration kinds plus function/class/import bindings.
fn collect_region_names<'p, E: Extend<&'p str>>(statements: &[Statement<'p>], out: &mut E) {
    for statement in statements {
        match statement {
            Statement::VariableDeclaration(declaration) => {
                collect_declaration_names(declaration, out);
            }
            Statement::FunctionDeclaration(function) => {
                if let Some(id) = &function.id {
                    out.extend(std::iter::once(id.name.as_str()));
                }
            }
            Statement::ClassDeclaration(class) => {
                if let Some(id) = &class.id {
                    out.extend(std::iter::once(id.name.as_str()));
                }
            }
            Statement::ImportDeclaration(import) => {
                for specifier in import.specifiers.iter().flatten() {
                    let local = match specifier {
                        ImportDeclarationSpecifier::ImportSpecifier(specifier) => &specifier.local,
                        ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
                            &specifier.local
                        }
                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
                            &specifier.local
                        }
                    };
                    out.extend(std::iter::once(local.name.as_str()));
                }
            }
            _ => {}
        }
    }
}

/// Block-scoped bindings only: `var` keeps its enclosing-region identity.
fn collect_block_scoped_names<'p, E: Extend<&'p str>>(statements: &[Statement<'p>], out: &mut E) {
    for statement in statements {
        match statement {
            Statement::VariableDeclaration(declaration) => {
                if declaration.kind != VariableDeclarationKind::Var {
                    collect_declaration_names(declaration, out);
                }
            }
            Statement::FunctionDeclaration(function) => {
                if let Some(id) = &function.id {
                    out.extend(std::iter::once(id.name.as_str()));
                }
            }
            Statement::ClassDeclaration(class) => {
                if let Some(id) = &class.id {
                    out.extend(std::iter::once(id.name.as_str()));
                }
            }
            _ => {}
        }
    }
}

fn for_left_target_names<'p>(left: &ForStatementLeft<'p>) -> Vec<&'p str> {
    match left {
        ForStatementLeft::AssignmentTargetIdentifier(id) => vec![id.name.as_str()],
        ForStatementLeft::ArrayAssignmentTarget(array) => array_target_names(array),
        ForStatementLeft::ObjectAssignmentTarget(object) => object_target_names(object),
        _ => Vec::new(),
    }
}

fn array_target_names<'p>(array: &ArrayAssignmentTarget<'p>) -> Vec<&'p str> {
    let mut names = Vec::new();
    for element in array.elements.iter().flatten() {
        names.extend(maybe_default_names(element));
    }
    if let Some(rest) = &array.rest {
        names.extend(assignment_target_names(&rest.target));
    }
    names
}

fn object_target_names<'p>(object: &ObjectAssignmentTarget<'p>) -> Vec<&'p str> {
    let mut names = Vec::new();
    for property in &object.properties {
        match property {
            AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(identifier) => {
                names.push(identifier.binding.name.as_str());
            }
            AssignmentTargetProperty::AssignmentTargetPropertyProperty(property) => {
                names.extend(maybe_default_names(&property.binding));
            }
        }
    }
    if let Some(rest) = &object.rest {
        names.extend(assignment_target_names(&rest.target));
    }
    names
}

fn maybe_default_names<'p>(maybe: &AssignmentTargetMaybeDefault<'p>) -> Vec<&'p str> {
    match maybe {
        AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(with_default) => {
            assignment_target_names(&with_default.binding)
        }
        AssignmentTargetMaybeDefault::AssignmentTargetIdentifier(id) => vec![id.name.as_str()],
        AssignmentTargetMaybeDefault::ArrayAssignmentTarget(array) => array_target_names(array),
        AssignmentTargetMaybeDefault::ObjectAssignmentTarget(object) => object_target_names(object),
        _ => Vec::new(),
    }
}

fn assignment_target_names<'p>(target: &AssignmentTarget<'p>) -> Vec<&'p str> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => vec![id.name.as_str()],
        AssignmentTarget::ArrayAssignmentTarget(array) => array_target_names(array),
        AssignmentTarget::ObjectAssignmentTarget(object) => object_target_names(object),
        _ => Vec::new(),
    }
}
