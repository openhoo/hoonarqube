use super::{
    ArrowFunctionExpression, AssignmentExpression, AssignmentOperator,
    AssignmentTargetPropertyIdentifier, AssignmentTargetWithDefault, BindingPattern,
    BlockStatement, CallExpression, Class, ExportDefaultDeclarationKind, ExportSpecifier,
    Expression, ImportDeclaration, ImportDeclarationSpecifier, MemberExpression, MethodDefinition,
    MethodDefinitionKind, ModuleExportName, NewExpression, ScopeFlags, Span, StaticBlock,
    SwitchStatement, TbBinding, TbCallee, TbEvent, TbKind, TbModel, TbScope, TbScopeKind,
    TbSignature, TbSite, UnaryExpression, UnaryOperator, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator, Visit, finish_model, member_object,
    static_property_name, unparenthesized, walk_arrow_function_expression, walk_block_statement,
    walk_call_expression, walk_catch_clause, walk_class, walk_export_default_declaration,
    walk_expression, walk_for_statement, walk_function, walk_member_expression,
    walk_method_definition, walk_new_expression, walk_program, walk_static_block,
    walk_switch_statement, walk_unary_expression, walk_variable_declaration,
    walk_variable_declarator,
};

/// Builds the [`TbModel`] in one `Visit` pass. Writes versus reads are told
/// apart by an assignment/update depth guard: the default walk funnels both
/// assignment-target identifiers and ordinary references through
/// `visit_identifier_reference`.
pub(crate) struct TbBuilder<'a, 'm> {
    pub(crate) model: &'m mut TbModel<'a>,
    pub(crate) stack: Vec<usize>,
    pub(crate) write_depth: u32,
    pub(crate) compound: bool,
    pub(crate) skip_parameters: bool,
    /// Kind of the variable declaration currently being walked.
    pub(crate) pending_kind: TbKind,
}

impl<'a> TbBuilder<'a, '_> {
    pub(crate) fn push_scope(&mut self, kind: TbScopeKind, span: Span) {
        let parent = self.stack.last().copied();
        self.model.scopes.push(TbScope {
            parent,
            kind,
            span,
            bindings: Vec::new(),
        });
        self.stack.push(self.model.scopes.len() - 1);
    }

    pub(crate) fn pop_scope(&mut self) {
        self.stack.pop();
    }

    pub(crate) fn declare(&mut self, name: &'a str, kind: TbKind, decl: Span) -> usize {
        let target = match kind {
            // `var` hoists to the nearest function/program boundary; imports
            // always live at module top level.
            TbKind::Var => self.nearest_function_scope(),
            TbKind::Import => 0,
            _ => self.stack.last().copied().unwrap_or(0),
        };
        let home_block = match kind {
            TbKind::Var => self.home_block(),
            _ => None,
        };
        let global = self.model.scopes[target].kind == TbScopeKind::Program;
        let id = self.model.bindings.len();
        self.model.bindings.push(TbBinding {
            name,
            kind,
            decl,
            reads: Vec::new(),
            writes: Vec::new(),
            home_block,
            arity: None,
            global,
            array_like: false,
        });
        self.model.scopes[target].bindings.push(id);
        id
    }

    pub(crate) fn nearest_function_scope(&self) -> usize {
        self.stack
            .iter()
            .rev()
            .find(|s| self.model.scopes[**s].kind != TbScopeKind::Block)
            .copied()
            .unwrap_or(0)
    }

    /// Innermost enclosing block above the nearest function boundary — the
    /// home of a hoisted `var`, used by `S2392`.
    pub(crate) fn home_block(&self) -> Option<Span> {
        self.stack.iter().rev().find_map(|scope| {
            let scope = &self.model.scopes[*scope];
            match scope.kind {
                TbScopeKind::Block => Some(scope.span),
                TbScopeKind::Program | TbScopeKind::Function => None,
            }
        })
    }

    pub(crate) fn record_reference(&mut self, name: &'a str, span: Span) {
        self.model.events.push(TbEvent {
            name,
            span,
            write: self.write_depth > 0,
            compound: self.compound,
            chain: self.stack.clone(),
        });
    }

    pub(crate) fn record_callee(
        &mut self,
        expression: &Expression<'a>,
        arguments: &[oxc_ast::ast::Argument<'a>],
        constructor: bool,
    ) {
        let Expression::Identifier(reference) = unparenthesized(expression) else {
            return;
        };
        let mut explicit_undefined = Vec::new();
        let mut spread = false;
        for (position, argument) in arguments.iter().enumerate() {
            match argument.as_expression() {
                None => spread = true,
                Some(expression) => {
                    if let Expression::Identifier(name) = unparenthesized(expression)
                        && name.name == "undefined"
                    {
                        explicit_undefined.push((position, name.span));
                    }
                }
            }
        }
        self.model.callees.push(TbCallee {
            name: reference.name.as_str(),
            span: reference.span,
            arity: arguments.len(),
            constructor,
            chain: self.stack.clone(),
            explicit_undefined,
            spread,
        });
    }

    /// `delete x[i]` on an array-like binding (`S2870`).
    pub(crate) fn record_delete(&mut self, unary: &UnaryExpression<'a>) {
        if unary.operator != UnaryOperator::Delete {
            return;
        }
        if let Some(member) = unary.argument.as_member_expression()
            && let Expression::Identifier(object) = member_object(member)
        {
            self.model.delete_sites.push(TbSite {
                name: object.name.as_str(),
                span: unary.span,
                chain: self.stack.clone(),
            });
        }
    }

    pub(crate) fn declare_pattern(&mut self, pattern: &BindingPattern<'a>, kind: TbKind) {
        match pattern {
            BindingPattern::BindingIdentifier(identifier) => {
                self.declare(identifier.name.as_str(), kind, identifier.span);
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    self.declare_pattern(&property.value, kind);
                }
                if let Some(rest) = &object.rest {
                    self.declare_pattern(&rest.argument, kind);
                }
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    self.declare_pattern(element, kind);
                }
                if let Some(rest) = &array.rest {
                    self.declare_pattern(&rest.argument, kind);
                }
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.declare_pattern(&assignment.left, kind);
            }
        }
    }

    pub(crate) fn declare_parameters(&mut self, parameters: &oxc_ast::ast::FormalParameters<'a>) {
        if self.skip_parameters {
            return;
        }
        for parameter in &parameters.items {
            // TypeScript parameter properties assign `this.x` implicitly;
            // they are never plain local parameters.
            if parameter.accessibility.is_none() && !parameter.readonly {
                self.declare_pattern(&parameter.pattern, TbKind::Param);
            }
        }
        if let Some(rest) = &parameters.rest {
            self.declare_pattern(&rest.rest.argument, TbKind::Param);
        }
    }

    /// `for (let v of xs)` assigns `v` although no assignment node exists.
    pub(crate) fn mark_loop_bindings(&mut self, declaration: &VariableDeclaration<'a>) {
        if matches!(declaration.kind, VariableDeclarationKind::Const) {
            return;
        }
        for declarator in &declaration.declarations {
            self.mark_loop_pattern(&declarator.id);
        }
    }

    fn mark_loop_pattern(&mut self, pattern: &BindingPattern<'a>) {
        match pattern {
            BindingPattern::BindingIdentifier(identifier) => {
                self.model.events.push(TbEvent {
                    name: identifier.name.as_str(),
                    span: identifier.span,
                    write: true,
                    compound: false,
                    chain: self.stack.clone(),
                });
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    self.mark_loop_pattern(&property.value);
                }
                if let Some(rest) = &object.rest {
                    self.mark_loop_pattern(&rest.argument);
                }
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    self.mark_loop_pattern(element);
                }
                if let Some(rest) = &array.rest {
                    self.mark_loop_pattern(&rest.argument);
                }
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.mark_loop_pattern(&assignment.left);
            }
        }
    }
    /// Loop-head targets are visited while the loop scope is active, with
    /// declaration and assignment targets classified as writes accordingly.
    fn visit_for_head(&mut self, left: &oxc_ast::ast::ForStatementLeft<'a>) {
        match left {
            oxc_ast::ast::ForStatementLeft::VariableDeclaration(declaration) => {
                self.visit_variable_declaration(declaration);
                self.mark_loop_bindings(declaration);
            }
            left => {
                let saved = self.write_depth;
                self.write_depth += 1;
                self.visit_for_statement_left(left);
                self.write_depth = saved;
            }
        }
    }
}

impl<'a> Visit<'a> for TbBuilder<'a, '_> {
    fn visit_program(&mut self, program: &oxc_ast::ast::Program<'a>) {
        self.push_scope(TbScopeKind::Program, program.span);
        walk_program(self, program);
        self.pop_scope();
    }

    fn visit_block_statement(&mut self, statement: &BlockStatement<'a>) {
        self.push_scope(TbScopeKind::Block, statement.span);
        walk_block_statement(self, statement);
        self.pop_scope();
    }

    fn visit_switch_statement(&mut self, statement: &SwitchStatement<'a>) {
        self.push_scope(TbScopeKind::Block, statement.span);
        walk_switch_statement(self, statement);
        self.pop_scope();
    }

    fn visit_static_block(&mut self, block: &StaticBlock<'a>) {
        self.push_scope(TbScopeKind::Function, block.span);
        walk_static_block(self, block);
        self.pop_scope();
    }

    fn visit_for_statement(&mut self, statement: &oxc_ast::ast::ForStatement<'a>) {
        self.push_scope(TbScopeKind::Block, statement.span);
        walk_for_statement(self, statement);
        self.pop_scope();
    }

    fn visit_for_in_statement(&mut self, statement: &oxc_ast::ast::ForInStatement<'a>) {
        self.push_scope(TbScopeKind::Block, statement.span);
        self.visit_for_head(&statement.left);
        // The iterable resolves in the enclosing scope: the loop-head
        // binding is not yet initialized where the iterable evaluates.
        let head = self.stack.pop();
        self.visit_expression(&statement.right);
        if let Some(id) = head {
            self.stack.push(id);
        }
        self.visit_statement(&statement.body);
        self.pop_scope();
    }

    fn visit_for_of_statement(&mut self, statement: &oxc_ast::ast::ForOfStatement<'a>) {
        self.push_scope(TbScopeKind::Block, statement.span);
        self.visit_for_head(&statement.left);
        // The iterable resolves in the enclosing scope: the loop-head
        // binding is not yet initialized where the iterable evaluates.
        let head = self.stack.pop();
        self.visit_expression(&statement.right);
        if let Some(id) = head {
            self.stack.push(id);
        }
        self.visit_statement(&statement.body);
        self.pop_scope();
    }

    fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
        self.push_scope(TbScopeKind::Block, clause.span);
        if let Some(param) = &clause.param {
            self.declare_pattern(&param.pattern, TbKind::CatchParam);
        }
        walk_catch_clause(self, clause);
        self.pop_scope();
    }

    fn visit_function(&mut self, function: &oxc_ast::ast::Function<'a>, flags: ScopeFlags) {
        let declaration = function.r#type == oxc_ast::ast::FunctionType::FunctionDeclaration;
        let mut name_binding = None;
        if declaration && let Some(id) = &function.id {
            name_binding = Some(self.declare(id.name.as_str(), TbKind::Function, id.span));
        }
        self.push_scope(TbScopeKind::Function, function.span);
        if !declaration && let Some(id) = &function.id {
            self.declare(id.name.as_str(), TbKind::Function, id.span);
        }
        self.declare_parameters(&function.params);
        self.skip_parameters = false;
        let arity = signature_arity(&function.params);
        if let Some(binding) = name_binding {
            self.model.bindings[binding].arity = Some(arity);
        }
        walk_function(self, function, flags);
        self.pop_scope();
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        self.push_scope(TbScopeKind::Function, arrow.span);
        self.declare_parameters(&arrow.params);
        walk_arrow_function_expression(self, arrow);
        self.pop_scope();
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
        // Setters legitimately leave their parameter unread (`S1172`); the
        // flag is consumed and cleared by the method's own `visit_function`.
        if method.kind == MethodDefinitionKind::Set {
            self.skip_parameters = true;
        }
        walk_method_definition(self, method);
        self.skip_parameters = false;
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        let declaration = class.r#type == oxc_ast::ast::ClassType::ClassDeclaration;
        if declaration && let Some(id) = &class.id {
            self.declare(id.name.as_str(), TbKind::Class, id.span);
        }
        self.push_scope(TbScopeKind::Block, class.span);
        if !declaration && let Some(id) = &class.id {
            self.declare(id.name.as_str(), TbKind::Class, id.span);
        }
        walk_class(self, class);
        self.pop_scope();
    }

    fn visit_unary_expression(&mut self, unary: &UnaryExpression<'a>) {
        self.record_delete(unary);
        walk_unary_expression(self, unary);
    }

    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'a>) {
        let saved = self.pending_kind;
        self.pending_kind = match declaration.kind {
            VariableDeclarationKind::Var => TbKind::Var,
            VariableDeclarationKind::Let => TbKind::Let,
            _ => TbKind::Const,
        };
        walk_variable_declaration(self, declaration);
        self.pending_kind = saved;
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        let before = self.model.bindings.len();
        self.declare_pattern(&declarator.id, self.pending_kind);
        if before < self.model.bindings.len()
            && matches!(declarator.id, BindingPattern::BindingIdentifier(_))
            && matches!(declarator.init, Some(Expression::ArrayExpression(_)))
        {
            self.model.bindings[before].array_like = true;
        }
        walk_variable_declarator(self, declarator);
    }

    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
        let Some(specifiers) = &declaration.specifiers else {
            return;
        };
        for specifier in specifiers {
            let local = match specifier {
                ImportDeclarationSpecifier::ImportSpecifier(specifier) => &specifier.local,
                ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => &specifier.local,
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => &specifier.local,
            };
            self.declare(local.name.as_str(), TbKind::Import, local.span);
        }
    }

    fn visit_export_specifier(&mut self, specifier: &ExportSpecifier<'a>) {
        // `export { local }` keeps the local binding alive.
        if let ModuleExportName::IdentifierReference(reference) = &specifier.local {
            self.record_reference(reference.name.as_str(), reference.span);
        }
    }

    fn visit_export_default_declaration(
        &mut self,
        declaration: &oxc_ast::ast::ExportDefaultDeclaration<'a>,
    ) {
        // `export default function name() {}` uses `name`.
        if let ExportDefaultDeclarationKind::FunctionDeclaration(function) =
            &declaration.declaration
            && let Some(id) = &function.id
        {
            self.record_reference(id.name.as_str(), id.span);
        }
        walk_export_default_declaration(self, declaration);
    }

    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        self.compound |= assignment.operator != AssignmentOperator::Assign;
        self.write_depth += 1;
        self.visit_assignment_target(&assignment.left);
        self.write_depth -= 1;
        self.compound = false;
        walk_expression(self, &assignment.right);
    }

    fn visit_update_expression(&mut self, update: &oxc_ast::ast::UpdateExpression<'a>) {
        self.compound = true;
        self.write_depth += 1;
        self.visit_simple_assignment_target(&update.argument);
        self.write_depth -= 1;
        self.compound = false;
    }

    /// The object of a member assignment target is always a read; nested
    /// assignment expressions re-raise the depth themselves.
    fn visit_member_expression(&mut self, member: &MemberExpression<'a>) {
        let saved = self.write_depth;
        self.write_depth = 0;
        walk_member_expression(self, member);
        self.write_depth = saved;
    }

    /// `[k = f()] = arr` / `({a: b = f()} = o)`: the binding target keeps its
    /// write classification while the default expression stays a read.
    fn visit_assignment_target_with_default(&mut self, target: &AssignmentTargetWithDefault<'a>) {
        self.visit_assignment_target(&target.binding);
        let saved = self.write_depth;
        self.write_depth = 0;
        self.visit_expression(&target.init);
        self.write_depth = saved;
    }

    /// `({a = helper()} = o)`: the shorthand binding is a write, its default
    /// expression a read.
    fn visit_assignment_target_property_identifier(
        &mut self,
        property: &AssignmentTargetPropertyIdentifier<'a>,
    ) {
        self.visit_identifier_reference(&property.binding);
        let saved = self.write_depth;
        self.write_depth = 0;
        if let Some(init) = &property.init {
            self.visit_expression(init);
        }
        self.write_depth = saved;
    }

    /// Computed destructuring keys are reads; only their binding targets
    /// inherit the surrounding assignment write classification.
    fn visit_assignment_target_property_property(
        &mut self,
        property: &oxc_ast::ast::AssignmentTargetPropertyProperty<'a>,
    ) {
        let saved = self.write_depth;
        self.write_depth = 0;
        self.visit_property_key(&property.name);
        self.write_depth = saved;
        self.visit_assignment_target_maybe_default(&property.binding);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.record_callee(&call.callee, &call.arguments, false);
        walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, new: &NewExpression<'a>) {
        self.record_callee(&new.callee, &new.arguments, true);
        walk_new_expression(self, new);
    }

    fn visit_identifier_reference(&mut self, reference: &oxc_ast::ast::IdentifierReference<'a>) {
        self.record_reference(reference.name.as_str(), reference.span);
    }
}

/// `(minimum, hard maximum, optional positions)` of one signature; a rest
/// parameter removes the maximum.
pub(crate) fn signature_arity(parameters: &oxc_ast::ast::FormalParameters<'_>) -> TbSignature {
    let optional = parameters
        .items
        .iter()
        .enumerate()
        .filter(|(_, parameter)| parameter.initializer.is_some() || parameter.optional)
        .map(|(position, _)| position)
        .collect();
    let minimum = parameters
        .items
        .iter()
        .rposition(|parameter| parameter.initializer.is_none() && !parameter.optional)
        .map_or(0, |position| position + 1);
    let maximum = parameters.rest.is_none().then(|| parameters.items.len());
    TbSignature {
        minimum,
        maximum,
        optional,
    }
}

pub(crate) fn build_tb_model<'a>(program: &'a oxc_ast::ast::Program<'a>) -> TbModel<'a> {
    let mut model = TbModel {
        scopes: Vec::new(),
        bindings: Vec::new(),
        events: Vec::new(),
        callees: Vec::new(),
        shadows: Vec::new(),
        duplicates: Vec::new(),
        implicit_globals: Vec::new(),
        calls: Vec::new(),
        news: Vec::new(),
        delete_sites: Vec::new(),
        array_deletes: Vec::new(),
    };
    let mut builder = TbBuilder {
        model: &mut model,
        stack: Vec::new(),
        write_depth: 0,
        compound: false,
        skip_parameters: false,
        pending_kind: TbKind::Let,
    };
    builder.visit_program(program);
    finish_model(model)
}

pub(crate) fn callee_member_name<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    call.callee
        .as_member_expression()
        .and_then(static_property_name)
}
