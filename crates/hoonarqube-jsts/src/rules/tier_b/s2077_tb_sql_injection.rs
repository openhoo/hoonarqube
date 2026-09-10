// Rule module s2077_tb_sql_injection (generated).
use crate::engine::scope_model::bound_names;
use crate::support::{
    IssueSink, RuleScope, identifier_name, module_export_name_name, property_key_name,
    unparenthesized,
};
use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, AssignmentOperator, BindingPattern,
    BlockStatement, CallExpression, Declaration, Expression, ForInStatement, ForOfStatement,
    ForStatement, ForStatementLeft, Function, ImportDeclaration, ImportDeclarationSpecifier,
    ImportOrExportKind, Program, SimpleAssignmentTarget, Statement, StaticBlock, SwitchStatement,
    TSModuleReference, UpdateExpression, VariableDeclaration, VariableDeclarationKind,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_block_statement,
    walk_catch_clause, walk_declaration, walk_for_in_statement, walk_for_of_statement,
    walk_for_statement, walk_function, walk_program, walk_static_block, walk_switch_statement,
    walk_update_expression, walk_variable_declaration,
};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;
use std::collections::BTreeSet;

/// `S2077`: SQL sinks fed interpolated or concatenated strings.
pub(crate) fn check_tb_sql_injection(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = SqlInjectionCollector::default();
    collector.collect(program);
    for span in &collector.sites {
        sink.emit_span(
            RuleScope::Both,
            "S2077",
            "Make sure that executing SQL queries is safe here.",
            *span,
        );
    }
}

const SQL_QUERY_SIGNATURES: &[&str] = &[
    "pg.Client.query",
    "pg.Pool.query",
    "mysql.createConnection.query",
    "mysql.createPool.query",
    "mysql.createPoolCluster.query",
    "mysql2.createConnection.query",
    "mysql2.createPool.query",
    "mysql2.createPoolCluster.query",
    "sequelize.Sequelize.query",
    "sqlite3.Database.run",
    "sqlite3.Database.get",
    "sqlite3.Database.all",
    "sqlite3.Database.each",
    "sqlite3.Database.exec",
    "better-sqlite3.exec",
    "better-sqlite3.prepare",
    "mssql.ConnectionPool.query",
    "mssql.Request.query",
    "mssql.Request.batch",
    "mssql.Request.execute",
    "mysql2.createConnection.execute",
    "oracledb.getConnection.execute",
    "oracledb.getConnection.executeMany",
    "oracledb.getConnection.queryStream",
    "pg-promise.any",
    "pg-promise.each",
    "pg-promise.func",
    "pg-promise.many",
    "pg-promise.manyOrNone",
    "pg-promise.map",
    "pg-promise.multi",
    "pg-promise.multiResult",
    "pg-promise.none",
    "pg-promise.one",
    "pg-promise.oneOrNone",
    "pg-promise.proc",
    "pg-promise.query",
    "pg-promise.result",
    "knex.raw",
    "knex.whereRaw",
    "knex.havingRaw",
    "knex.groupByRaw",
    "knex.orderByRaw",
    "knex.joinRaw",
    "typeorm.createConnection.query",
    "typeorm.getConnection.query",
    "typeorm.getManager.query",
    "typeorm.getRepository.query",
];

#[derive(Clone)]
enum SqlSource<'a> {
    Unknown,
    Path(String),
    Expression {
        expression: &'a Expression<'a>,
        suffix: String,
        scope: usize,
        function_scope: usize,
        at: u32,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SqlStateKind {
    Declaration,
    Write,
}

struct SqlState<'a> {
    at: u32,
    function_scope: usize,
    kind: SqlStateKind,
    source: SqlSource<'a>,
}

struct SqlBinding<'a> {
    name: &'a str,
    scope: usize,
    start: u32,
    hoisted: bool,
    states: Vec<SqlState<'a>>,
}

struct SqlScope {
    parent: Option<usize>,
    function_scope: usize,
}

struct SqlWrite<'a> {
    name: &'a str,
    scope: usize,
    function_scope: usize,
    at: u32,
    source: SqlSource<'a>,
}

struct SqlCall<'a> {
    call: &'a CallExpression<'a>,
    scope: usize,
    function_scope: usize,
}

#[derive(Default)]
pub(crate) struct SqlInjectionCollector<'a> {
    pub(crate) sites: Vec<Span>,
    bindings: Vec<SqlBinding<'a>>,
    scopes: Vec<SqlScope>,
    scope_stack: Vec<usize>,
    writes: Vec<SqlWrite<'a>>,
    calls: Vec<SqlCall<'a>>,
}

impl<'a> SqlInjectionCollector<'a> {
    fn collect(&mut self, program: &'a Program<'a>) {
        self.visit_program(program);
        self.materialize_writes();
        for call in &self.calls {
            let Some(path) = self.resolve_path(
                &call.call.callee,
                call.scope,
                call.call.span.start,
                call.function_scope,
            ) else {
                continue;
            };
            if !SQL_QUERY_SIGNATURES.contains(&path.as_str()) {
                continue;
            }
            let Some(argument) = call
                .call
                .arguments
                .first()
                .and_then(|argument| argument.as_expression())
            else {
                continue;
            };
            if is_dynamic_sql(argument) {
                self.sites.push(call.call.callee.span());
            }
        }
    }

    fn push_program_scope(&mut self) {
        let id = self.scopes.len();
        self.scopes.push(SqlScope {
            parent: None,
            function_scope: id,
        });
        self.scope_stack.push(id);
    }

    fn push_scope(&mut self, function: bool) -> usize {
        let id = self.scopes.len();
        let parent = self.scope_stack.last().copied();
        let function_scope = if function {
            id
        } else {
            self.current_function_scope()
        };
        self.scopes.push(SqlScope {
            parent,
            function_scope,
        });
        self.scope_stack.push(id);
        id
    }

    fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    fn current_scope(&self) -> usize {
        self.scope_stack.last().copied().unwrap_or(0)
    }

    fn current_function_scope(&self) -> usize {
        self.scopes
            .get(self.current_scope())
            .map_or(0, |scope| scope.function_scope)
    }

    fn expression_source(&self, expression: Option<&'a Expression<'a>>, at: u32) -> SqlSource<'a> {
        expression.map_or(SqlSource::Unknown, |expression| SqlSource::Expression {
            expression,
            suffix: String::new(),
            scope: self.current_scope(),
            function_scope: self.current_function_scope(),
            at,
        })
    }

    fn source_with_suffix(source: &SqlSource<'a>, suffix: &str) -> SqlSource<'a> {
        match source {
            SqlSource::Unknown => SqlSource::Unknown,
            SqlSource::Path(path) => SqlSource::Path(format!("{path}.{suffix}")),
            SqlSource::Expression {
                expression,
                suffix: existing,
                scope,
                function_scope,
                at,
            } => {
                let suffix = if existing.is_empty() {
                    suffix.to_string()
                } else {
                    format!("{existing}.{suffix}")
                };
                SqlSource::Expression {
                    expression,
                    suffix,
                    scope: *scope,
                    function_scope: *function_scope,
                    at: *at,
                }
            }
        }
    }

    fn declare(
        &mut self,
        name: &'a str,
        scope: usize,
        start: u32,
        hoisted: bool,
        source: SqlSource<'a>,
    ) {
        if let Some(binding) = self
            .bindings
            .iter_mut()
            .find(|binding| binding.scope == scope && binding.name == name)
        {
            binding.start = binding.start.min(start);
            binding.hoisted |= hoisted;
            binding.states.push(SqlState {
                at: start,
                function_scope: self.scopes[scope].function_scope,
                kind: SqlStateKind::Declaration,
                source,
            });
            return;
        }
        self.bindings.push(SqlBinding {
            name,
            scope,
            start,
            hoisted,
            states: vec![SqlState {
                at: start,
                function_scope: self.scopes[scope].function_scope,
                kind: SqlStateKind::Declaration,
                source,
            }],
        });
    }

    fn declare_pattern(
        &mut self,
        pattern: &BindingPattern<'a>,
        scope: usize,
        source: SqlSource<'a>,
        start: u32,
        hoisted: bool,
    ) {
        self.declare_pattern_inner(pattern, scope, source, start, hoisted, false);
    }

    fn declare_pattern_inner(
        &mut self,
        pattern: &BindingPattern<'a>,
        scope: usize,
        source: SqlSource<'a>,
        start: u32,
        hoisted: bool,
        preserve_uninitialized_var: bool,
    ) {
        match pattern {
            BindingPattern::BindingIdentifier(identifier) => {
                let already_declared = self
                    .bindings
                    .iter()
                    .any(|binding| binding.scope == scope && binding.name == identifier.name);
                if !(preserve_uninitialized_var && already_declared) {
                    self.declare(
                        identifier.name.as_str(),
                        scope,
                        identifier.span.start.max(start),
                        hoisted,
                        source,
                    );
                }
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    let Some(key) = property_key_name(&property.key) else {
                        self.declare_pattern_inner(
                            &property.value,
                            scope,
                            SqlSource::Unknown,
                            start,
                            hoisted,
                            preserve_uninitialized_var,
                        );
                        continue;
                    };
                    self.declare_pattern_inner(
                        &property.value,
                        scope,
                        Self::source_with_suffix(&source, key),
                        start,
                        hoisted,
                        preserve_uninitialized_var,
                    );
                }
                if let Some(rest) = &object.rest {
                    self.declare_pattern_inner(
                        &rest.argument,
                        scope,
                        SqlSource::Unknown,
                        start,
                        hoisted,
                        preserve_uninitialized_var,
                    );
                }
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    self.declare_pattern_inner(
                        element,
                        scope,
                        SqlSource::Unknown,
                        start,
                        hoisted,
                        preserve_uninitialized_var,
                    );
                }
                if let Some(rest) = &array.rest {
                    self.declare_pattern_inner(
                        &rest.argument,
                        scope,
                        SqlSource::Unknown,
                        start,
                        hoisted,
                        preserve_uninitialized_var,
                    );
                }
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.declare_pattern_inner(
                    &assignment.left,
                    scope,
                    source,
                    start,
                    hoisted,
                    preserve_uninitialized_var,
                );
            }
        }
    }
    fn precollect_imports(&mut self, program: &Program<'a>) {
        let root = self.current_scope();
        for statement in &program.body {
            self.precollect_import_statement(root, statement);
        }
    }

    fn precollect_import_statement(&mut self, root: usize, statement: &Statement<'a>) {
        if let Some(Declaration::TSImportEqualsDeclaration(declaration)) =
            statement.as_declaration()
            && declaration.import_kind == ImportOrExportKind::Value
        {
            if let TSModuleReference::ExternalModuleReference(reference) =
                &declaration.module_reference
            {
                self.declare(
                    declaration.id.name.as_str(),
                    root,
                    0,
                    true,
                    SqlSource::Path(reference.expression.value.to_string()),
                );
            }
            return;
        }
        let Statement::ImportDeclaration(declaration) = statement else {
            return;
        };
        if declaration.import_kind == ImportOrExportKind::Type {
            return;
        }
        let module = declaration.source.value.as_str();
        let Some(specifiers) = &declaration.specifiers else {
            return;
        };
        for specifier in specifiers {
            self.precollect_import_specifier(root, module, specifier);
        }
    }

    fn precollect_import_specifier(
        &mut self,
        root: usize,
        module: &str,
        specifier: &ImportDeclarationSpecifier<'a>,
    ) {
        match specifier {
            ImportDeclarationSpecifier::ImportSpecifier(specifier) => {
                if specifier.import_kind == ImportOrExportKind::Type {
                    return;
                }
                let Some(imported) = module_export_name_name(&specifier.imported) else {
                    return;
                };
                let path = if imported == "default" {
                    module.to_string()
                } else {
                    format!("{module}.{imported}")
                };
                self.declare(
                    specifier.local.name.as_str(),
                    root,
                    0,
                    true,
                    SqlSource::Path(path),
                );
            }
            ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
                self.declare(
                    specifier.local.name.as_str(),
                    root,
                    0,
                    true,
                    SqlSource::Path(module.to_string()),
                );
            }
            ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
                self.declare(
                    specifier.local.name.as_str(),
                    root,
                    0,
                    true,
                    SqlSource::Path(module.to_string()),
                );
            }
        }
    }

    fn nearest_binding(&self, scope: usize, name: &str, at: u32) -> Option<usize> {
        let mut selected: Option<usize> = None;
        for (index, binding) in self.bindings.iter().enumerate() {
            if binding.scope != scope || binding.name != name {
                continue;
            }
            if binding.start <= at
                && selected.is_none_or(|current| self.bindings[current].start < binding.start)
            {
                selected = Some(index);
            }
        }
        selected
    }

    fn resolve_binding(&self, mut scope: usize, name: &str, at: u32) -> Option<usize> {
        loop {
            if let Some(selected) = self.nearest_binding(scope, name, at) {
                return Some(selected);
            }
            let fallback = self
                .bindings
                .iter()
                .enumerate()
                .filter(|(_, binding)| binding.scope == scope && binding.name == name)
                .min_by_key(|(_, binding)| (binding.start, !binding.hoisted))
                .map(|(index, _)| index);
            if fallback.is_some() {
                return fallback;
            }
            let parent = self.scopes[scope].parent?;
            scope = parent;
        }
    }

    fn binding_path(
        &self,
        binding_id: usize,
        at: u32,
        function_scope: usize,
        active: &mut BTreeSet<usize>,
    ) -> Option<String> {
        if !active.insert(binding_id) {
            return None;
        }
        let source = self.bindings[binding_id]
            .states
            .iter()
            .filter(|state| {
                state.at <= at
                    && (state.kind == SqlStateKind::Declaration
                        || state.function_scope == function_scope)
            })
            .max_by_key(|state| state.at)
            .map(|state| state.source.clone());
        let result = match source {
            Some(SqlSource::Path(path)) => Some(path),
            Some(SqlSource::Expression {
                expression,
                suffix,
                scope,
                function_scope,
                at,
            }) => self
                .resolve_path(expression, scope, at, function_scope)
                .map(|path| {
                    if suffix.is_empty() {
                        path
                    } else {
                        format!("{path}.{suffix}")
                    }
                }),
            Some(SqlSource::Unknown) | None => None,
        };
        active.remove(&binding_id);
        result
    }

    fn resolve_path(
        &self,
        expression: &Expression<'a>,
        scope: usize,
        at: u32,
        function_scope: usize,
    ) -> Option<String> {
        self.resolve_path_active(expression, scope, at, function_scope, &mut BTreeSet::new())
    }

    fn resolve_path_active(
        &self,
        expression: &Expression<'a>,
        scope: usize,
        at: u32,
        function_scope: usize,
        active: &mut BTreeSet<usize>,
    ) -> Option<String> {
        match unparenthesized(expression) {
            Expression::Identifier(identifier) => {
                let binding = self.resolve_binding(scope, identifier.name.as_str(), at)?;
                self.binding_path(binding, at, function_scope, active)
            }
            Expression::StaticMemberExpression(member) => self
                .resolve_path_active(&member.object, scope, at, function_scope, active)
                .map(|path| format!("{path}.{}", member.property.name)),
            Expression::ComputedMemberExpression(member) => {
                let Expression::StringLiteral(property) = unparenthesized(&member.expression)
                else {
                    return None;
                };
                self.resolve_path_active(&member.object, scope, at, function_scope, active)
                    .map(|path| format!("{path}.{}", property.value.as_str()))
            }
            Expression::CallExpression(call) => {
                if identifier_name(&call.callee) == Some("require")
                    && self.resolve_binding(scope, "require", at).is_none()
                {
                    let argument = call.arguments.first()?.as_expression()?;
                    if let Expression::StringLiteral(module) = unparenthesized(argument) {
                        return Some(module.value.to_string());
                    }
                    return None;
                }
                self.resolve_path_active(&call.callee, scope, at, function_scope, active)
            }
            Expression::NewExpression(new_expression) => {
                self.resolve_path_active(&new_expression.callee, scope, at, function_scope, active)
            }
            _ => None,
        }
    }

    fn materialize_writes(&mut self) {
        let writes = std::mem::take(&mut self.writes);
        for write in writes {
            let Some(binding_id) = self.resolve_binding(write.scope, write.name, write.at) else {
                continue;
            };
            self.bindings[binding_id].states.push(SqlState {
                at: write.at,
                function_scope: write.function_scope,
                kind: SqlStateKind::Write,
                source: write.source,
            });
        }
    }

    fn record_simple_assignment(
        &mut self,
        target: &oxc_ast::ast::AssignmentTarget<'a>,
        at: u32,
        source: SqlSource<'a>,
    ) {
        if let Some(SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier)) =
            target.as_simple_assignment_target()
        {
            self.writes.push(SqlWrite {
                name: identifier.name.as_str(),
                scope: self.current_scope(),
                function_scope: self.current_function_scope(),
                at,
                source,
            });
        }
    }

    fn record_loop_target(&mut self, left: &ForStatementLeft<'a>, at: u32) {
        match left {
            ForStatementLeft::VariableDeclaration(declaration) => {
                for declarator in &declaration.declarations {
                    for name in bound_names(&declarator.id) {
                        self.writes.push(SqlWrite {
                            name,
                            scope: self.current_scope(),
                            function_scope: self.current_function_scope(),
                            at,
                            source: SqlSource::Unknown,
                        });
                    }
                }
            }
            left => {
                if let Some(target) = left.as_assignment_target() {
                    self.record_simple_assignment(target, at, SqlSource::Unknown);
                }
            }
        }
    }
}

fn is_dynamic_sql(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::TemplateLiteral(template) => !template.expressions.is_empty(),
        Expression::BinaryExpression(binary)
            if binary.operator == oxc_ast::ast::BinaryOperator::Addition =>
        {
            sql_operand_is_untrusted(&binary.left) || sql_operand_is_untrusted(&binary.right)
        }
        _ => false,
    }
}

fn sql_operand_is_untrusted(expression: &Expression<'_>) -> bool {
    !matches!(
        unparenthesized(expression),
        Expression::StringLiteral(_) | Expression::NumericLiteral(_)
    )
}

impl<'a> Visit<'a> for SqlInjectionCollector<'a> {
    fn visit_program(&mut self, program: &Program<'a>) {
        self.push_program_scope();
        self.precollect_imports(program);
        walk_program(self, program);
        self.pop_scope();
    }

    fn visit_import_declaration(&mut self, _declaration: &ImportDeclaration<'a>) {}

    fn visit_declaration(&mut self, declaration: &Declaration<'a>) {
        match declaration {
            Declaration::FunctionDeclaration(function) => {
                if let Some(identifier) = &function.id {
                    self.declare(
                        identifier.name.as_str(),
                        self.current_scope(),
                        function.span.start,
                        true,
                        SqlSource::Unknown,
                    );
                }
            }
            Declaration::ClassDeclaration(class) => {
                if let Some(identifier) = &class.id {
                    self.declare(
                        identifier.name.as_str(),
                        self.current_scope(),
                        class.span.start,
                        false,
                        SqlSource::Unknown,
                    );
                }
            }
            _ => {}
        }
        walk_declaration(self, declaration);
    }

    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'a>) {
        let is_var = declaration.kind == VariableDeclarationKind::Var;
        let target_scope = if is_var {
            self.current_function_scope()
        } else {
            self.current_scope()
        };
        for declarator in &declaration.declarations {
            let source = self.expression_source(
                declarator.init.as_ref().map(|init| self.alloc(init)),
                declarator.span.start,
            );
            if is_var && declarator.init.is_none() {
                self.declare_pattern_inner(
                    &declarator.id,
                    target_scope,
                    source,
                    declarator.span.start,
                    true,
                    true,
                );
            } else {
                self.declare_pattern(
                    &declarator.id,
                    target_scope,
                    source,
                    declarator.span.start,
                    is_var,
                );
            }
        }
        walk_variable_declaration(self, declaration);
    }

    fn visit_assignment_expression(&mut self, expression: &AssignmentExpression<'a>) {
        let source = if expression.operator == AssignmentOperator::Assign {
            self.expression_source(Some(self.alloc(&expression.right)), expression.span.start)
        } else {
            SqlSource::Unknown
        };
        self.record_simple_assignment(&expression.left, expression.span.start, source);
        walk_assignment_expression(self, expression);
    }

    fn visit_update_expression(&mut self, expression: &UpdateExpression<'a>) {
        if let SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) = &expression.argument
        {
            self.writes.push(SqlWrite {
                name: identifier.name.as_str(),
                scope: self.current_scope(),
                function_scope: self.current_function_scope(),
                at: expression.span.start,
                source: SqlSource::Unknown,
            });
        }
        walk_update_expression(self, expression);
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        let function_scope = self.push_scope(true);
        if let Some(identifier) = &function.id {
            self.declare(
                identifier.name.as_str(),
                function_scope,
                identifier.span.start,
                true,
                SqlSource::Unknown,
            );
        }
        for parameter in &function.params.items {
            self.declare_pattern(
                &parameter.pattern,
                function_scope,
                SqlSource::Unknown,
                parameter.span.start,
                true,
            );
        }
        if let Some(rest) = &function.params.rest {
            self.declare_pattern(
                &rest.rest.argument,
                function_scope,
                SqlSource::Unknown,
                rest.span.start,
                true,
            );
        }
        walk_function(self, function, flags);
        self.pop_scope();
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        let function_scope = self.push_scope(true);
        for parameter in &arrow.params.items {
            self.declare_pattern(
                &parameter.pattern,
                function_scope,
                SqlSource::Unknown,
                parameter.span.start,
                true,
            );
        }
        if let Some(rest) = &arrow.params.rest {
            self.declare_pattern(
                &rest.rest.argument,
                function_scope,
                SqlSource::Unknown,
                rest.span.start,
                true,
            );
        }
        walk_arrow_function_expression(self, arrow);
        self.pop_scope();
    }

    fn visit_block_statement(&mut self, block: &BlockStatement<'a>) {
        self.push_scope(false);
        walk_block_statement(self, block);
        self.pop_scope();
    }

    fn visit_catch_clause(&mut self, clause: &oxc_ast::ast::CatchClause<'a>) {
        let catch_scope = self.push_scope(false);
        if let Some(parameter) = &clause.param {
            self.declare_pattern(
                &parameter.pattern,
                catch_scope,
                SqlSource::Unknown,
                parameter.span.start,
                true,
            );
        }
        walk_catch_clause(self, clause);
        self.pop_scope();
    }

    fn visit_for_statement(&mut self, statement: &ForStatement<'a>) {
        self.push_scope(false);
        walk_for_statement(self, statement);
        self.pop_scope();
    }

    fn visit_for_in_statement(&mut self, statement: &ForInStatement<'a>) {
        self.push_scope(false);
        self.record_loop_target(&statement.left, statement.body.span().start);
        walk_for_in_statement(self, statement);
        self.pop_scope();
    }

    fn visit_for_of_statement(&mut self, statement: &ForOfStatement<'a>) {
        self.push_scope(false);
        self.record_loop_target(&statement.left, statement.body.span().start);
        walk_for_of_statement(self, statement);
        self.pop_scope();
    }

    fn visit_switch_statement(&mut self, statement: &SwitchStatement<'a>) {
        self.push_scope(false);
        walk_switch_statement(self, statement);
        self.pop_scope();
    }

    fn visit_static_block(&mut self, block: &StaticBlock<'a>) {
        self.push_scope(false);
        walk_static_block(self, block);
        self.pop_scope();
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.calls.push(SqlCall {
            call: self.alloc(call),
            scope: self.current_scope(),
            function_scope: self.current_function_scope(),
        });
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn sql_sinks_require_known_api_identity() {
        let flagged = js("import pg from 'pg';\n\
             function run(name, column) {\n\
                 const client = new pg.Client();\n\
                 client.query(`SELECT * FROM users WHERE name = ${name}`);\n\
                 pg.Client.query('SELECT ' + column);\n\
             }\n");
        assert_eq!(filtered(&flagged, "S2077").len(), 2);

        let custom = js("const renderer = { query(text) { return text; } };\n\
             function render(input) { return renderer.query('label: ' + input); }\n\
             child_process.exec('echo ' + input);\n\
             function query(text) { return text; }\n\
             query('SELECT ' + input);\n");
        assert_eq!(filtered(&custom, "S2077").len(), 0);

        let parameterized = js("import { Client as PgClient } from 'pg';\n\
             function run(client, input) {\n\
                 client.query('SELECT * FROM records WHERE value = $1', [input]);\n\
             }\n\
             const client = new PgClient();\n\
             client.query('SELECT * FROM records WHERE value = $1', [input]);\n");
        assert_eq!(filtered(&parameterized, "S2077").len(), 0);
        let import_equals = ts("import pg = require('pg');\n\
             pg.Client.query('SELECT ' + input);\n");
        assert_eq!(filtered(&import_equals, "S2077").len(), 1);
    }

    #[test]
    fn sql_identity_respects_lexical_bindings_and_source_positions() {
        let source = js("import pg from 'pg';\n\
             pg.Client.query('SELECT ' + top);\n\
             function shadow(pg) { pg.Client.query('SELECT ' + local); }\n\
             function catch_shadow() { try { throw 1; } catch (pg) { pg.Client.query('SELECT ' + local); } }\n\
             { const pg = {}; pg.Client.query('SELECT ' + block); }\n\
             const pg2 = pg;\n\
             pg2.Client.query('SELECT ' + alias);\n");
        assert_eq!(filtered(&source, "S2077").len(), 2);

        let require_chain = js("const Client = require('pg').Client;\n\
             const db = new Client();\n\
             db.query('SELECT ' + value);\n\
             const mysql = require('mysql');\n\
             const connection = mysql.createConnection({});\n\
             connection.query('SELECT ' + value);\n");
        assert_eq!(filtered(&require_chain, "S2077").len(), 2);

        let factories = js("import knex from 'knex';\n\
             import pgPromise from 'pg-promise';\n\
             import { getConnection } from 'typeorm';\n\
             const db = knex({}).raw('SELECT ' + value);\n\
             const pgdb = pgPromise();\n\
             pgdb.any('SELECT ' + value);\n\
             const connection = getConnection();\n\
             connection.query('SELECT ' + value);\n");
        assert_eq!(filtered(&factories, "S2077").len(), 3);
    }

    #[test]
    fn shadowed_require_reassignment_and_loop_scopes_stay_unknown() {
        let source = js("function local(require) {\n\
                 const pg = require('pg');\n\
                 pg.Client.query('SELECT ' + value);\n\
             }\n\
             const pg = require('pg');\n\
             let db = new pg.Client();\n\
             db = {};\n\
             db.query('SELECT ' + value);\n\
             for (let db of values) { db.query('SELECT ' + value); }\n\
             db.query('SELECT ' + value);\n");
        assert_eq!(filtered(&source, "S2077").len(), 0);
        let late_import = js("pg.Client.query('SELECT ' + value);\n\
             import pg from 'pg';\n");
        assert_eq!(filtered(&late_import, "S2077").len(), 1);

        let loop_shadow = js("import pg from 'pg';\n\
             for (let pg of values) { pg.Client.query('SELECT ' + inner); }\n\
             pg.Client.query('SELECT ' + outer);\n");
        assert_eq!(filtered(&loop_shadow, "S2077").len(), 1);

        let var_loop = js("import pg from 'pg';\n\
             var db = new pg.Client();\n\
             for (var db of values) {}\n\
             db.query('SELECT ' + value);\n");
        assert_eq!(filtered(&var_loop, "S2077").len(), 0);
        let var_redeclaration = js("import pg from 'pg';\n\
             var db = new pg.Client();\n\
             var db;\n\
             db.query('SELECT ' + value);\n");
        assert_eq!(filtered(&var_redeclaration, "S2077").len(), 1);

        let first_var_shadow = js("import pg from 'pg';\n\
             function local() {\n\
                 var pg;\n\
                 pg.Client.query('SELECT ' + inner);\n\
             }\n\
             pg.Client.query('SELECT ' + outer);\n");
        assert_eq!(filtered(&first_var_shadow, "S2077").len(), 1);
    }
}
