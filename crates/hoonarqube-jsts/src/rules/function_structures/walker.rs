// Family walker for 'function_structures' (generated).
use super::s2376_class_getter_pairing::check_class_getter_pairing;
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{
    IssueSink, LineIndex, RuleScope, identifier_name, property_key_name, span_text_contains,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, AssignmentOperator, BlockStatement, Class,
    Declaration, DoWhileStatement, Expression, ForStatement, Function, FunctionBody, IfStatement,
    LabeledStatement, MethodDefinition, ObjectExpression, ObjectPropertyKind, PropertyKind,
    Statement, StaticBlock, SwitchCase, TryStatement, UnaryExpression, UnaryOperator,
    WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_class, walk_declaration,
    walk_expression, walk_labeled_statement, walk_method_definition, walk_object_expression,
    walk_static_block, walk_unary_expression,
};
use oxc_span::{GetSpan, Span};

pub(crate) fn check_function_structures(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = FunctionStructureCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        next_block_is_bare: false,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S3001`, `S3525`, `S3531`, `S3626`, and `S2376` in one traversal.
pub(crate) struct FunctionStructureCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) source: &'a str,
    /// Set while visiting a block that sits directly in a statement list
    /// (`S3626` bare-block case).
    pub(crate) next_block_is_bare: bool,
}

impl<'a> FunctionStructureCollector<'a, '_> {
    /// Enters a function-like node: checks its generator body (`S3531`) and
    /// resets bare-block tracking for the subtree.
    pub(crate) fn enter_function(
        &mut self,
        function: &Function<'_>,
        walk_children: impl FnOnce(&mut Self),
    ) {
        if function.generator {
            let mut scanner = YieldScanner::default();
            if let Some(body) = &function.body {
                scanner.visit_function_body(body);
            }
            if !scanner.found {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3531",
                    "Add a \"yield\" statement to this generator.",
                    function.span(),
                );
            }
        }
        let saved_bare = self.next_block_is_bare;
        self.next_block_is_bare = false;
        walk_children(self);
        self.next_block_is_bare = saved_bare;
    }

    /// Flags the last statement of a statement list when it is an
    /// unconditional jump (`S3626`).
    pub(crate) fn flag_trailing_jump(&mut self, statements: &[Statement<'_>]) {
        let Some(last) = statements.last() else {
            return;
        };
        if matches!(
            last,
            Statement::BreakStatement(_)
                | Statement::ContinueStatement(_)
                | Statement::ReturnStatement(_)
                | Statement::ThrowStatement(_)
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3626",
                "Remove this redundant jump statement.",
                last.span(),
            );
        }
    }

    /// Walks a loop body: trailing-jump check plus non-bare traversal of its
    /// block statements.
    pub(crate) fn visit_loop_body(&mut self, body: &Statement<'a>) {
        if let Statement::BlockStatement(block) = body {
            self.flag_trailing_jump(&block.body);
            for statement in &block.body {
                self.next_block_is_bare = true;
                self.visit_statement(statement);
            }
        } else {
            self.next_block_is_bare = false;
            self.visit_statement(body);
        }
    }
}

impl<'a> Visit<'a> for FunctionStructureCollector<'a, '_> {
    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        // `S3001`: `delete x` on a plain identifier.
        if it.operator == UnaryOperator::Delete && identifier_name(&it.argument).is_some() {
            self.sink.emit_span(
                RuleScope::Both,
                "S3001",
                "Remove this delete of a plain identifier.",
                it.argument.span(),
            );
        }
        walk_unary_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        // `S3525`: `X.prototype.member = function ...`.
        if it.operator == AssignmentOperator::Assign
            && span_text_contains(self.source, it.left.span(), ".prototype.")
            && matches!(
                it.right,
                Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
            )
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3525",
                "Assign methods directly instead of adding them to a prototype.",
                it.left.span(),
            );
        }
        walk_assignment_expression(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            self.enter_function(function, |collector| {
                walk_expression(collector, it);
            });
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        // Arrows cannot be generators; only reset bare-block tracking.
        let saved_bare = self.next_block_is_bare;
        self.next_block_is_bare = false;
        walk_arrow_function_expression(self, it);
        self.next_block_is_bare = saved_bare;
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        let saved_bare = self.next_block_is_bare;
        self.next_block_is_bare = false;
        walk_static_block(self, it);
        self.next_block_is_bare = saved_bare;
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            self.enter_function(function, |collector| {
                walk_declaration(collector, it);
            });
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.enter_function(&it.value, |collector| {
            walk_method_definition(collector, it);
        });
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        check_class_getter_pairing(&mut self.sink, &it.body.body);
        walk_class(self, it);
    }

    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        // `S2376` over object-literal accessors.
        let getters: Vec<(Option<&str>, Span)> = it
            .properties
            .iter()
            .filter_map(|property| match property {
                ObjectPropertyKind::ObjectProperty(inner) if inner.kind == PropertyKind::Get => {
                    Some((property_key_name(&inner.key), inner.key.span()))
                }
                _ => None,
            })
            .collect();
        let setters: Vec<Option<&str>> = it
            .properties
            .iter()
            .filter_map(|property| match property {
                ObjectPropertyKind::ObjectProperty(inner) if inner.kind == PropertyKind::Set => {
                    Some(property_key_name(&inner.key))
                }
                _ => None,
            })
            .collect();
        for (name, span) in getters {
            if !setters.contains(&name) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S2376",
                    "Add a setter matching this getter.",
                    span,
                );
            }
        }
        walk_object_expression(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        for statement in &it.statements {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
    }
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        for statement in &it.body {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        if self.next_block_is_bare {
            self.flag_trailing_jump(&it.body);
        }
        for statement in &it.body {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
    }

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        self.next_block_is_bare = false;
        walk_labeled_statement(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.visit_expression(&it.test);
        self.next_block_is_bare = false;
        self.visit_statement(&it.consequent);
        if let Some(alternate) = &it.alternate {
            self.next_block_is_bare = false;
            self.visit_statement(alternate);
        }
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(init) = &it.init {
            self.visit_for_statement_init(init);
        }
        if let Some(test) = &it.test {
            self.visit_expression(test);
        }
        if let Some(update) = &it.update {
            self.visit_expression(update);
        }
        self.visit_loop_body(&it.body);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.visit_expression(&it.test);
        self.visit_loop_body(&it.body);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.visit_loop_body(&it.body);
        self.visit_expression(&it.test);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        // Case bodies end conventionally with `break`; not an `S3626` case.
        for statement in &it.consequent {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        self.flag_trailing_jump(&it.block.body);
        for statement in &it.block.body {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
        if let Some(handler) = &it.handler {
            self.flag_trailing_jump(&handler.body.body);
            for statement in &handler.body.body {
                self.next_block_is_bare = true;
                self.visit_statement(statement);
            }
        }
        if let Some(finalizer) = &it.finalizer {
            self.flag_trailing_jump(&finalizer.body);
            for statement in &finalizer.body {
                self.next_block_is_bare = true;
                self.visit_statement(statement);
            }
        }
    }
}

/// Finds `yield` expressions outside nested functions; used for `S3531`.
#[derive(Default)]
pub(crate) struct YieldScanner {
    pub(crate) found: bool,
}

impl<'a> Visit<'a> for YieldScanner {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if matches!(it, Expression::YieldExpression(_)) {
            self.found = true;
        }
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, _it: &MethodDefinition<'a>) {}

    fn visit_static_block(&mut self, _it: &StaticBlock<'a>) {}
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_function_structures(ctx.program, ctx.source, ctx.index, ctx.language)
}
