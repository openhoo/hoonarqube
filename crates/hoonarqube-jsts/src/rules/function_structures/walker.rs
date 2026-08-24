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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn delete_prototype_and_generator_rules_flag_expected_shapes() {
        let delete_plain = js_keys("delete variable;\n");
        assert_eq!(count_key(&delete_plain, "javascript:S3001"), 1);
        let delete_member = js_keys("delete obj.field;\n");
        assert_eq!(count_key(&delete_member, "javascript:S3001"), 0);

        let prototype_assignment = js_keys("Type.prototype.method = function () {};\n");
        assert_eq!(count_key(&prototype_assignment, "javascript:S3525"), 1);
        let plain_assignment = js_keys("obj.handler = function () {};\n");
        assert_eq!(count_key(&plain_assignment, "javascript:S3525"), 0);

        let empty_generator = js_keys("function* generate() {}\n");
        assert_eq!(count_key(&empty_generator, "javascript:S3531"), 1);
        let yielding_generator = js_keys("function* generate() {\n  yield 1;\n}\n");
        assert_eq!(count_key(&yielding_generator, "javascript:S3531"), 0);
        // A yield inside a nested generator belongs to that nested function.
        let nested_yield_only =
            js_keys("function* outer() {\n  function* inner() {\n    yield 1;\n  }\n}\n");
        assert_eq!(count_key(&nested_yield_only, "javascript:S3531"), 1);
    }

    #[test]
    fn trailing_jumps_flagged_only_in_redundant_positions() {
        let loop_break = js_keys("while (a) {\n  break;\n}\n");
        assert_eq!(count_key(&loop_break, "javascript:S3626"), 1);

        let bare_block = js("function f() {\n  {\n    return 1;\n  }\n}\n");
        let s3626_lines: Vec<u32> = bare_block
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S3626"))
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(s3626_lines, vec![3]);

        // Function bodies and case bodies end with jumps conventionally.
        let conventional = js_keys("switch (x) {\n  case 1:\n    break;\n}\n");
        assert_eq!(count_key(&conventional, "javascript:S3626"), 0);
        let fn_tail = js_keys("function f() {\n  return 1;\n}\n");
        assert_eq!(count_key(&fn_tail, "javascript:S3626"), 0);
    }

    #[test]
    fn s2376_flags_unpaired_getters_on_classes_and_objects() {
        assert_eq!(
            count_key(
                &js_keys(
                    "class A {\n  get a() {\n    return 1;\n  }\n  get b() {\n    return 2;\n  }\n}\n"
                ),
                "javascript:S2376"
            ),
            2
        );
        assert_eq!(
            count_key(
                &js_keys("const o = {\n  get n() {\n    return 1;\n  },\n  set n(v) {},\n};\n"),
                "javascript:S2376"
            ),
            0
        );
    }

    #[test]
    fn s3626_flags_trailing_jumps_in_try_and_loop_bodies() {
        let try_tail = js_keys(
            "function f() {\n  try {\n    a();\n    return 1;\n  } finally {\n    b();\n  }\n}\n",
        );
        assert_eq!(count_key(&try_tail, "javascript:S3626"), 1);

        assert_eq!(
            count_key(
                &js_keys("do {\n  f();\n  continue;\n} while (a);\n"),
                "javascript:S3626"
            ),
            1
        );
        assert_eq!(
            count_key(
                &js_keys("function f() {\n  for (;;) {\n    g();\n    return 1;\n  }\n}\n"),
                "javascript:S3626"
            ),
            1
        );
    }

    #[test]
    fn s3626_spares_if_branches_and_labeled_blocks() {
        assert_eq!(
            count_key(
                &js_keys("function f(a) {\n  if (a) {\n    return 1;\n  }\n  return 0;\n}\n"),
                "javascript:S3626"
            ),
            0
        );
        assert_eq!(
            count_key(
                &js_keys("function f() {\n  blk: {\n    break blk;\n  }\n}\n"),
                "javascript:S3626"
            ),
            0
        );
    }

    #[test]
    fn s3525_and_s3531_check_arrow_right_sides_and_generator_methods() {
        assert_eq!(
            count_key(
                &js_keys("Type.prototype.method = () => {};\n"),
                "javascript:S3525"
            ),
            1
        );
        assert_eq!(
            count_key(&js_keys("Type.prototype.count = 1;\n"), "javascript:S3525"),
            0
        );
        assert_eq!(
            count_key(&js_keys("class A {\n  *gen() {}\n}\n"), "javascript:S3531"),
            1
        );
        assert_eq!(
            count_key(
                &js_keys("class A {\n  *gen() {\n    yield 1;\n  }\n}\n"),
                "javascript:S3531"
            ),
            0
        );
    }
}
