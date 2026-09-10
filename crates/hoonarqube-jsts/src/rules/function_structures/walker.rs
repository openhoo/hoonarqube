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

fn check_function_structures(
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
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S3001`, `S3525`, `S3531`, `S3626`, and `S2376` in one traversal.
struct FunctionStructureCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
}

impl<'a> FunctionStructureCollector<'a, '_> {
    /// Enters a function-like node and checks its generator body (`S3531`).
    fn enter_function(&mut self, function: &Function<'_>, walk_children: impl FnOnce(&mut Self)) {
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
        walk_children(self);
    }

    fn is_redundant_jump(statement: &Statement<'_>, continue_jump: bool) -> bool {
        match statement {
            Statement::ContinueStatement(continue_statement) if continue_jump => {
                continue_statement.label.is_none()
            }
            Statement::ReturnStatement(return_statement) if !continue_jump => {
                return_statement.argument.is_none()
            }
            _ => false,
        }
    }

    fn flag_trailing_jump(&mut self, statements: &[Statement<'_>], continue_jump: bool) {
        if statements.len() <= 1 {
            return;
        }
        let Some(last) = statements.last() else {
            return;
        };
        if Self::is_redundant_jump(last, continue_jump) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3626",
                "Remove this redundant jump.",
                last.span(),
            );
        }
    }

    fn flag_trailing_if_jump(&mut self, statements: &[Statement<'_>], continue_jump: bool) {
        let Some(Statement::IfStatement(if_statement)) = statements.last() else {
            return;
        };
        let branch_spans = [
            &if_statement.consequent,
            if_statement
                .alternate
                .as_ref()
                .unwrap_or(&if_statement.consequent),
        ]
        .into_iter()
        .enumerate()
        .filter_map(|(index, branch)| {
            if index == 1 && if_statement.alternate.is_none() {
                return None;
            }
            let Statement::BlockStatement(block) = branch else {
                return None;
            };
            (block.body.len() > 1)
                .then(|| block.body.last())
                .flatten()
                .filter(|statement| Self::is_redundant_jump(statement, continue_jump))
                .map(GetSpan::span)
        })
        .collect::<Vec<_>>();
        for span in branch_spans {
            self.sink.emit_span(
                RuleScope::Both,
                "S3626",
                "Remove this redundant jump.",
                span,
            );
        }
    }

    fn flag_function_tail(&mut self, statements: &[Statement<'_>]) {
        self.flag_trailing_jump(statements, false);
        self.flag_trailing_if_jump(statements, false);
    }

    fn flag_loop_tail(&mut self, statements: &[Statement<'_>]) {
        self.flag_trailing_jump(statements, true);
        self.flag_trailing_if_jump(statements, true);
    }

    /// Walks a loop body and applies the loop-specific trailing-jump checks.
    fn visit_loop_body(&mut self, body: &Statement<'a>) {
        if let Statement::BlockStatement(block) = body {
            self.flag_loop_tail(&block.body);
            for statement in &block.body {
                self.visit_statement(statement);
            }
        } else {
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
            let target = crate::support::source_slice(self.source, it.left.span());
            let (owner, member) = target
                .split_once(".prototype.")
                .unwrap_or(("Type", "method"));
            self.sink.emit_span(
                RuleScope::Both,
                "S3525",
                &format!(
                    "Declare a \"{owner}\" class and move this declaration of \"{member}\" into it."
                ),
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
        walk_arrow_function_expression(self, it);
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        walk_static_block(self, it);
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
        self.flag_function_tail(&it.statements);
        for statement in &it.statements {
            self.visit_statement(statement);
        }
    }
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        for statement in &it.body {
            self.visit_statement(statement);
        }
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        for statement in &it.body {
            self.visit_statement(statement);
        }
    }

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        walk_labeled_statement(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.visit_expression(&it.test);
        self.visit_statement(&it.consequent);
        if let Some(alternate) = &it.alternate {
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
        for statement in &it.consequent {
            self.visit_statement(statement);
        }
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        for statement in &it.block.body {
            self.visit_statement(statement);
        }
        if let Some(handler) = &it.handler {
            for statement in &handler.body.body {
                self.visit_statement(statement);
            }
        }
        if let Some(finalizer) = &it.finalizer {
            for statement in &finalizer.body {
                self.visit_statement(statement);
            }
        }
    }
}

/// Finds `yield` expressions outside nested functions; used for `S3531`.
#[derive(Default)]
struct YieldScanner {
    found: bool,
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
    fn trailing_jumps_match_upstream_redundant_positions() {
        let loop_break = js_keys("while (a) {\n  break;\n}\n");
        assert_eq!(count_key(&loop_break, "javascript:S3626"), 0);

        let bare_block = js_keys("function f() {\n  {\n    return 1;\n  }\n}\n");
        assert_eq!(count_key(&bare_block, "javascript:S3626"), 0);

        // Function bodies and case bodies end with jumps conventionally.
        let conventional = js_keys("switch (x) {\n  case 1:\n    break;\n}\n");
        assert_eq!(count_key(&conventional, "javascript:S3626"), 0);
        let fn_tail = js_keys("function f() {\n  return 1;\n}\n");
        assert_eq!(count_key(&fn_tail, "javascript:S3626"), 0);

        let bare_return = js_keys("function f() {\n  work();\n  return;\n}\n");
        assert_eq!(count_key(&bare_return, "javascript:S3626"), 1);
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
    fn s3626_flags_only_unlabelled_continue_in_loop_bodies() {
        let try_tail = js_keys(
            "function f() {\n  try {\n    a();\n    return 1;\n  } finally {\n    b();\n  }\n}\n",
        );
        assert_eq!(count_key(&try_tail, "javascript:S3626"), 0);

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
            0
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
