// Family walker for 'embedded_effects' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{Expression, ExpressionStatement, ForStatement, UnaryOperator, UpdateOperator};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_expression, walk_expression_statement};
use oxc_span::GetSpan;

pub(crate) fn check_embedded_effects(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = EmbeddedEffectCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        expr_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S881` (standalone `++`/`--`), `S1121` (standalone assignments), and
/// `S905` (pointless expression statements) in one traversal.
///
/// Updates and assignments are only tolerated as the direct root expression
/// of an `ExpressionStatement` or in a `for` header init/update slot; the
/// `expr_depth` counter distinguishes those roots from deeper embedding.
pub(crate) struct EmbeddedEffectCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Distance of the current expression below its statement root: `1` for
    /// the root itself, increasing per nesting level, `0` outside
    /// statement-root contexts (initializers, conditions, arguments, ...).
    pub(crate) expr_depth: u32,
}

impl<'a> Visit<'a> for EmbeddedEffectCollector<'_> {
    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        if is_pointless_expression(&it.expression) {
            self.sink.emit_span(
                RuleScope::Both,
                "S905",
                "Remove this expression; it has no effect.",
                it.expression.span(),
            );
        }
        let saved = self.expr_depth;
        self.expr_depth = 1;
        walk_expression_statement(self, it);
        self.expr_depth = saved;
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(init) = &it.init {
            // Only the expression form of the init slot is an embedded
            // statement root; `for (let i = ...)` declarations walk with
            // their own (non-root) initializer context.
            if init.as_expression().is_some() {
                let saved = self.expr_depth;
                self.expr_depth = 1;
                self.visit_for_statement_init(init);
                self.expr_depth = saved;
            } else {
                self.visit_for_statement_init(init);
            }
        }
        if let Some(test) = &it.test {
            self.visit_expression(test);
        }
        if let Some(update) = &it.update {
            let saved = self.expr_depth;
            self.expr_depth = 1;
            self.visit_expression(update);
            self.expr_depth = saved;
        }
        self.visit_statement(&it.body);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        match it {
            Expression::UpdateExpression(update) => {
                if self.expr_depth != 1 {
                    let operator = match update.operator {
                        UpdateOperator::Increment => "++",
                        UpdateOperator::Decrement => "--",
                    };
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S881",
                        &format!("Remove this use of the operator '{operator}'."),
                        update.span(),
                    );
                }
            }
            Expression::AssignmentExpression(assign) if self.expr_depth != 1 => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1121",
                    "Extract this assignment out of this expression.",
                    assign.span(),
                );
            }
            _ => {}
        }
        if self.expr_depth > 0 {
            self.expr_depth += 1;
            walk_expression(self, it);
            self.expr_depth -= 1;
        } else {
            walk_expression(self, it);
        }
    }
}

/// Whether an expression statement provably has no effect: literals,
/// identifiers, templates without substitutions, and pure operators over
/// such operands. Calls, assignments, `delete`, tagged templates, and any
/// unrecognized shape are treated as effectful.
pub(crate) fn is_pointless_expression(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::Identifier(_)
        | Expression::ThisExpression(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::ParenthesizedExpression(parens) => is_pointless_expression(&parens.expression),
        Expression::UnaryExpression(unary) => {
            unary.operator != UnaryOperator::Delete && is_pointless_expression(&unary.argument)
        }
        Expression::BinaryExpression(binary) => {
            is_pointless_expression(&binary.left) && is_pointless_expression(&binary.right)
        }
        Expression::LogicalExpression(logical) => {
            is_pointless_expression(&logical.left) && is_pointless_expression(&logical.right)
        }
        Expression::SequenceExpression(sequence) => sequence
            .expressions
            .iter()
            .all(|expression| is_pointless_expression(expression)),
        _ => false,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_embedded_effects(ctx.program, ctx.index, ctx.language)
}
