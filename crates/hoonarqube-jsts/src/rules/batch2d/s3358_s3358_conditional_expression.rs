// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::support::RuleScope;
use oxc_ast::ast::ConditionalExpression;
use oxc_ast::ast::Expression;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_expression;
use oxc_span::GetSpan;
use oxc_span::Span;

/// Finds the first nested `ConditionalExpression` inside a ternary branch
/// (`S3358`). The reference listener is `ConditionalExpression
/// ConditionalExpression`, so any descendant ternary reports — unless an
/// array, object, function, arrow, or JSX expression container breaks the
/// nesting. The first nested ternary stops the descent: deeper levels are
/// reported when the traversal reaches them as parents.
#[derive(Default)]
struct NestedTernaryScanner {
    found: Option<Span>,
}

impl<'a> Visit<'a> for NestedTernaryScanner {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.found.is_some() {
            return;
        }
        match it {
            Expression::ConditionalExpression(nested) => {
                self.found = Some(nested.span());
            }
            // Nesting breakers: a ternary inside one of these is not nested
            // in the outer ternary for `S3358`.
            Expression::ArrayExpression(_)
            | Expression::ObjectExpression(_)
            | Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_) => {}
            _ => walk_expression(self, it),
        }
    }

    fn visit_jsx_expression_container(&mut self, _it: &oxc_ast::ast::JSXExpressionContainer<'a>) {}
}

// Generated per-rule checks (moved out of traversal overrides).
impl EsIdiomCollector<'_> {
    /// `S3358` logic extracted from `visit_conditional_expression`.
    pub(crate) fn check_s3358_conditional_expression(&mut self, it: &ConditionalExpression<'_>) {
        // `S3358`: ternaries nested anywhere in the test, consequent, or
        // alternate, unless a nesting breaker intervenes.
        for branch in [&it.test, &it.consequent, &it.alternate] {
            let mut scanner = NestedTernaryScanner::default();
            scanner.visit_expression(branch);
            if let Some(span) = scanner.found {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3358",
                    "Extract this nested ternary operation into an independent statement.",
                    span,
                );
            }
        }
    }
}
