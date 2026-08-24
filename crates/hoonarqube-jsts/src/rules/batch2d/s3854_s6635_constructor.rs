use super::collectors::{
    ClassAccessorCollector, ReturnMixScanner, SuperCallScanner, ThisUseScanner,
};
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::MethodDefinition;
use oxc_ast::ast::Statement;
use oxc_ast_visit::Visit;
use oxc_span::{GetSpan, Span};

impl ClassAccessorCollector<'_> {
    /// `S3854`: missing, duplicated, conditional, or late `super()` calls;
    /// also `S6635`: constructors returning values.
    pub(crate) fn check_constructor(&mut self, method: &MethodDefinition<'_>, heritage: bool) {
        let Some(body) = &method.value.body else {
            return;
        };
        // `S6635` applies with or without a base class.
        let mut returns = ReturnMixScanner::default();
        returns.visit_function_body(body);
        for span in &returns.valued_spans {
            self.sink.emit_span(
                RuleScope::Both,
                "S6635",
                "Remove this return value; constructors should not return anything.",
                *span,
            );
        }
        if !heritage {
            return;
        }

        // Split the calls into direct top-level statements and nested
        // (conditional) ones; only the top-level ones can be "first".
        let mut top_level_spans: Vec<Span> = Vec::new();
        let mut nested_spans: Vec<Span> = Vec::new();
        for statement in &body.statements {
            if is_super_call_statement(statement) {
                if let Statement::ExpressionStatement(expr) = statement
                    && let Expression::CallExpression(call) = unparenthesized(&expr.expression)
                {
                    top_level_spans.push(call.span());
                }
            } else {
                let mut scanner = SuperCallScanner::default();
                scanner.visit_statement(statement);
                nested_spans.extend(scanner.spans);
            }
        }

        if top_level_spans.is_empty() && nested_spans.is_empty() {
            self.sink.emit_span(
                RuleScope::Both,
                "S3854",
                "Add a \"super()\" call in this constructor.",
                method.key.span(),
            );
            return;
        }
        for span in &nested_spans {
            self.sink.emit_span(
                RuleScope::Both,
                "S3854",
                "Move this call of super() to the first statement of this constructor.",
                *span,
            );
        }
        for span in top_level_spans.iter().skip(1) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3854",
                "Remove this duplicated call to super().",
                *span,
            );
        }
        // `this` must not be touched before the first `super()` call.
        if let Some(first) = top_level_spans.first() {
            for statement in &body.statements {
                if is_super_call_statement(statement) {
                    break;
                }
                let mut scanner = ThisUseScanner::default();
                scanner.visit_statement(statement);
                if scanner.found {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3854",
                        "Call super() before accessing \"this\".",
                        statement.span(),
                    );
                    break;
                }
            }
            let _ = first;
        }
    }
}

pub(crate) fn is_super_call_statement(statement: &Statement<'_>) -> bool {
    matches!(statement, Statement::ExpressionStatement(expr)
        if matches!(unparenthesized(&expr.expression), Expression::CallExpression(call)
            if matches!(call.callee, Expression::Super(_))))
}
