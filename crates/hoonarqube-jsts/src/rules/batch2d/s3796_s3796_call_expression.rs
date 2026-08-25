use super::collectors::{FunctionMetricsCollector, ReturnMixScanner};
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::expression::walker::call_property;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::FunctionBody;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

/// `S3796`: array methods whose callbacks are expected to return values.
/// `forEach` is deliberately absent — its callbacks legitimately produce
/// nothing, so they never carry a missing-return defect.
const ARRAY_CALLBACK_METHODS: [&str; 10] = [
    "every",
    "filter",
    "find",
    "findIndex",
    "flatMap",
    "map",
    "reduce",
    "reduceRight",
    "some",
    "sort",
];

/// Whether one function body carries no value-returning statement outside
/// nested functions (`S3796`).
fn lacks_valued_return(body: &FunctionBody<'_>) -> bool {
    let mut scanner = ReturnMixScanner::default();
    scanner.visit_function_body(body);
    scanner.valued_spans.is_empty()
}

// Generated per-rule checks (moved out of traversal overrides).
impl FunctionMetricsCollector<'_> {
    /// `S3796` logic extracted from `visit_call_expression`.
    pub(crate) fn check_s3796_call_expression(&mut self, it: &CallExpression<'_>) {
        // `S3796`: array-method callbacks without any value-returning
        // statement (JavaScript-only).
        if let Some((property, _member)) = call_property(it)
            && ARRAY_CALLBACK_METHODS.contains(&property)
            && let Some(callback) = it.arguments.first().and_then(argument_expression)
        {
            let missing = match callback {
                Expression::FunctionExpression(function) => function
                    .body
                    .as_ref()
                    .is_some_and(|body| lacks_valued_return(body)),
                Expression::ArrowFunctionExpression(arrow) => arrow
                    .body
                    .as_function_body()
                    .is_some_and(lacks_valued_return),
                _ => false,
            };
            if missing {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S3796",
                    "Add the missing \"return\" statement to this function.",
                    callback.span(),
                );
            }
        }
    }
}
