use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::object_property;
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5693`: body parsers configured without a size limit.
    ///
    /// Deviation: the catalog's `fileUploadSizeLimit` / `standardSizeLimit`
    /// INTEGER parameters are not evaluated — limit values in user code can
    /// be strings (`'1mb'`) or arbitrary expressions, and no oracle
    /// evidence pins down threshold semantics. The presence of any explicit
    /// `limit` option satisfies the check.
    pub(crate) fn check_body_parser_limit(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        if property != "json" && property != "urlencoded" && property != "text" {
            return;
        }
        let root = expression_root_name(&member.object);
        if !matches!(root, Some("express" | "bodyParser")) {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(argument) else {
            return;
        };
        if object_property(object, "limit").is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S5693",
                "Configure a request-body size limit ('limit').",
                call.span(),
            );
        }
    }
}
