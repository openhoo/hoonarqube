use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use crate::support::identifier_name;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ImportDeclaration;
use oxc_ast::ast::NewExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4817`: `XPath` evaluation entry points worth reviewing.
    pub(crate) fn check_xpath_usage(&mut self, call: &CallExpression<'_>) {
        let mut flagged = false;
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name == "evaluate"
            && expression_root_name(&member.object) == Some("document")
        {
            flagged = true;
        }
        if !flagged
            && sink_callee_name(&call.callee) == Some("require")
            && first_string_argument(call) == Some("xpath")
        {
            flagged = true;
        }
        if flagged {
            self.sink.emit_span(
                RuleScope::Both,
                "S4817",
                "Make sure evaluating this XPath expression is safe here.",
                call.span(),
            );
        }
    }

    /// `S4817`: `xpath` module imports.
    pub(crate) fn check_xpath_module_import(&mut self, declaration: &ImportDeclaration<'_>) {
        if declaration.source.value == "xpath" {
            self.sink.emit_span(
                RuleScope::Both,
                "S4817",
                "Make sure evaluating these XPath expressions is safe here.",
                declaration.span(),
            );
        }
    }

    /// `S4817`: dedicated `XPathEvaluator` constructions.
    pub(crate) fn check_new_xpath_evaluator(&mut self, constructor: &NewExpression<'_>) {
        if identifier_name(&constructor.callee) == Some("XPathEvaluator") {
            self.sink.emit_span(
                RuleScope::Both,
                "S4817",
                "Make sure evaluating XPath expressions with this evaluator is safe here.",
                constructor.span(),
            );
        }
    }
}
