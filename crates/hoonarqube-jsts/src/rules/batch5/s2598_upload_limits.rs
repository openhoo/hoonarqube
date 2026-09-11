use crate::rules::batch5::collectors::{SecurityFactory, SecurityHotspotCollector, SecurityModule};
use crate::rules::shared::argument_expression;
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{CallExpression, Expression, NewExpression};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2598`: multer disk storage must specify a destination.
    pub(crate) fn check_upload_limits(&mut self, call: &CallExpression<'_>) {
        if !matches!(unparenthesized(&call.callee), Expression::Identifier(_)) {
            return;
        }
        let at = call.span().start;
        if !self
            .security_bindings
            .is_module(&call.callee, SecurityModule::Multer, at)
        {
            return;
        }
        let Some(options) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        if !self.security_bindings.object_property_factory_missing(
            options,
            "storage",
            SecurityFactory::MulterDiskStorage,
            "destination",
            at,
        ) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S2598",
            "Restrict folder destination of uploaded files.",
            call.callee.span(),
        );
    }

    /// Retained for the generated visitor; S2598 does not inspect constructors.
    pub(crate) fn check_new_upload(_new: &NewExpression<'_>) {}
}
