use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::object_property;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use crate::support::identifier_name;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::NewExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S6245`: S3 bucket creations without a server-side-encryption option.
    pub(crate) fn check_s3_create_bucket(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("createBucket") {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(options) = unparenthesized(argument) else {
            return;
        };
        if object_property(options, "ServerSideEncryptionConfiguration").is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S6245",
                "Enable server-side encryption for this S3 bucket.",
                call.span(),
            );
        }
    }

    /// `S6245`: `CreateBucketCommand` inputs without server-side encryption.
    pub(crate) fn check_new_s3_bucket_command(&mut self, constructor: &NewExpression<'_>) {
        if identifier_name(&constructor.callee) != Some("CreateBucketCommand") {
            return;
        }
        let Some(argument) = constructor.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(options) = unparenthesized(argument) else {
            return;
        };
        if object_property(options, "ServerSideEncryptionConfiguration").is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S6245",
                "Enable server-side encryption for this S3 bucket.",
                constructor.span(),
            );
        }
    }
}
