// Rule module s6330_sqs_encryption.
use super::shared::{CdkFile, required_prop};
use crate::support::IssueSink;
use crate::support::RuleScope;
use oxc_ast::ast::NewExpression;

const OMITTED: &str =
    "Omitting \"encryption\" disables SQS queue encryption. Make sure it is safe here.";
const DISABLED: &str = "Setting \"encryption\" to QueueEncryption.UNENCRYPTED disables SQS queue encryption. Make sure it is safe here.";
const CFN_OMITTED: &str =
    "Omitting \"kmsMasterKeyId\" disables SQS queue encryption. Make sure it is safe here.";

/// `S6330`: SQS queues should be encrypted at rest.
///
/// Flags `new sqs.Queue` without `encryption` or with
/// `QueueEncryption.UNENCRYPTED`, and `new sqs.CfnQueue` without
/// `kmsMasterKeyId`. Conservative subset: the omitted-shape fires only when
/// the props argument is provably absent, literally `undefined`, or a
/// provable object literal without the key; opaque props are skipped.
pub(crate) fn check_s6330_sqs_encryption(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    if file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_sqs.CfnQueue") {
        required_prop(
            file,
            new_expression,
            2,
            "kmsMasterKeyId",
            "S6330",
            CFN_OMITTED,
            sink,
        );
        return;
    }
    if !file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_sqs.Queue") {
        return;
    }
    if let Some(value) = required_prop(
        file,
        new_expression,
        2,
        "encryption",
        "S6330",
        OMITTED,
        sink,
    ) && file.value_fqn(&value).as_deref()
        == Some("aws_cdk_lib.aws_sqs.QueueEncryption.UNENCRYPTED")
    {
        sink.emit_span(RuleScope::Both, "S6330", DISABLED, value.span());
    }
}
