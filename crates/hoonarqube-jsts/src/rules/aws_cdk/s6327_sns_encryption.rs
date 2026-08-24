// Rule module s6327_sns_encryption.
use super::shared::{CdkFile, required_prop};
use crate::support::IssueSink;
use oxc_ast::ast::NewExpression;

const TOPIC_OMITTED: &str =
    "Omitting \"masterKey\" disables SNS topics encryption. Make sure it is safe here.";
const CFN_TOPIC_OMITTED: &str =
    "Omitting \"kmsMasterKeyId\" disables SNS topics encryption. Make sure it is safe here.";

/// `S6327`: SNS topics should be encrypted with a KMS key.
///
/// Flags `new sns.Topic` without `masterKey` and `new sns.CfnTopic` without
/// `kmsMasterKeyId`. Conservative subset: the omitted-shape fires only when
/// the props argument is provably absent, literally `undefined`, or a
/// provable object literal without the key; opaque props are skipped.
pub(crate) fn check_s6327_sns_encryption(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    if file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_sns.Topic") {
        required_prop(
            file,
            new_expression,
            2,
            "masterKey",
            "S6327",
            TOPIC_OMITTED,
            sink,
        );
    } else if file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_sns.CfnTopic") {
        required_prop(
            file,
            new_expression,
            2,
            "kmsMasterKeyId",
            "S6327",
            CFN_TOPIC_OMITTED,
            sink,
        );
    }
}
