// Rule module s6275_ebs_encryption.
use super::shared::{BoolPropCheck, CdkFile, required_bool_prop};
use crate::support::IssueSink;
use oxc_ast::ast::NewExpression;

const OMITTED: &str =
    "Omitting \"encrypted\" disables volumes encryption. Make sure it is safe here.";
const DISABLED: &str = "Make sure that using unencrypted volumes is safe here.";

/// `S6275`: EBS volumes should be encrypted at rest via `encrypted`.
///
/// Conservative subset: the omitted-shape fires only when the props argument
/// is provably absent, literally `undefined`, or a provable object literal
/// without the key; opaque props are skipped.
pub(crate) fn check_s6275_ebs_encryption(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    if file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_ec2.Volume") {
        required_bool_prop(
            file,
            new_expression,
            2,
            BoolPropCheck {
                key: "encrypted",
                rule: "S6275",
                omitted: OMITTED,
                disabled: DISABLED,
            },
            sink,
        );
    }
}
