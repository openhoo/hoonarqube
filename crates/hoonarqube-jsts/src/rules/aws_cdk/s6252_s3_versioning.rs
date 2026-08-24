// Rule module s6252_s3_versioning.
use super::shared::{BoolPropCheck, CdkFile, required_bool_prop};
use crate::support::IssueSink;
use oxc_ast::ast::NewExpression;

const OMITTED: &str =
    "Omitting the \"versioned\" argument disables S3 bucket versioning. Make sure it is safe here.";
const UNVERSIONED: &str = "Make sure using unversioned S3 bucket is safe here.";

/// `S6252`: S3 buckets should have versioning enabled via `versioned`.
///
/// Conservative subset: the omitted-shape fires only when the props argument
/// is provably absent, literally `undefined`, or a provable object literal
/// without the key; opaque props are skipped.
pub(crate) fn check_s6252_s3_versioning(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    if file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_s3.Bucket") {
        required_bool_prop(
            file,
            new_expression,
            2,
            BoolPropCheck {
                key: "versioned",
                rule: "S6252",
                omitted: OMITTED,
                disabled: UNVERSIONED,
            },
            sink,
        );
    }
}
