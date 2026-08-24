// Rule module s6249_s3_insecure_http.
use super::shared::{BoolPropCheck, CdkFile, required_bool_prop};
use crate::support::IssueSink;
use oxc_ast::ast::NewExpression;

const OMITTED: &str = "Omitting 'enforceSSL' authorizes HTTP requests. Make sure it is safe here.";
const AUTHORIZED: &str = "Make sure authorizing HTTP requests is safe here.";

/// `S6249`: S3 buckets should enforce HTTPS-only access via `enforceSSL`.
///
/// Conservative subset: the omitted-shape fires only when the props argument
/// is provably absent, literally `undefined`, or a provable object literal
/// without the key; opaque props are skipped.
pub(crate) fn check_s6249_s3_insecure_http(
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
                key: "enforceSSL",
                rule: "S6249",
                omitted: OMITTED,
                disabled: AUTHORIZED,
            },
            sink,
        );
    }
}
