// Rule module s6332_efs_encryption.
use super::shared::{CdkFile, property_value, required_prop};
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::NewExpression;

const OMITTED: &str = "Omitting \"encrypted\" disables EFS encryption. Make sure it is safe here.";
const DISABLED: &str = "Make sure that using unencrypted file systems is safe here.";

/// `S6332`: EFS file systems should be encrypted at rest.
///
/// The L2 `FileSystem` defaults to encryption, so only `encrypted: false` is
/// flagged; the L1 `CfnFileSystem` must carry `encrypted: true` explicitly —
/// a missing key or a provable non-`true` literal is flagged. Non-literal
/// values cannot be proven and are skipped.
pub(crate) fn check_s6332_efs_encryption(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    if file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_efs.FileSystem") {
        // Omission is fine on the L2 construct; only `false` is provably bad.
        let props = file.props_arg(&new_expression.arguments, 2);
        if let Some(view) = props.view()
            && let Some(value) = property_value(view, "encrypted")
            && file.value_bool(&value) == Some(false)
        {
            sink.emit_span(RuleScope::Both, "S6332", DISABLED, value.span());
        }
        return;
    }
    if file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_efs.CfnFileSystem") {
        let omitted = required_prop(file, new_expression, 2, "encrypted", "S6332", OMITTED, sink);
        if let Some(value) = omitted
            && file.value_bool(&value) == Some(false)
        {
            sink.emit_span(RuleScope::Both, "S6332", DISABLED, value.span());
        }
    }
}
