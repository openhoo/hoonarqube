// Rule module s6281_s3_public_access_block.
use super::shared::{CdkFile, PropsView, ValueView, property_value};
use crate::support::IssueSink;
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{Expression, NewExpression};

const PUBLIC: &str = "Disabling public access block settings allows public ACL/policies to be set on this S3 bucket.";
const BLOCK_ACLS_ONLY: &str = "Using BLOCK_ACLS_ONLY allows public access via bucket policies.";

const BLOCK_KEYS: [&str; 4] = [
    "blockPublicAcls",
    "blockPublicPolicy",
    "ignorePublicAcls",
    "restrictPublicBuckets",
];

/// `S6281`: S3 bucket public access should be fully blocked.
///
/// Flags `blockPublicAccess: s3.BlockPublicAccess.BLOCK_ACLS_ONLY` and
/// `blockPublicAccess: new s3.BlockPublicAccess({...})` configurations with
/// any block setting explicitly `false`. Digest-backed (variable) values
/// carry no constructor arguments and are conservatively skipped.
pub(crate) fn check_s6281_s3_public_access_block(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    if !file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_s3.Bucket") {
        return;
    }
    let Some(PropsView::Live(props)) = file.props_arg(&new_expression.arguments, 2).view() else {
        return;
    };
    let Some(block) = property_value(PropsView::Live(props), "blockPublicAccess") else {
        return;
    };
    if file
        .value_fqn(&block)
        .is_some_and(|fqn| fqn == "aws_cdk_lib.aws_s3.BlockPublicAccess.BLOCK_ACLS_ONLY")
    {
        sink.emit_span(RuleScope::Both, "S6281", BLOCK_ACLS_ONLY, block.span());
        return;
    }
    let ValueView::Live(expression) = &block else {
        return;
    };
    let Expression::NewExpression(constructor) = unparenthesized(expression) else {
        return;
    };
    if !file.is_cdk(&constructor.callee, "aws_cdk_lib.aws_s3.BlockPublicAccess") {
        return;
    }
    let Some(PropsView::Live(config)) = file.props_arg(&constructor.arguments, 0).view() else {
        return;
    };
    for key in BLOCK_KEYS {
        if let Some(value) = property_value(PropsView::Live(config), key)
            && file.value_bool(&value) == Some(false)
        {
            sink.emit_span(RuleScope::Both, "S6281", PUBLIC, value.span());
        }
    }
}
