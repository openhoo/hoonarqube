// Rule module s6265_s3_public_access.
use super::shared::{CdkFile, PropsArg, PropsView, property_value};
use crate::support::IssueSink;
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{CallExpression, Expression, NewExpression};
use oxc_span::GetSpan;

const UNRESTRICTED: &str =
    "Make sure allowing unrestricted access to objects from this bucket is safe here.";
const PUBLIC_ACCESS_LEVELS: [&str; 3] = ["PUBLIC_READ", "PUBLIC_READ_WRITE", "AUTHENTICATED_READ"];

/// `S6265`: S3 buckets should not grant access to all or authenticated users.
///
/// Flags `accessControl` set to a public/authenticated `BucketAccessControl`
/// level, `publicReadAccess: true`, and `grantPublicAccess()` calls on bucket
/// instances. Bucket-deployment constructs are checked for `accessControl`
/// only, mirroring the upstream rule.
pub(crate) fn check_s6265_s3_public_access_new(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    let is_bucket = file.is_cdk(&new_expression.callee, "aws_cdk_lib.aws_s3.Bucket");
    let is_deployment = file.is_cdk(
        &new_expression.callee,
        "aws_cdk_lib.aws_s3_deployment.BucketDeployment",
    );
    if !is_bucket && !is_deployment {
        return;
    }
    let PropsArg::Live(props) = file.props_arg(&new_expression.arguments, 2) else {
        return;
    };
    if let Some(value) = property_value(PropsView::Live(props), "accessControl")
        && let Some(level) = file
            .value_fqn(&value)
            .as_deref()
            .and_then(public_access_level)
    {
        sink.emit_span(
            RuleScope::Both,
            "S6265",
            &format!("Make sure granting {level} access is safe here."),
            value.span(),
        );
    }
    if is_bucket
        && let Some(value) = property_value(PropsView::Live(props), "publicReadAccess")
        && file.value_bool(&value) == Some(true)
    {
        sink.emit_span(RuleScope::Both, "S6265", UNRESTRICTED, value.span());
    }
}

/// Flags `bucket.grantPublicAccess(...)` on bucket instances, including
/// instances bound to a unique variable.
pub(crate) fn check_s6265_s3_public_access_call(
    file: &CdkFile,
    call: &CallExpression<'_>,
    sink: &mut IssueSink,
) {
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return;
    };
    if member.property.name.as_str() != "grantPublicAccess" {
        return;
    }
    let on_bucket = match unparenthesized(&member.object) {
        Expression::NewExpression(new) => file.is_cdk(&new.callee, "aws_cdk_lib.aws_s3.Bucket"),
        Expression::Identifier(identifier) => {
            file.bound_new_is_cdk(identifier.name.as_str(), "aws_cdk_lib.aws_s3.Bucket")
        }
        _ => false,
    };
    if on_bucket {
        sink.emit_span(
            RuleScope::Both,
            "S6265",
            UNRESTRICTED,
            member.property.span(),
        );
    }
}

fn public_access_level(fqn: &str) -> Option<&'static str> {
    PUBLIC_ACCESS_LEVELS
        .into_iter()
        .find(|level| fqn == format!("aws_cdk_lib.aws_s3.BucketAccessControl.{level}"))
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6265_flags_public_s3_access_grants() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6265"))
                .count()
        };

        // `publicReadAccess: true` on a bucket.
        assert_eq!(
            count(
                "import * as s3 from 'aws-cdk-lib/aws-s3';\n\
             new s3.Bucket(this, 'B', { publicReadAccess: true });\n"
            ),
            1
        );

        // Public `accessControl` level.
        assert_eq!(
            count(
                "import * as s3 from 'aws-cdk-lib/aws-s3';\n\
             new s3.Bucket(this, 'B', {\n\
             \x20 accessControl: s3.BucketAccessControl.PUBLIC_READ,\n\
             });\n"
            ),
            1
        );

        // `grantPublicAccess()` on a bucket variable.
        assert_eq!(
            count(
                "import * as s3 from 'aws-cdk-lib/aws-s3';\n\
             const bucket = new s3.Bucket(this, 'B', {});\n\
             bucket.grantPublicAccess();\n"
            ),
            1
        );

        // Clean: private access control and no grants.
        assert_eq!(
            count(
                "import * as s3 from 'aws-cdk-lib/aws-s3';\n\
             new s3.Bucket(this, 'B', {\n\
             \x20 accessControl: s3.BucketAccessControl.PRIVATE,\n\
             \x20 publicReadAccess: false,\n\
             });\n"
            ),
            0
        );
    }
}
