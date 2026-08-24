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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6249_requires_enforce_ssl_on_cdk_s3_buckets() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6249"))
                .count()
        };

        // Namespace import, props argument absent: `enforceSSL` provably missing.
        assert_eq!(
            count("import * as s3 from 'aws-cdk-lib/aws-s3';\nnew s3.Bucket(this, 'Bucket');\n"),
            1
        );

        // Named import, `enforceSSL: false` authorizes HTTP.
        assert_eq!(
            count(
                "import { Bucket } from 'aws-cdk-lib/aws-s3';\n\
             new Bucket(this, 'Bucket', { enforceSSL: false });\n"
            ),
            1
        );

        // Require form, props object bound to a unique variable.
        assert_eq!(
            count(
                "const s3 = require('aws-cdk-lib/aws-s3');\n\
             const props = {};\n\
             new s3.Bucket(this, 'Bucket', props);\n"
            ),
            1
        );

        // Clean: HTTPS enforced.
        assert_eq!(
            count(
                "import * as s3 from 'aws-cdk-lib/aws-s3';\n\
             new s3.Bucket(this, 'Bucket', { enforceSSL: true });\n"
            ),
            0
        );

        // Clean: non-CDK constructor with the same shape.
        assert_eq!(
            count("import * as s3 from 'other-lib';\nnew s3.Bucket(this, 'Bucket');\n"),
            0
        );

        // Clean: opaque props value cannot prove the setting is missing.
        assert_eq!(
            count(
                "import * as s3 from 'aws-cdk-lib/aws-s3';\n\
             new s3.Bucket(this, 'Bucket', unknownProps);\n"
            ),
            0
        );
    }

    #[test]
    fn s6249_reports_enforce_ssl_for_typescript_files_too() {
        let report = ts("import * as s3 from 'aws-cdk-lib/aws-s3';\n\
         new s3.Bucket(this, 'Bucket', { versioned: true });\n");
        let issues: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S6249")
            .collect();
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Omitting 'enforceSSL' authorizes HTTP requests. Make sure it is safe here."
        );
    }
}
