// Rule module s6252_s3_versioning.
use super::shared::{CdkFile, property_span, required_prop};
use crate::support::{IssueSink, RuleScope};
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
        let property_span = file
            .props_arg(&new_expression.arguments, 2)
            .view()
            .and_then(|props| property_span(props, "versioned"));
        if let Some(value) =
            required_prop(file, new_expression, 2, "versioned", "S6252", OMITTED, sink)
            && file.value_bool(&value) == Some(false)
        {
            sink.emit_span(
                RuleScope::Both,
                "S6252",
                UNVERSIONED,
                property_span.unwrap_or_else(|| value.span()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6252_requires_versioning_on_cdk_s3_buckets() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6252"))
                .count()
        };

        // Props argument absent: `versioned` provably missing.
        assert_eq!(
            count("import * as s3 from 'aws-cdk-lib/aws-s3';\nnew s3.Bucket(this, 'Bucket');\n"),
            1
        );

        // Explicit `versioned: false`.
        assert_eq!(
            count(
                "import * as s3 from 'aws-cdk-lib/aws-s3';\n\
             new s3.Bucket(this, 'Bucket', { versioned: false });\n"
            ),
            1
        );

        // `versioned` routed through a unique const binding.
        assert_eq!(
            count(
                "import * as s3 from 'aws-cdk-lib/aws-s3';\n\
             const unversioned = false;\n\
             new s3.Bucket(this, 'Bucket', { versioned: unversioned });\n"
            ),
            1
        );

        // Clean: versioning enabled.
        assert_eq!(
            count(
                "import * as s3 from 'aws-cdk-lib/aws-s3';\n\
             new s3.Bucket(this, 'Bucket', { versioned: true });\n"
            ),
            0
        );
    }
}
