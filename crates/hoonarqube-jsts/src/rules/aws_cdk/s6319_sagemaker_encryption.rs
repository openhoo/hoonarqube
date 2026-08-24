// Rule module s6319_sagemaker_encryption.
use super::shared::{CdkFile, required_prop};
use crate::support::IssueSink;
use oxc_ast::ast::NewExpression;

const OMITTED: &str = "Omitting \"kmsKeyId\" disables encryption of SageMaker notebook instances. Make sure it is safe here.";

/// `S6319`: `SageMaker` notebook instances should be encrypted with a KMS key
/// (`kmsKeyId`).
///
/// Conservative subset: the omitted-shape fires only when the props argument
/// is provably absent, literally `undefined`, or a provable object literal
/// without the key; opaque props are skipped.
pub(crate) fn check_s6319_sagemaker_encryption(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    if file.is_cdk(
        &new_expression.callee,
        "aws_cdk_lib.aws_sagemaker.CfnNotebookInstance",
    ) {
        required_prop(file, new_expression, 2, "kmsKeyId", "S6319", OMITTED, sink);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6319_requires_sagemaker_kms_key() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6319"))
                .count()
        };

        assert_eq!(
            count(
                "import * as sagemaker from 'aws-cdk-lib/aws-sagemaker';\n\
             new sagemaker.CfnNotebookInstance(this, 'NB');\n"
            ),
            1
        );
        assert_eq!(
            count(
                "import * as sagemaker from 'aws-cdk-lib/aws-sagemaker';\n\
             new sagemaker.CfnNotebookInstance(this, 'NB', { kmsKeyId: 'k' });\n"
            ),
            0
        );
    }
}
