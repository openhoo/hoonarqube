// Rule module s6303_rds_encryption.
use super::shared::{CdkFile, ValueView, property_value};
use crate::support::IssueSink;
use crate::support::RuleScope;
use oxc_ast::ast::NewExpression;
use oxc_span::GetSpan;

const OMITTED: &str =
    "Omitting storageEncrypted disables RDS encryption. Make sure it is safe here.";
const UNSAFE: &str = "Make sure that using unencrypted storage is safe here.";

const RDS_PREFIX: &str = "aws_cdk_lib.aws_rds.";
/// L2 clusters/instances may pass `storageEncryptionKey` instead.
const L2_TYPES: [&str; 4] = [
    "DatabaseCluster",
    "DatabaseClusterFromSnapshot",
    "DatabaseInstance",
    "DatabaseInstanceReadReplica",
];

/// `S6303`: RDS instances and clusters should be encrypted at rest.
///
/// Flags missing `storageEncrypted` and `storageEncrypted: false`. L2
/// constructs providing `storageEncryptionKey: new kms.Key/Alias` are
/// exempt, mirroring the upstream exception.
pub(crate) fn check_s6303_rds_encryption(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    let Some(fqn) = file.fqn(&new_expression.callee) else {
        return;
    };
    let Some(storage) = fqn.strip_prefix(RDS_PREFIX) else {
        return;
    };
    if !matches!(
        storage,
        "CfnDBCluster"
            | "CfnDBInstance"
            | "DatabaseCluster"
            | "DatabaseClusterFromSnapshot"
            | "DatabaseInstance"
            | "DatabaseInstanceReadReplica"
    ) {
        return;
    }
    let props = file.props_arg(&new_expression.arguments, 2);
    if props.provably_absent() {
        sink.emit_span(
            RuleScope::Both,
            "S6303",
            OMITTED,
            new_expression.callee.span(),
        );
        return;
    }
    let Some(view) = props.view() else {
        return;
    };
    let l2 = L2_TYPES.contains(&storage);
    if l2
        && let Some(key) = property_value(view, "storageEncryptionKey")
        && kms_key_or_alias(file, &key)
    {
        return;
    }
    match property_value(view, "storageEncrypted") {
        Some(value) => {
            if file.value_bool(&value) == Some(false) {
                sink.emit_span(RuleScope::Both, "S6303", UNSAFE, value.span());
            }
        }
        None => sink.emit_span(
            RuleScope::Both,
            "S6303",
            OMITTED,
            new_expression.callee.span(),
        ),
    }
}

fn kms_key_or_alias(file: &CdkFile, key: &ValueView<'_, '_>) -> bool {
    matches!(
        file.value_new_fqn(key).as_deref(),
        Some("aws_cdk_lib.aws_kms.Key" | "aws_cdk_lib.aws_kms.Alias")
    )
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6303_requires_rds_storage_encryption() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6303"))
                .count()
        };

        assert_eq!(
            count(
                "import * as rds from 'aws-cdk-lib/aws-rds';\nnew rds.DatabaseInstance(this, 'DB');\n"
            ),
            1
        );
        assert_eq!(
            count(
                "import * as rds from 'aws-cdk-lib/aws-rds';\n\
             new rds.DatabaseInstance(this, 'DB', { storageEncrypted: false });\n"
            ),
            1
        );
        // L2 exception: explicit KMS storage encryption key.
        assert_eq!(
            count(
                "import * as rds from 'aws-cdk-lib/aws-rds';\n\
             import * as kms from 'aws-cdk-lib/aws-kms';\n\
             new rds.DatabaseInstance(this, 'DB', {\n\
             \x20 storageEncryptionKey: new kms.Key(this, 'Key'),\n\
             });\n"
            ),
            0
        );
        // Clean: encrypted.
        assert_eq!(
            count(
                "import * as rds from 'aws-cdk-lib/aws-rds';\n\
             new rds.DatabaseCluster(this, 'DB', { storageEncrypted: true });\n"
            ),
            0
        );
    }
}
