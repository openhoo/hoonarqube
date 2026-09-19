use crate::engine::file_context::FileContext;
use crate::support::WebFrameworkFacts;
use crate::support::has_keyword;
use crate::support::issue_at;
use crate::support::resolves_to_aws_client;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7608 — S3 operations should verify bucket ownership --------------

const RULE_KEY: &str = "python:S7608";
const MESSAGE: &str = "Add the 'ExpectedBucketOwner' parameter to verify S3 bucket ownership.";
const MESSAGE_EXTRA_ARGS: &str =
    "Add the 'ExpectedBucketOwner' to the 'ExtraArgs' parameter to verify S3 bucket ownership.";

/// S3 client methods that accept `ExpectedBucketOwner` (Sonar's
/// `S3_METHODS_REQUIRING_EXPECTED_BUCKET_OWNER`).
const S3_METHODS_REQUIRING_EXPECTED_BUCKET_OWNER: &[&str] = &[
    "copy_object",
    "create_bucket_metadata_configuration",
    "create_bucket_metadata_table_configuration",
    "create_multipart_upload",
    "delete_bucket",
    "delete_bucket_analytics_configuration",
    "delete_bucket_cors",
    "delete_bucket_encryption",
    "delete_bucket_intelligent_tiering_configuration",
    "delete_bucket_inventory_configuration",
    "delete_bucket_lifecycle",
    "delete_bucket_metadata_configuration",
    "delete_bucket_metadata_table_configuration",
    "delete_bucket_metrics_configuration",
    "delete_bucket_ownership_controls",
    "delete_bucket_policy",
    "delete_bucket_replication",
    "delete_bucket_tagging",
    "delete_bucket_website",
    "delete_object",
    "delete_object_tagging",
    "delete_objects",
    "delete_public_access_block",
    "get_bucket_accelerate_configuration",
    "get_bucket_acl",
    "get_bucket_analytics_configuration",
    "get_bucket_cors",
    "get_bucket_encryption",
    "get_bucket_intelligent_tiering_configuration",
    "get_bucket_inventory_configuration",
    "get_bucket_lifecycle",
    "get_bucket_lifecycle_configuration",
    "get_bucket_location",
    "get_bucket_logging",
    "get_bucket_metadata_configuration",
    "get_bucket_metadata_table_configuration",
    "get_bucket_metrics_configuration",
    "get_bucket_notification",
    "get_bucket_notification_configuration",
    "get_bucket_ownership_controls",
    "get_bucket_policy",
    "get_bucket_policy_status",
    "get_bucket_replication",
    "get_bucket_request_payment",
    "get_bucket_tagging",
    "get_bucket_versioning",
    "get_bucket_website",
    "get_object",
    "get_object_acl",
    "get_object_attributes",
    "get_object_legal_hold",
    "get_object_lock_configuration",
    "get_object_retention",
    "get_object_tagging",
    "get_object_torrent",
    "get_public_access_block",
    "head_bucket",
    "head_object",
    "list_bucket_analytics_configurations",
    "list_bucket_intelligent_tiering_configurations",
    "list_bucket_inventory_configurations",
    "list_bucket_metrics_configurations",
    "list_multipart_uploads",
    "list_object_versions",
    "list_objects",
    "list_objects_v2",
    "list_parts",
    "put_bucket_accelerate_configuration",
    "put_bucket_acl",
    "put_bucket_analytics_configuration",
    "put_bucket_cors",
    "put_bucket_encryption",
    "put_bucket_intelligent_tiering_configuration",
    "put_bucket_inventory_configuration",
    "put_bucket_lifecycle",
    "put_bucket_lifecycle_configuration",
    "put_bucket_logging",
    "put_bucket_metrics_configuration",
    "put_bucket_notification",
    "put_bucket_notification_configuration",
    "put_bucket_ownership_controls",
    "put_bucket_policy",
    "put_bucket_replication",
    "put_bucket_request_payment",
    "put_bucket_tagging",
    "put_bucket_versioning",
    "put_bucket_website",
    "put_object",
    "put_object_acl",
    "put_object_legal_hold",
    "put_object_lock_configuration",
    "put_object_retention",
    "put_object_tagging",
    "put_public_access_block",
    "rename_object",
    "restore_object",
    "select_object_content",
    "update_bucket_metadata_inventory_table_configuration",
    "update_bucket_metadata_journal_table_configuration",
    "upload_part",
    "upload_part_copy",
];

/// File-level transfer helpers take the owner check through `ExtraArgs`.
const UPLOAD_DOWNLOAD_FILE_METHODS: &[&str] = &[
    "upload_file",
    "upload_fileobj",
    "download_file",
    "download_fileobj",
];

/// Whether the call passes a `*args` or `**kwargs` unpacking (Sonar's
/// `UNPACKING_EXPR` arguments), which hides the real keyword set.
fn has_args_or_kwargs_unpacking(call: &ruff_python_ast::ExprCall) -> bool {
    call.arguments
        .args
        .iter()
        .any(|arg| matches!(arg, Expr::Starred(_)))
        || call
            .arguments
            .keywords
            .iter()
            .any(|keyword| keyword.arg.is_none())
}

/// python:S7608 — S3 client calls that accept `ExpectedBucketOwner` must pass
/// it; `upload_file`/`download_file` variants must pass `ExtraArgs` instead.
/// The receiver must resolve to a boto3/aiobotocore client factory call.
pub(crate) fn check_s7608_s3_expected_bucket_owner(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            continue;
        };
        let method = attribute.attr.as_str();
        if !resolves_to_aws_client(&facts, &attribute.value) {
            continue;
        }
        if UPLOAD_DOWNLOAD_FILE_METHODS.contains(&method) {
            if !has_keyword(&call.arguments, "ExtraArgs") {
                issues.push(issue_at(
                    RULE_KEY,
                    MESSAGE_EXTRA_ARGS,
                    call.func.range(),
                    index,
                    source,
                ));
            }
            continue;
        }
        if !S3_METHODS_REQUIRING_EXPECTED_BUCKET_OWNER.contains(&method) {
            continue;
        }
        if has_args_or_kwargs_unpacking(call) || has_keyword(&call.arguments, "ExpectedBucketOwner")
        {
            continue;
        }
        issues.push(issue_at(
            RULE_KEY,
            MESSAGE,
            call.func.range(),
            index,
            source,
        ));
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7608";

    #[test]
    fn s7608_flags_s3_operations_without_expected_bucket_owner() {
        let flagged = scan(concat!(
            "import boto3\n",
            "s3_client = boto3.client('s3')\n",
            "def lambda_handler(event, context):\n",
            "    s3_client.get_object(Bucket='b', Key='k')\n",
            "    s3_client.put_object(Bucket='b', Key='k', Body=b'd')\n",
            "    s3_client.delete_object(Bucket='b', Key='k')\n",
        ));
        let issues = findings(&flagged, KEY);
        assert_eq!(issues.len(), 3);
        assert_eq!(
            issues[0].message,
            "Add the 'ExpectedBucketOwner' parameter to verify S3 bucket ownership."
        );
    }

    #[test]
    fn s7608_spares_operations_with_expected_bucket_owner_or_unpacking() {
        let compliant = scan(concat!(
            "import boto3\n",
            "s3_client = boto3.client('s3')\n",
            "def handler(event, context):\n",
            "    s3_client.get_object(Bucket='b', Key='k', ExpectedBucketOwner='123456789012')\n",
            "    s3_client.create_bucket(Bucket='new-bucket')\n",
            "    s3_client.get_object(*args)\n",
            "    s3_client.get_object(**kwargs)\n",
        ));
        assert!(findings(&compliant, KEY).is_empty());
    }

    #[test]
    fn s7608_flags_upload_download_without_extra_args() {
        let flagged = scan(concat!(
            "import boto3\n",
            "s3_client = boto3.client('s3')\n",
            "def handler(event, context):\n",
            "    s3_client.upload_file('n', 'b', '1')\n",
            "    s3_client.download_fileobj('n', 'b', '1', ExpectedBucketOwner='')\n",
            "    s3_client.upload_file('n', 'b', '1', ExtraArgs={})\n",
        ));
        let issues = findings(&flagged, KEY);
        assert_eq!(issues.len(), 2);
        assert_eq!(
            issues[0].message,
            "Add the 'ExpectedBucketOwner' to the 'ExtraArgs' parameter to verify S3 bucket ownership."
        );
    }

    #[test]
    fn s7608_flags_aiobotocore_clients() {
        let flagged = scan(concat!(
            "import aiobotocore.session\n",
            "session = aiobotocore.session.get_session()\n",
            "aclient = session.create_client('s3')\n",
            "async def handler(event, context):\n",
            "    await aclient.get_object(Bucket='b', Key='k')\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 1);
    }

    #[test]
    fn s7608_spares_non_s3_and_unknown_receivers() {
        let quiet = scan(concat!(
            "import boto3\n",
            "ec2_client = boto3.client('ec2')\n",
            "ec2_client.describe_instances()\n",
            "cache.get_object(Bucket='b', Key='k')\n",
        ));
        assert!(findings(&quiet, KEY).is_empty());
    }
}
