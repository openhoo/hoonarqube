use super::s6252_s3_versioning::S3Bindings;
use crate::engine::file_context::FileContext;
use crate::support::{issue_at, keyword_range, keyword_value, string_literal_text};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
// --- python:S6265 — S3 buckets not granted to all users -------------------------

fn has_unknown_keyword_unpack(arguments: &ruff_python_ast::Arguments) -> bool {
    arguments
        .keywords
        .iter()
        .any(|keyword| keyword.arg.is_none() && !matches!(keyword.value, Expr::Dict(_)))
}

fn literal_unpacked_keyword<'a>(
    arguments: &'a ruff_python_ast::Arguments,
    name: &str,
) -> Option<&'a Expr> {
    arguments.keywords.iter().find_map(|keyword| {
        if keyword.arg.is_some() {
            return None;
        }
        let Expr::Dict(dict) = &keyword.value else {
            return None;
        };
        dict.items.iter().find_map(|item| {
            item.key
                .as_ref()
                .and_then(string_literal_text)
                .filter(|key| key == name)
                .map(|_| &item.value)
        })
    })
}

const LEGACY_MESSAGE: &str = "Do not grant this S3 bucket access to all users.";
const ALL_USERS_GRANT_URI: &str = "http://acs.amazonaws.com/groups/global/AllUsers";

fn message_for_access_level(level: &str) -> &'static str {
    match level {
        "PUBLIC_READ" => "Make sure granting PUBLIC_READ access is safe here.",
        "PUBLIC_READ_WRITE" => "Make sure granting PUBLIC_READ_WRITE access is safe here.",
        "AUTHENTICATED_READ" => "Make sure granting AUTHENTICATED_READ access is safe here.",
        _ => unreachable!("public access level is validated by S3Bindings"),
    }
}

pub(crate) fn check_s6265_s3_public_acl(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let bindings = file_ctx
        .has_aws_cdk_import
        .then(|| S3Bindings::collect(file_ctx));
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let at = call.range().start();
        if let Some(bindings) = bindings.as_ref() {
            let is_bucket = bindings.is_s3_bucket_constructor(&call.func, at);
            let is_deployment = bindings.is_bucket_deployment_constructor(&call.func, at);
            if (is_bucket || is_deployment)
                && !has_unknown_keyword_unpack(&call.arguments)
                && let Some(access_control) = keyword_value(&call.arguments, "access_control")
                    .or_else(|| literal_unpacked_keyword(&call.arguments, "access_control"))
                && let Some(level) = bindings.public_access_level(access_control, at)
            {
                issues.push(issue_at(
                    "python:S6265",
                    message_for_access_level(level),
                    keyword_range(&call.arguments, "access_control")
                        .unwrap_or_else(|| access_control.range()),
                    index,
                    source,
                ));
                continue;
            }
        }
        let public_acl = keyword_value(&call.arguments, "ACL")
            .and_then(string_literal_text)
            .is_some_and(|acl| acl.starts_with("public-"))
            || call.arguments.keywords.iter().any(|keyword| {
                matches!(
                    keyword
                        .arg
                        .as_ref()
                        .map(ruff_python_ast::Identifier::as_str),
                    Some("GrantFullControl" | "GrantRead")
                ) && string_literal_text(&keyword.value)
                    .is_some_and(|grant| grant.contains(ALL_USERS_GRANT_URI))
            });
        if public_acl {
            issues.push(issue_at(
                "python:S6265",
                LEGACY_MESSAGE,
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6265_flags_public_acl_enums_on_bucket_and_deployment() {
        let flagged = concat!(
            "import aws_cdk.aws_s3 as s3\n",
            "import aws_cdk.aws_s3_deployment as s3deploy\n",
            "s3.Bucket(self, \"bucket\", access_control=s3.BucketAccessControl.PUBLIC_READ_WRITE)\n",
            "s3deploy.BucketDeployment(self, \"DeployWebsite\", access_control=s3.BucketAccessControl.PUBLIC_READ_WRITE)\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6265").len(), 2);
        let safe = concat!(
            "import aws_cdk.aws_s3 as s3\n",
            "import aws_cdk.aws_s3_deployment as s3deploy\n",
            "s3.Bucket(self, \"bucket\", access_control=s3.BucketAccessControl.PRIVATE)\n",
            "s3deploy.BucketDeployment(self, \"DeployWebsite\", access_control=s3.BucketAccessControl.PRIVATE)\n",
        );
        assert!(findings(&scan(safe), "python:S6265").is_empty());
        let unknown = concat!(
            "import aws_cdk.aws_s3 as s3\n",
            "access_policy = configured_access\n",
            "s3.Bucket(self, \"logs\", access_control=access_policy)\n",
        );
        assert!(findings(&scan(unknown), "python:S6265").is_empty());
    }

    #[test]
    fn s6265_requires_trusted_enum_and_constructor_provenance() {
        let source = concat!(
            "from aws_cdk.aws_s3 import Bucket as S3Bucket, BucketAccessControl as ACL\n",
            "S3Bucket(self, \"real\", access_control=ACL.PUBLIC_READ)\n",
            "S3Bucket = LocalBucket\n",
            "S3Bucket(self, \"local\", access_control=ACL.PUBLIC_READ)\n",
            "import aws_cdk_fake.aws_s3 as fake_s3\n",
            "fake_s3.Bucket(self, \"lookalike\", access_control=fake_s3.BucketAccessControl.PUBLIC_READ)\n",
        );
        assert_eq!(findings(&scan(source), "python:S6265").len(), 1);
    }

    #[test]
    fn s6265_preserves_legacy_acl_checks() {
        let flagged = concat!(
            "s3.put_object_acl(Bucket=\"b\", Key=\"k\", ACL=\"public-read\")\n",
            "s3.put_bucket_acl(Bucket=\"b\", GrantFullControl='uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"')\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6265").len(), 2);
        assert!(
            findings(
                &scan("s3.put_object_acl(Bucket=\"b\", Key=\"k\", ACL=\"private\")\n"),
                "python:S6265"
            )
            .is_empty()
        );
    }
}
