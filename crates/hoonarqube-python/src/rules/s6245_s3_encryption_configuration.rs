use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6245 — S3 buckets should have server-side encryption ---------------

pub(crate) fn check_s6245_s3_encryption_configuration(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("create_bucket")
            && !has_keyword(&call.arguments, "ServerSideEncryptionConfiguration")
        {
            issues.push(issue_at(
                "python:S6245",
                "Enable server-side encryption for this S3 bucket.",
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
    fn s6245_requires_s3_server_side_encryption_configuration() {
        let flagged = "s3.create_bucket(Bucket=\"b\")\n";
        assert_eq!(findings(&scan(flagged), "python:S6245").len(), 1);
        assert!(findings(
                &scan("s3.create_bucket(Bucket=\"b\", ServerSideEncryptionConfiguration={\"Rules\": []})\n"),
                "python:S6245"
            )
            .is_empty());
    }
}
