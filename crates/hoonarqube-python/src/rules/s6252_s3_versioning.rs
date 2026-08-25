use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6252 — S3 buckets should have versioning enabled -------------------

pub(crate) fn check_s6252_s3_versioning(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("put_bucket_versioning")
            && !has_keyword(&call.arguments, "VersioningConfiguration")
        {
            issues.push(issue_at(
                "python:S6252",
                "Enable versioning for this S3 bucket.",
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
    fn s6252_requires_s3_versioning_configuration() {
        let flagged = "s3.put_bucket_versioning(Bucket=\"b\")\n";
        assert_eq!(findings(&scan(flagged), "python:S6252").len(), 1);
        assert!(findings(
                &scan("s3.put_bucket_versioning(Bucket=\"b\", VersioningConfiguration={\"Status\": \"Enabled\"})\n"),
                "python:S6252"
            )
            .is_empty());
    }
}
