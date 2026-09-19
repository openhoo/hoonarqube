use crate::engine::file_context::FileContext;
use crate::support::WebFrameworkFacts;
use crate::support::is_boto3_client_method_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7622 — paginated boto3 operations need paginators -------------

const MESSAGE: &str = "Use a paginator to retrieve all results from this boto3 operation.";

/// `botocore.client.BaseClient` operations whose results are paginated
/// (Sonar's `SENSITIVE_METHODS_FQNS`, method names only).
const PAGINATED_METHODS: &[&str] = &["list_objects_v2", "scan"];

pub(crate) fn check_s7622_boto3_pagination(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if PAGINATED_METHODS
            .iter()
            .any(|method| is_boto3_client_method_call(&facts, call, method))
        {
            issues.push(issue_at(
                "python:S7622",
                MESSAGE,
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

    const KEY: &str = "python:S7622";

    #[test]
    fn s7622_flags_unpaginated_list_objects_v2() {
        let source = "import boto3\ns3 = boto3.client(\"s3\")\n\ndef lambda_handler(event, context):\n    keys = []\n    response = s3.list_objects_v2(Bucket=\"my-bucket\")\n    for obj in response.get(\"Contents\", []):\n        keys.append(obj[\"Key\"])\n    return keys\n";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Use a paginator to retrieve all results from this boto3 operation."
        );
    }

    #[test]
    fn s7622_accepts_paginator_usage() {
        let source = "import boto3\ns3 = boto3.client(\"s3\")\n\ndef lambda_handler(event, context):\n    keys = []\n    paginator = s3.get_paginator(\"list_objects_v2\")\n    for page in paginator.paginate(Bucket=\"my-bucket\"):\n        for obj in page.get(\"Contents\", []):\n            keys.append(obj[\"Key\"])\n    return keys\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7622_flags_scan_and_works_outside_handlers() {
        let source = "import boto3\ndynamodb = boto3.client(\"dynamodb\")\n\ndef collect():\n    return dynamodb.scan(TableName=\"t\")\n";
        assert_eq!(findings(&scan(source), KEY).len(), 1);
    }

    #[test]
    fn s7622_ignores_non_client_receivers() {
        let source =
            "def lambda_handler(event, context):\n    return event.list_objects_v2(Bucket=\"b\")\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }
}
