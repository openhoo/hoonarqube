use crate::engine::file_context::FileContext;
use crate::support::{
    Boto3Callee, WebFrameworkFacts, boto3_callee, issue_at, nth_or_keyword_arg,
    nth_or_keyword_range, resolved_string_literal,
};
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6262 — AWS region should not be set with a hardcoded String -----

const MESSAGE: &str = "AWS region should not be set with a hardcoded String";

/// `region_name` position in each boto3 client factory the reference check
/// matches (`boto3.client`/`resource`, `Session.client`/`resource`, and the
/// `Session` constructor itself).
fn region_arg_index(kind: Boto3Callee) -> usize {
    match kind {
        Boto3Callee::SessionNew => 3,
        _ => 1,
    }
}

pub(crate) fn check_s6262_hardcoded_aws_region(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(kind) = boto3_callee(&facts, call) else {
            continue;
        };
        let position = region_arg_index(kind);
        let Some(argument) = nth_or_keyword_arg(call, position, "region_name") else {
            continue;
        };
        if resolved_string_literal(&facts, argument).is_none() {
            continue;
        }
        let range =
            nth_or_keyword_range(call, position, "region_name").unwrap_or_else(|| argument.range());
        issues.push(issue_at("python:S6262", MESSAGE, range, index, source));
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6262_flags_hardcoded_regions_on_boto3_factories() {
        let flagged = concat!(
            "import boto3\n",
            "from boto3.session import Session\n",
            "boto3.client('lambda', region_name='us-west-2')\n",
            "boto3.client('lambda', 'us-west-2')\n",
            "boto3.resource('s3', 'us-west-2')\n",
            "Session(None, None, None, 'us-west-2')\n",
            "session = boto3.Session()\n",
            "session.client('ec2', 'us-west-2')\n",
            "session.resource('s3', region_name='us-west-2')\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6262").len(), 6);
    }

    #[test]
    fn s6262_flags_single_assigned_string_regions() {
        let flagged = concat!(
            "import boto3\n",
            "my_region = 'us-west-2'\n",
            "boto3.client('lambda', region_name=my_region)\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6262").len(), 1);
    }

    #[test]
    fn s6262_ignores_externalized_and_absent_regions() {
        let compliant = concat!(
            "import boto3\n",
            "import os\n",
            "region = os.environ.get('AWS_REGION', 'us-east-1')\n",
            "boto3.client('s3', region_name=region)\n",
            "boto3.client('lambda')\n",
            "boto3.client('lambda', other_argument='us-west-2')\n",
            "boto3.safe(region_name='us-west-2')\n",
            "from_os = os.environ['AWS_REGION']\n",
            "boto3.client('lambda', region_name=from_os)\n",
        );
        assert!(findings(&scan(compliant), "python:S6262").is_empty());
    }
}
