use crate::engine::file_context::FileContext;
use crate::support::{
    Boto3Callee, WebFrameworkFacts, boto3_callee, issue_at, nth_or_keyword_arg,
    nth_or_keyword_range, resolved_string_literal,
};
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7625 — long-term AWS access keys should not be used in code -----

const ACCESS_KEY_MESSAGE: &str = "Make sure using long-term access keys is safe here.";
const SECRET_KEY_MESSAGE: &str = "Make sure using long-term secret keys is safe here.";

/// Positional index of `aws_access_key_id` for each boto3 factory the
/// reference check matches (`aws_secret_access_key` follows it).
fn access_key_index(kind: Boto3Callee) -> usize {
    match kind {
        Boto3Callee::SessionNew => 0,
        _ => 6,
    }
}

pub(crate) fn check_s7625_aws_long_term_access_keys(
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
        let position = access_key_index(kind);
        // The reference reports at most one argument per call: the access
        // key wins over the secret key when both are long-term literals.
        let flagged = [
            (position, "aws_access_key_id", ACCESS_KEY_MESSAGE),
            (position + 1, "aws_secret_access_key", SECRET_KEY_MESSAGE),
        ]
        .into_iter()
        .find(|(position, name, _)| {
            nth_or_keyword_arg(call, *position, name)
                .and_then(|argument| resolved_string_literal(&facts, argument))
                .is_some()
        });
        if let Some((position, name, message)) = flagged {
            let range = nth_or_keyword_range(call, position, name).unwrap_or_else(|| call.range());
            issues.push(issue_at("python:S7625", message, range, index, source));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, findings_of, scan};

    #[test]
    fn s7625_flags_literal_access_keys_on_boto3_factories() {
        let flagged = concat!(
            "import boto3\n",
            "boto3.client('s3', aws_access_key_id='EXAMPLE-ACCESS-KEY-ID',\n",
            "    aws_secret_access_key='EXAMPLE-SECRET-ACCESS-KEY')\n",
            "boto3.resource('s3', aws_access_key_id='EXAMPLE-ACCESS-KEY-ID')\n",
            "boto3.client('s3', None, None, None, None, None,\n",
            "    'EXAMPLE-ACCESS-KEY-ID', 'EXAMPLE-SECRET-ACCESS-KEY')\n",
            "boto3.Session('EXAMPLE-ACCESS-KEY-ID', 'EXAMPLE-SECRET-ACCESS-KEY')\n",
            "session = boto3.session.Session()\n",
            "session.client('ec2', aws_secret_access_key='EXAMPLE-SECRET-ACCESS-KEY')\n",
        );
        let found = findings_of(flagged, "python:S7625");
        assert_eq!(found.len(), 5);
        assert_eq!(
            found[0],
            "Make sure using long-term access keys is safe here."
        );
        assert_eq!(
            found[4],
            "Make sure using long-term secret keys is safe here."
        );
    }

    #[test]
    fn s7625_flags_single_assigned_string_keys() {
        let flagged = concat!(
            "import boto3\n",
            "access_key = 'EXAMPLE-ACCESS-KEY-ID'\n",
            "boto3.client('lambda', aws_access_key_id=access_key)\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S7625").len(), 1);
    }

    #[test]
    fn s7625_ignores_temporary_and_externalized_credentials() {
        let compliant = concat!(
            "import boto3\n",
            "import os\n",
            "boto3.client('s3')\n",
            "boto3.resource('s3', aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),\n",
            "    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))\n",
            "credentials = sts_client.assume_role(RoleArn=arn, RoleSessionName='s')['Credentials']\n",
            "boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'],\n",
            "    aws_secret_access_key=credentials['SecretAccessKey'],\n",
            "    aws_session_token=credentials['SessionToken'])\n",
            "key = get_temporary_credentials()\n",
            "boto3.client('s3', aws_access_key_id=key, aws_secret_access_key=key)\n",
            "def handler(access_key, secret_key):\n",
            "    boto3.client('s3', aws_access_key_id=access_key,\n",
            "        aws_secret_access_key=secret_key)\n",
        );
        assert!(findings(&scan(compliant), "python:S7625").is_empty());
    }
}
