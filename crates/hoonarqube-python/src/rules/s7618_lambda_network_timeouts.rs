use crate::engine::file_context::FileContext;
use crate::support::AwsLambdaFacts;
use crate::support::is_none_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::nth_argument_or_keyword;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ExprCall;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7618 — network calls in Lambda need explicit timeouts ---------

const MESSAGE: &str = "Set an explicit timeout for this network call to prevent hanging executions in Lambda functions.";

/// `requests` module-level functions and `Session` methods that take a
/// `timeout` keyword (Sonar's `REQUESTS_METHODS`).
const REQUESTS_METHODS: &[&str] = &[
    "get", "post", "put", "delete", "head", "options", "patch", "request",
];

/// `boto3.client`/`boto3.resource` entry points (plus the `Session`
/// spellings) whose `config` argument accepts a `botocore.config.Config`.
const BOTO3_ENTRY_FUNCTIONS: &[&str] = &[
    "boto3.client",
    "boto3.resource",
    "boto3.Session.client",
    "boto3.Session.resource",
    "boto3.session.Session.client",
    "boto3.session.Session.resource",
];

/// Positional index of `config` in `boto3.client(...)`/`boto3.resource(...)`.
const BOTO3_CONFIG_NTH_ARGUMENT: usize = 9;

pub(crate) fn check_s7618_lambda_network_timeouts(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let lambda = AwsLambdaFacts::build(file_ctx);
    if !lambda.has_handler() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        check_requests_call(&lambda, call, index, source, &mut issues);
        check_boto3_call(&lambda, call, index, source, &mut issues);
    }
    issues
}

fn check_requests_call(
    lambda: &AwsLambdaFacts<'_>,
    call: &ExprCall,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Some(fqn) = lambda.facts.expr_fqn(&call.func) else {
        return;
    };
    let is_requests_call = REQUESTS_METHODS.iter().any(|method| {
        fqn == format!("requests.{method}")
            || fqn == format!("requests.api.{method}")
            || fqn == format!("requests.sessions.Session.{method}")
            || fqn == format!("requests.Session.{method}")
            || fqn == format!("requests.session.{method}")
    });
    if !is_requests_call {
        return;
    }
    match keyword_value(&call.arguments, "timeout") {
        // `timeout=None` disables the timeout entirely (Sonar's
        // `addIssueIf(isNone)` anchors on the whole call).
        Some(value) if is_none_literal(value) => {
            issues.push(issue_at(
                "python:S7618",
                MESSAGE,
                call.range(),
                index,
                source,
            ));
        }
        Some(_) => {}
        None => issues.push(issue_at(
            "python:S7618",
            MESSAGE,
            call.func.range(),
            index,
            source,
        )),
    }
}

fn check_boto3_call(
    lambda: &AwsLambdaFacts<'_>,
    call: &ExprCall,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Some(fqn) = lambda.facts.expr_fqn(&call.func) else {
        return;
    };
    if !BOTO3_ENTRY_FUNCTIONS.contains(&fqn.as_str()) {
        return;
    }
    let Some(config_arg) =
        nth_argument_or_keyword(&call.arguments, BOTO3_CONFIG_NTH_ARGUMENT, "config")
    else {
        issues.push(issue_at(
            "python:S7618",
            MESSAGE,
            call.func.range(),
            index,
            source,
        ));
        return;
    };
    // Only flag a `Config(...)` constructor that sets neither timeout; any
    // other expression is unknown and stays silent like the reference.
    let Expr::Call(config_call) = config_arg else {
        return;
    };
    let is_config = lambda
        .facts
        .expr_fqn(&config_call.func)
        .is_some_and(|fqn| fqn == "botocore.config.Config");
    if is_config
        && keyword_value(&config_call.arguments, "read_timeout").is_none()
        && keyword_value(&config_call.arguments, "connect_timeout").is_none()
    {
        issues.push(issue_at(
            "python:S7618",
            MESSAGE,
            call.func.range(),
            index,
            source,
        ));
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7618";

    #[test]
    fn s7618_flags_requests_call_without_timeout_in_lambda_file() {
        let source = "import requests\n\ndef lambda_handler(event, context):\n    response = requests.get('https://api.example.com/data')\n    return response.json()\n";
        let report = scan(source);
        let found = findings(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Set an explicit timeout for this network call to prevent hanging executions in Lambda functions."
        );
    }

    #[test]
    fn s7618_accepts_requests_call_with_timeout() {
        let source = "import requests\nimport os\n\ndef lambda_handler(event, context):\n    try:\n        timeout = (float(os.environ.get('CONNECT_TIMEOUT', 3)),\n                  float(os.environ.get('READ_TIMEOUT', 10)))\n        response = requests.get('https://api.example.com/data', timeout=timeout)\n        return response.json()\n    except requests.exceptions.Timeout:\n        return {'error': 'Request timed out'}\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7618_flags_explicit_none_timeout() {
        let source = "import requests\n\ndef lambda_handler(event, context):\n    return requests.get('https://x', timeout=None)\n";
        assert_eq!(findings(&scan(source), KEY).len(), 1);
    }

    #[test]
    fn s7618_flags_boto3_client_without_config() {
        let source = "import boto3\n\ns3 = boto3.client('s3')\n\ndef lambda_handler(event, context):\n    response = s3.get_object(Bucket='my-bucket', Key='my-key')\n    return response['Body'].read()\n";
        assert_eq!(findings(&scan(source), KEY).len(), 1);
    }

    #[test]
    fn s7618_accepts_boto3_client_with_timeout_config() {
        let source = "import boto3\nfrom botocore.config import Config\nfrom botocore.exceptions import ReadTimeoutError, ConnectTimeoutError\n\nconfig = Config(connect_timeout=5, read_timeout=10)\ns3 = boto3.client('s3', config=config)\n\ndef lambda_handler(event, context):\n    try:\n        response = s3.get_object(Bucket='my-bucket', Key='my-key')\n        return response['Body'].read()\n    except (ReadTimeoutError, ConnectTimeoutError):\n        return {'error': 'AWS service call timed out'}\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7618_flags_config_constructor_without_timeouts() {
        let source = "import boto3\nfrom botocore.config import Config\n\ns3 = boto3.client('s3', config=Config(retries={'max_attempts': 3}))\n\ndef lambda_handler(event, context):\n    return s3.get_object(Bucket='b', Key='k')\n";
        assert_eq!(findings(&scan(source), KEY).len(), 1);
    }

    #[test]
    fn s7618_ignores_files_without_lambda_handler() {
        let source = "import requests\n\ndef fetch():\n    return requests.get('https://api.example.com/data')\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }

    #[test]
    fn s7618_ignores_unrelated_calls() {
        let source =
            "def lambda_handler(event, context):\n    print('hello')\n    return len(event)\n";
        assert!(findings(&scan(source), KEY).is_empty());
    }
}
