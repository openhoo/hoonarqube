use crate::engine::file_context::FileContext;
use crate::support::WebFrameworkFacts;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::resolves_to_aws_client;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7609 — CloudWatch metric namespaces must not start with AWS/ -----

const RULE_KEY: &str = "python:S7609";
const MESSAGE: &str =
    "Do not use AWS reserved namespace that begins with 'AWS/' for custom metrics.";

/// python:S7609 — `put_metric_data` on a boto3/aiobotocore client whose
/// `Namespace` argument is a string literal (or a name singly assigned one)
/// beginning with `AWS/` collides with AWS's reserved namespaces. Sonar
/// anchors the issue on the whole `Namespace=...` argument.
pub(crate) fn check_s7609_cloudwatch_metric_namespace(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) != Some("put_metric_data") {
            continue;
        }
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            continue;
        };
        if !resolves_to_aws_client(&facts, &attribute.value) {
            continue;
        }
        let Some(keyword) = call
            .arguments
            .keywords
            .iter()
            .find(|keyword| keyword.arg.as_deref() == Some("Namespace"))
        else {
            continue;
        };
        let value = match &keyword.value {
            Expr::Name(name) => facts
                .strict_single_assignment(name.id.as_str(), name.range())
                .map(|(value, _)| value),
            other => Some(other),
        };
        let is_reserved = value
            .and_then(string_literal_text)
            .is_some_and(|text| text.starts_with("AWS/"));
        if is_reserved {
            issues.push(issue_at(RULE_KEY, MESSAGE, keyword.range(), index, source));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7609";

    #[test]
    fn s7609_flags_aws_prefixed_namespaces() {
        let flagged = scan(concat!(
            "import boto3\n",
            "cloudwatch = boto3.client('cloudwatch')\n",
            "cloudwatch.put_metric_data(Namespace='AWS/MyCustomService', MetricData=[])\n",
            "ns = 'AWS/Lambda/Custom'\n",
            "cloudwatch.put_metric_data(Namespace=ns, MetricData=[])\n",
        ));
        let issues = findings(&flagged, KEY);
        assert_eq!(issues.len(), 2);
        assert_eq!(
            issues[0].message,
            "Do not use AWS reserved namespace that begins with 'AWS/' for custom metrics."
        );
    }

    #[test]
    fn s7609_spares_custom_and_missing_namespaces() {
        let compliant = scan(concat!(
            "import boto3\n",
            "cloudwatch = boto3.client('cloudwatch')\n",
            "cloudwatch.put_metric_data(Namespace='MyApp/CustomService', MetricData=[])\n",
            "cloudwatch.put_metric_data(MetricData=[])\n",
            "cloudwatch.put_metric_data(Namespace=compute_namespace())\n",
        ));
        assert!(findings(&compliant, KEY).is_empty());
    }

    #[test]
    fn s7609_flags_aiobotocore_clients() {
        let flagged = scan(concat!(
            "import aiobotocore.session\n",
            "async def publish_metrics():\n",
            "    session = aiobotocore.session.get_session()\n",
            "    client = session.create_client('cloudwatch')\n",
            "    await client.put_metric_data(Namespace='AWS/Lambda/Custom', MetricData=[])\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 1);
    }

    #[test]
    fn s7609_spares_unknown_receivers() {
        let quiet = scan("metrics.put_metric_data(Namespace='AWS/Foo')\n");
        assert!(findings(&quiet, KEY).is_empty());
    }
}
