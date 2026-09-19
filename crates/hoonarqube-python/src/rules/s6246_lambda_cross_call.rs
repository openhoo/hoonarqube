use crate::engine::file_context::FileContext;
use crate::support::{
    Boto3Callee, WebFrameworkFacts, boto3_callee, in_lambda_handler, is_client_receiver, issue_at,
    keyword_value, lambda_handler_ranges, resolved_string_literal,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6246 — Lambdas should not invoke other lambdas synchronously ----

const MESSAGE: &str = "Avoid synchronous calls to other lambdas";

/// Whether `expr` produces a boto3 client (`botocore.client.BaseClient` in
/// the reference's type model): a `boto3.client`/`<session>.client` call, or
/// a name whose visible assignments all produce one.
fn is_boto3_client(facts: &WebFrameworkFacts<'_>, expr: &Expr, call: &ExprCall) -> bool {
    match expr {
        Expr::Call(inner) => matches!(
            boto3_callee(facts, inner),
            Some(Boto3Callee::Client | Boto3Callee::SessionClient)
        ),
        Expr::Name(name) => is_client_receiver(facts, name.id.as_str(), call.range()),
        _ => false,
    }
}

pub(crate) fn check_s6246_lambda_cross_call(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let handlers = lambda_handler_ranges(&facts);
    if handlers.is_empty() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            continue;
        };
        if attribute.attr.as_str() != "invoke"
            || !is_boto3_client(&facts, &attribute.value, call)
            || !in_lambda_handler(&facts, &handlers, call.range())
        {
            continue;
        }
        let synchronous = keyword_value(&call.arguments, "InvocationType")
            .and_then(|value| resolved_string_literal(&facts, value))
            .is_some_and(|value| value == "RequestResponse");
        if synchronous {
            issues.push(issue_at(
                "python:S6246",
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

    #[test]
    fn s6246_flags_request_response_invocation_inside_handlers() {
        let flagged = concat!(
            "import boto3\n",
            "client = boto3.client('lambda')\n",
            "def lambda_handler(event, context):\n",
            "    client.invoke(InvocationType='RequestResponse')\n",
            "    local = boto3.client('lambda')\n",
            "    local.invoke(InvocationType='RequestResponse')\n",
            "    boto3.client('lambda').invoke(InvocationType='RequestResponse')\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6246").len(), 3);
    }

    #[test]
    fn s6246_ignores_async_and_untyped_invocations() {
        let compliant = concat!(
            "import boto3\n",
            "client = boto3.client('lambda')\n",
            "def lambda_handler(event, context):\n",
            "    client.invoke(InvocationType='Event')\n",
            "    client.invoke(FunctionName='target')\n",
            "    other = 'something else'\n",
            "    other.invoke(InvocationType='RequestResponse')\n",
            "def not_a_lambda():\n",
            "    client.invoke(InvocationType='RequestResponse')\n",
            "client.invoke(InvocationType='RequestResponse')\n",
        );
        assert!(findings(&scan(compliant), "python:S6246").is_empty());
    }

    #[test]
    fn s6246_resolves_single_assigned_invocation_type() {
        let flagged = concat!(
            "import boto3\n",
            "client = boto3.client('lambda')\n",
            "def lambda_handler(event, context):\n",
            "    mode = 'RequestResponse'\n",
            "    client.invoke(InvocationType=mode)\n",
        );
        assert_eq!(findings(&scan(flagged), "python:S6246").len(), 1);
    }
}
