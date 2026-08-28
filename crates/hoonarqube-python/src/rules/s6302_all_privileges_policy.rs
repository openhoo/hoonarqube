use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::wildcard_literal;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6302 — policies granting all privileges -----------------------------

pub(crate) fn check_s6302_all_privileges_policy(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    // SonarPython scopes this rule to AWS CDK PolicyStatement calls.
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("PolicyStatement")
            && let Some(wildcard) =
                keyword_value(&call.arguments, "actions").and_then(wildcard_literal)
        {
            issues.push(issue_at(
                "python:S6302",
                "Make sure granting all privileges is safe here.",
                wildcard.range(),
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
    fn s6302_spares_boto3_policy_dictionaries() {
        let flagged = concat!(
            "client = boto3.resource(\"iam\")\n",
            "p1 = {\"Action\": \"*\"}\n",
            "p2 = {\"Action\": [\"s3:*\", \"ec2:RunInstances\"]}\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S6302").len(), 0);
        // Without a resolvable boto3 binding the file stays silent (CE parity).
        let stub_only =
            scan("p1 = {\"Action\": \"*\"}\np2 = {\"Action\": [\"s3:*\", \"ec2:RunInstances\"]}\n");
        assert!(findings(&stub_only, "python:S6302").is_empty());
        assert!(
            findings(
                &scan(concat!(
                    "client = boto3.resource(\"iam\")\n",
                    "p3 = {\"Action\": [\"s3:GetObject\"]}\n"
                )),
                "python:S6302"
            )
            .is_empty()
        );
    }
}
