use crate::engine::file_context::FileContext;
use crate::support::dict_string_entry;
use crate::support::for_each_dict_literal;
use crate::support::has_boto3_binding;
use crate::support::includes_wildcard;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6302 — policies granting all privileges -----------------------------

pub(crate) fn check_s6302_all_privileges_policy(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    // CE only evaluates policies in files with a resolvable boto3 binding;
    // stub-only files stay silent.
    if !has_boto3_binding(&file_ctx.calls) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for_each_dict_literal(parsed.syntax().body.as_slice(), &mut |dict| {
        if dict_string_entry(dict, "Action").is_some_and(includes_wildcard) {
            issues.push(issue_at(
                "python:S6302",
                "Scope this policy's actions instead of granting all privileges.",
                dict.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6302_flags_wildcard_action_policies_with_boto3_binding() {
        let flagged = concat!(
            "client = boto3.resource(\"iam\")\n",
            "p1 = {\"Action\": \"*\"}\n",
            "p2 = {\"Action\": [\"s3:*\", \"ec2:RunInstances\"]}\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S6302").len(), 1);
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
