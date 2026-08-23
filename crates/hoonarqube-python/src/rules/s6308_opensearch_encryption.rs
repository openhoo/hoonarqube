use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6308 — OpenSearch domains encrypted at rest --------------------------

pub(crate) fn check_s6308_opensearch_encryption(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const DOMAIN_CREATORS: [&str; 2] = ["create_domain", "create_elasticsearch_domain"];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if DOMAIN_CREATORS.contains(&called_name(&call.func).unwrap_or_default())
            && !has_keyword(&call.arguments, "EncryptionAtRestOptions")
        {
            issues.push(issue_at(
                "python:S6308",
                "Enable encryption at rest for this OpenSearch domain.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
