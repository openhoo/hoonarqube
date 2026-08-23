use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::is_false_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6303 — RDS resources encrypted at rest ------------------------------

pub(crate) fn check_s6303_rds_encryption(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const RDS_CREATORS: [&str; 2] = ["create_db_instance", "create_db_cluster"];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let unencrypted = RDS_CREATORS.contains(&called_name(&call.func).unwrap_or_default())
            && (!has_keyword(&call.arguments, "StorageEncrypted")
                || keyword_value(&call.arguments, "StorageEncrypted")
                    .is_some_and(is_false_literal));
        if unencrypted {
            issues.push(issue_at(
                "python:S6303",
                "Encrypt this RDS resource at rest.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
