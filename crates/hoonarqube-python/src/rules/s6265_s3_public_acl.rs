use crate::support::ALL_USERS_GRANT_URI;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6265_s3_public_acl(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let public_acl = keyword_value(&call.arguments, "ACL")
            .and_then(string_literal_text)
            .is_some_and(|acl| acl.starts_with("public-"))
            || call.arguments.keywords.iter().any(|keyword| {
                matches!(
                    keyword
                        .arg
                        .as_ref()
                        .map(ruff_python_ast::Identifier::as_str),
                    Some("GrantFullControl" | "GrantRead")
                ) && string_literal_text(&keyword.value)
                    .is_some_and(|grant| grant.contains(ALL_USERS_GRANT_URI))
            });
        if public_acl {
            issues.push(issue_at(
                "python:S6265",
                "Do not grant this S3 bucket access to all users.",
                call.range(),
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
    fn s6265_flags_public_acl_and_all_users_grants() {
        let flagged = concat!(
            "s3.put_object_acl(Bucket=\"b\", Key=\"k\", ACL=\"public-read\")\n",
            "s3.put_bucket_acl(Bucket=\"b\", GrantFullControl='uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"')\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S6265").len(), 2);
        assert!(
            findings(
                &scan("s3.put_object_acl(Bucket=\"b\", Key=\"k\", ACL=\"private\")\n"),
                "python:S6265"
            )
            .is_empty()
        );
    }
}
