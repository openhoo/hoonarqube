use crate::support::dict_string_entry;
use crate::support::for_each_dict_literal;
use crate::support::grants_to_all_principals;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6270 — resource-based policies granting public access --------------

pub(crate) fn check_s6270_public_resource_policy(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_dict_literal(parsed.syntax().body.as_slice(), &mut |dict| {
        if dict_string_entry(dict, "Principal").is_some_and(grants_to_all_principals) {
            issues.push(issue_at(
                "python:S6270",
                "Restrict this resource policy instead of granting public access.",
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
    fn s6270_flags_wildcard_principal_policies() {
        let flagged = concat!(
            "policy = {\"Statement\": [{\"Effect\": \"Allow\", \"Principal\": \"*\",\n",
            "    \"Action\": \"s3:GetObject\"}]}\n",
            "policy2 = {\"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"*\"}}]}\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S6270").len(), 2);
        assert!(findings(
                &scan("policy = {\"Statement\": [{\"Principal\": {\"AWS\": \"arn:aws:iam::123:root\"}}]}\n"),
                "python:S6270"
            )
            .is_empty());
    }
}
