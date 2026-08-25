use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2115 — secure database password ----------------------------------

pub(crate) fn check_s2115_empty_database_password(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const PASSWORD_KWARGS: [&str; 3] = ["password", "passwd", "pwd"];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let empty_password = PASSWORD_KWARGS.iter().any(|flag| {
            keyword_value(&call.arguments, flag)
                .and_then(string_literal_text)
                .is_some_and(|text| text.is_empty())
        });
        if empty_password {
            issues.push(issue_at(
                "python:S2115",
                "Replace this empty database password with a secure one.",
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
    fn s2115_flags_empty_database_passwords() {
        let flagged = concat!(
            "psycopg2.connect(dsn, password=\"\")\n",
            "mysql.connector.connect(passwd=\"\")\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S2115").len(), 2);
        assert!(
            findings(
                &scan("psycopg2.connect(dsn, password=\"s3cret\")\n"),
                "python:S2115"
            )
            .is_empty()
        );
    }
}
