use crate::engine::file_context::FileContext;
use crate::support::cookie_flag_missing;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_cookie_flag(
    index: &LineIndex,
    source: &str,
    rule_key: &str,
    message: &str,
    flag: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if cookie_flag_missing(call, flag) {
            issues.push(issue_at(rule_key, message, call.range(), index, source));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s3330_accepts_non_literal_httponly_argument() {
        // Issue #618: Sonar treats any present httponly kwarg as
        // compliant — a variable or expression argument is not a
        // violation (django/django cookie.py:115 shape).
        let clean = concat!(
            "resp.set_cookie(\"k\", \"v\", httponly=settings.SESSION_COOKIE_HTTPONLY or None)\n",
            "resp.set_cookie(\"k\", \"v\", httponly=True)\n",
            "resp.set_cookie(\"k\", \"v\", httponly=False)\n",
        );
        assert!(findings(&scan(clean), "python:S3330").is_empty());

        // Only a missing httponly argument reports.
        let flagged = "resp.set_cookie(\"k\", \"v\")\n";
        let report = scan(flagged);
        let found = findings(&report, "python:S3330");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
        assert_eq!(found[0].range.start.column, 0);
    }
}
