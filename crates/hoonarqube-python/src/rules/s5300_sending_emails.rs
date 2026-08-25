use crate::engine::file_context::FileContext;
use crate::support::is_call_method;
use crate::support::is_call_path;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5300 — sending emails is security-sensitive ---------------------

pub(crate) fn check_s5300_sending_emails(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let sends = is_call_path(call, "smtplib.SMTP")
            || is_call_method(call, "SMTP")
            || is_call_method(call, "sendmail")
            || is_call_method(call, "send_message");
        if sends {
            issues.push(issue_at(
                "python:S5300",
                "Make sure that sending emails is safe here.",
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
    fn s5300_flags_email_sending_apis() {
        let flagged = concat!(
            "client = smtplib.SMTP(host)\n",
            "client.sendmail(sender, to, msg)\n",
            "server.send_message(msg)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S5300").len(), 3);
        assert!(findings(&scan("sock.sendall(b\"x\")\n"), "python:S5300").is_empty());
    }
}
