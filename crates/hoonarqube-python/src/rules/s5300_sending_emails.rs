use crate::support::for_each_call;
use crate::support::is_call_method;
use crate::support::is_call_path;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5300 — sending emails is security-sensitive ---------------------

pub(crate) fn check_s5300_sending_emails(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
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
    });
    issues
}
