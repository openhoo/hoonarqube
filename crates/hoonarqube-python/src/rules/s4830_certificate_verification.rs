use crate::support::for_each_attr_load;
use crate::support::for_each_call;
use crate::support::http_verify_disabled;
use crate::support::is_call_path;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4830 — server certificates verified during SSL/TLS --------------

pub(crate) fn check_s4830_certificate_verification(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let unverified =
            http_verify_disabled(call) || is_call_path(call, "ssl._create_unverified_context");
        if unverified {
            issues.push(issue_at(
                "python:S4830",
                "Enable certificate verification for this SSL/TLS connection.",
                call.range(),
                index,
                source,
            ));
        }
    });
    for_each_attr_load(parsed.syntax().body.as_slice(), "CERT_NONE", |attr| {
        if matches!(attr.value.as_ref(), Expr::Name(name) if name.id.as_str() == "ssl") {
            issues.push(issue_at(
                "python:S4830",
                "Enable certificate verification for this SSL/TLS connection.",
                attr.range(),
                index,
                source,
            ));
        }
    });
    issues
}
