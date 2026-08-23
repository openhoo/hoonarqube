use crate::support::for_each_call;
use crate::support::for_each_stmt;
use crate::support::http_verify_disabled;
use crate::support::is_false_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5527 — server hostnames verified during SSL/TLS -----------------

pub(crate) fn check_s5527_hostname_verification(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let hostname_off = http_verify_disabled(call)
            || keyword_value(&call.arguments, "check_hostname").is_some_and(is_false_literal);
        if hostname_off {
            issues.push(issue_at(
                "python:S5527",
                "Enable hostname verification for this SSL/TLS connection.",
                call.range(),
                index,
                source,
            ));
        }
    });
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::Assign(assign) = stmt {
            let sets_false = is_false_literal(&assign.value);
            for target in &assign.targets {
                if let Expr::Attribute(attr) = target
                    && attr.attr.as_str() == "check_hostname"
                    && sets_false
                {
                    issues.push(issue_at(
                        "python:S5527",
                        "Enable hostname verification for this SSL/TLS connection.",
                        assign.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}
