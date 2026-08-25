use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3752 — HTTP routes restrict allowed methods ---------------------------

pub(crate) fn check_s3752_route_methods(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let wildcard_method = called_name(&call.func) == Some("add_route")
            && call
                .arguments
                .args
                .first()
                .and_then(string_literal_text)
                .is_some_and(|method| method == "*");
        let kitchen_sink = matches!(called_name(&call.func), Some("route" | "add_url_rule"))
            && keyword_value(&call.arguments, "methods").is_some_and(|methods| match methods {
                Expr::List(list) => list.elts.len() >= 5,
                _ => false,
            });
        if wildcard_method || kitchen_sink {
            issues.push(issue_at(
                "python:S3752",
                "Restrict this HTTP route to the methods it actually supports.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
