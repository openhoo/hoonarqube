use crate::engine::file_context::FileContext;
use crate::support::is_call_method;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5122_cors_wildcard(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_wildcard_dicts(index, source, file_ctx, &mut issues);
    flag_wildcard_calls(index, source, file_ctx, &mut issues);
    flag_wildcard_assignments(index, source, file_ctx, &mut issues);
    issues
}

fn is_wildcard(expr: &Expr) -> bool {
    string_literal_text(expr).as_deref() == Some("*")
}

fn flag_wildcard_dicts(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    for expr in &file_ctx.exprs {
        if let Expr::Dict(dict) = expr {
            for item in &dict.items {
                let Some(key) = item.key.as_ref() else {
                    continue;
                };
                if string_literal_text(key).as_deref() == Some(CORS_WILDCARD_HEADER)
                    && is_wildcard(&item.value)
                {
                    push_issue(dict.range(), index, source, issues);
                }
            }
        }
    }
}

fn flag_wildcard_calls(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    for call in &file_ctx.calls {
        if is_call_method(call, "CORS")
            && keyword_value(&call.arguments, "origins").is_some_and(is_wildcard)
        {
            push_issue(call.range(), index, source, issues);
        }
    }
}

fn flag_wildcard_assignments(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    for stmt in &file_ctx.stmts {
        if let Stmt::Assign(assign) = stmt {
            let sets_wildcard = is_wildcard(&assign.value);
            for target in &assign.targets {
                if let Expr::Subscript(subscript) = target {
                    let header = subscript.slice.as_ref();
                    if sets_wildcard
                        && string_literal_text(header).as_deref() == Some(CORS_WILDCARD_HEADER)
                    {
                        push_issue(assign.range(), index, source, issues);
                    }
                }
            }
        }
    }
}

fn push_issue(
    range: ruff_text_size::TextRange,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    issues.push(issue_at(
        "python:S5122",
        "Restrict the CORS \"Access-Control-Allow-Origin\" value to trusted origins.",
        range,
        index,
        source,
    ));
}

// --- python:S5122 — CORS policy restricted to trusted origins -----------------

const CORS_WILDCARD_HEADER: &str = "Access-Control-Allow-Origin";

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5122_flags_wildcard_cors_origins() {
        let flagged = concat!(
            "CORS(app, origins=\"*\")\n",
            "headers = {\"Access-Control-Allow-Origin\": \"*\"}\n",
            "resp.headers[\"Access-Control-Allow-Origin\"] = \"*\"\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S5122").len(), 3);
        let clean = concat!(
            "CORS(app, origins=\"https://example.com\")\n",
            "headers = {\"Access-Control-Allow-Origin\": \"https://example.com\"}\n"
        );
        assert!(findings(&scan(clean), "python:S5122").is_empty());
    }
}
