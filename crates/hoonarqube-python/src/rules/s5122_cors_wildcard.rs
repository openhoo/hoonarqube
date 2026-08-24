use crate::support::CORS_WILDCARD_HEADER;
use crate::support::for_each_call;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::is_call_method;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5122_cors_wildcard(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let wildcard = |expr: &Expr| string_literal_text(expr).as_deref() == Some("*");
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Dict(dict) = expr {
            for item in &dict.items {
                let Some(key) = item.key.as_ref() else {
                    continue;
                };
                if string_literal_text(key).as_deref() == Some(CORS_WILDCARD_HEADER)
                    && wildcard(&item.value)
                {
                    issues.push(issue_at(
                        "python:S5122",
                        "Restrict the CORS \"Access-Control-Allow-Origin\" value to trusted origins.",
                        dict.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if is_call_method(call, "CORS")
            && keyword_value(&call.arguments, "origins").is_some_and(&wildcard)
        {
            issues.push(issue_at(
                "python:S5122",
                "Restrict the CORS \"Access-Control-Allow-Origin\" value to trusted origins.",
                call.range(),
                index,
                source,
            ));
        }
    });
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::Assign(assign) = stmt {
            let sets_wildcard = wildcard(&assign.value);
            for target in &assign.targets {
                if let Expr::Subscript(subscript) = target {
                    let header = subscript.slice.as_ref();
                    if sets_wildcard
                        && string_literal_text(header).as_deref() == Some(CORS_WILDCARD_HEADER)
                    {
                        issues.push(issue_at(
                            "python:S5122",
                            "Restrict the CORS \"Access-Control-Allow-Origin\" value to trusted origins.",
                            assign.range(),
                            index,
                            source,
                        ));
                    }
                }
            }
        }
    });
    issues
}

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
