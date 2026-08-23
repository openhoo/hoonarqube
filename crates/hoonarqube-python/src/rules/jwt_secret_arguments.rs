use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_jwt_secret_arguments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if !matches!(
            dotted_name(&call.func).as_deref(),
            Some("jwt.encode" | "jwt.decode")
        ) {
            return;
        }
        let key_positional = call.arguments.args.get(1).and_then(string_literal_text);
        let key_keyword = keyword_value(&call.arguments, "key").and_then(string_literal_text);
        if let Some(secret) = key_positional.or(key_keyword) {
            drop(secret);
            issues.push(issue_at(
                "python:S6781",
                "Do not hard-code this JWT secret key.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
