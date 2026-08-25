use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_jwt_secret_arguments(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !matches!(
            dotted_name(&call.func).as_deref(),
            Some("jwt.encode" | "jwt.decode")
        ) {
            continue;
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
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6781_flags_hardcoded_jwt_secrets() {
        let flagged = scan("jwt.encode(payload, \"secret\")\njwt.encode(payload, key_from_env)\n");
        assert_eq!(findings(&flagged, "python:S6781").len(), 1);
    }
}
