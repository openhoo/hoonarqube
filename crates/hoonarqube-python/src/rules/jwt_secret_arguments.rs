use crate::engine::file_context::FileContext;
use crate::support::dotted_name_in;
use crate::support::is_static_text_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
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
        if !dotted_name_in(&call.func, &["jwt.encode", "jwt.decode"]) {
            continue;
        }
        // PyJWT HMAC keys are canonically bytes; any static text literal
        // (string or bytes) counts as a hard-coded secret.
        let key_positional = call
            .arguments
            .args
            .get(1)
            .is_some_and(is_static_text_literal);
        let key_keyword = keyword_value(&call.arguments, "key").is_some_and(is_static_text_literal);
        if key_positional || key_keyword {
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
        let flagged = scan(concat!(
            "jwt.encode(payload, \"secret\")\n",
            "jwt.encode(payload, b\"secret\")\n",
            "jwt.decode(token, key=b\"k\")\n",
            "jwt.encode(payload, key_from_env)\n",
            "jwt.decode(token, algorithms=[\"HS256\"])\n"
        ));
        assert_eq!(findings(&flagged, "python:S6781").len(), 3);
    }
}
