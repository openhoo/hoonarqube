use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
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
        if !matches!(
            file_ctx.known_bindings.resolve_call(call),
            KnownBinding::JwtEncode | KnownBinding::JwtDecode
        ) {
            continue;
        }
        let key_positional = call.arguments.args.get(1);
        let key_keyword = keyword_value(&call.arguments, "key");
        if key_positional
            .into_iter()
            .chain(key_keyword)
            .any(|key| file_ctx.known_bindings.is_static_text(key))
        {
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
    fn s6781_flags_literal_and_constant_bound_jwt_secrets() {
        let flagged = scan(concat!(
            "import jwt\n",
            "secret = \"secret\"\n",
            "jwt.encode(payload, \"secret\")\n",
            "jwt.encode(payload, b\"secret\")\n",
            "jwt.encode(payload, secret)\n",
            "jwt.decode(token, key=b\"k\")\n",
            "jwt.encode(payload, key_from_env)\n"
        ));
        assert_eq!(findings(&flagged, "python:S6781").len(), 4);
    }

    #[test]
    fn s6781_preserves_runtime_keys_and_lookalike_calls() {
        let safe = scan(concat!(
            "import jwt\n",
            "import os\n",
            "secret = os.environ['JWT_SECRET']\n",
            "jwt.encode(payload, secret)\n"
        ));
        assert!(findings(&safe, "python:S6781").is_empty());

        let lookalike = scan("jwt = object()\njwt.encode(payload, \"secret\")\n");
        assert!(findings(&lookalike, "python:S6781").is_empty());
    }
}
