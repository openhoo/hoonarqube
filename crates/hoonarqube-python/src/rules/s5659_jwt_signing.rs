use std::path::Path;

use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::has_keyword;
use crate::support::is_call_method;
use crate::support::is_test_scope_file;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5659 — JWT signed and verified -------------------------------------

pub(crate) fn check_s5659_jwt_signing(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    path: &Path,
) -> Vec<Issue> {
    // Catalog scope MAIN: the reference platform never reports on test files.
    if is_test_scope_file(path) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        // JWT-library provenance. The reference check resolves the callee to
        // the `jwt`/`jose.jwt` module functions; without type inference the
        // resolved import binding decides, and a receiver spelled `jwt` is
        // the textual fallback so unimported single-file snippets stay
        // decidable. Ordinary `bytes.decode`-style calls never qualify.
        let jwt_context = matches!(
            file_ctx.known_bindings.resolve_call(call),
            KnownBinding::JwtEncode | KnownBinding::JwtDecode
        ) || matches!(&*call.func, Expr::Attribute(attribute)
            if matches!(&*attribute.value, Expr::Name(name) if name.id.as_str() == "jwt"));
        if !jwt_context {
            continue;
        }
        let unsigned = is_call_method(call, "encode")
            && keyword_value(&call.arguments, "algorithm")
                .and_then(string_literal_text)
                .is_some_and(|algorithm| algorithm == "none");
        let unverified =
            is_call_method(call, "decode") && !has_keyword(&call.arguments, "algorithms");
        if unsigned || unverified {
            issues.push(issue_at(
                "python:S5659",
                "Sign this JWT with a strong algorithm and verify it on decode.",
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
    fn s5659_flags_unsigned_and_unverified_jwt() {
        let flagged = concat!(
            "t = jwt.encode(p, k, algorithm=\"none\")\n",
            "c = jwt.decode(t, k)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S5659").len(), 2);
        let clean = concat!(
            "t = jwt.encode(p, k, algorithm=\"HS256\")\n",
            "c = jwt.decode(t, k, algorithms=[\"HS256\"])\n"
        );
        assert!(findings(&scan(clean), "python:S5659").is_empty());
    }

    #[test]
    fn s5659_ignores_non_jwt_decode_calls() {
        // Ordinary bytes.decode calls carry no JWT context.
        let ordinary = scan("def f(b):\n    return b.decode('utf-8')\n");
        assert!(findings(&ordinary, "python:S5659").is_empty());

        // A locally defined bare decode() is not a JWT decode either.
        let local = scan("def decode(p):\n    return p\n\ntoken = decode(payload)\n");
        assert!(findings(&local, "python:S5659").is_empty());

        // JWT module provenance keeps the rule firing.
        let imported = scan("import jwt\n\ntoken = jwt.decode(payload)\n");
        assert_eq!(findings(&imported, "python:S5659").len(), 1);
        let from_import = scan("from jwt import decode\n\ntoken = decode(payload)\n");
        assert_eq!(findings(&from_import, "python:S5659").len(), 1);
    }
}
