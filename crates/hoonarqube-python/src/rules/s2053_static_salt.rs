use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::is_static_text_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::static_literal_payload_len;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2053 — unpredictable password-hashing salt ------------------------

pub(crate) fn check_s2053_static_salt(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const KDF_NAMES: [&str; 3] = ["pbkdf2_hmac", "pbkdf2_hmac_sha256", "scrypt"];
    const MINIMUM_SALT_BYTES: usize = 16;
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if !KDF_NAMES.contains(&called_name(&call.func).unwrap_or_default()) {
            return;
        }
        let positional_salt = call.arguments.args.get(2);
        let salt_expr = positional_salt.or_else(|| keyword_value(&call.arguments, "salt"));
        let short_salt = salt_expr.is_some_and(|salt| {
            is_static_text_literal(salt)
                && static_literal_payload_len(salt, source)
                    .is_some_and(|len| len < MINIMUM_SALT_BYTES)
        });
        if short_salt {
            issues.push(issue_at(
                "python:S2053",
                "Use a randomly generated salt of at least 16 bytes for this hash.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2053_flags_short_static_salts() {
        let flagged = concat!(
            "hashlib.pbkdf2_hmac(\"sha256\", pw, b\"salt\", 100000)\n",
            "hashlib.scrypt(pw, salt=b\"staticsalt\")\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S2053").len(), 2);
        let clean = concat!(
            "hashlib.pbkdf2_hmac(\"sha256\", pw, os.urandom(16), 100000)\n",
            "hashlib.pbkdf2_hmac(\"sha256\", pw, b\"a-32-byte-salt-of-random-data!!\", 100000)\n"
        );
        assert!(findings(&scan(clean), "python:S2053").is_empty());
    }
}
