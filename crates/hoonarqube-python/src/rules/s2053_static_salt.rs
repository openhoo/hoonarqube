use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::is_static_text_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2053 — unpredictable password-hashing salt ------------------------

pub(crate) fn check_s2053_static_salt(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const KDF_NAMES: [&str; 3] = ["pbkdf2_hmac", "pbkdf2_hmac_sha256", "scrypt"];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !KDF_NAMES.contains(&called_name(&call.func).unwrap_or_default()) {
            continue;
        }
        let positional_salt = call.arguments.args.get(2);
        let salt_expr = positional_salt.or_else(|| keyword_value(&call.arguments, "salt"));
        let static_salt = salt_expr.is_some_and(is_static_text_literal);
        if static_salt {
            issues.push(issue_at(
                "python:S2053",
                "Use a randomly generated salt of at least 16 bytes for this hash.",
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
    fn s2053_flags_short_static_salts() {
        let flagged = concat!(
            "hashlib.pbkdf2_hmac(\"sha256\", pw, b\"salt\", 100000)\n",
            "hashlib.scrypt(pw, salt=b\"staticsalt\")\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S2053").len(), 2);
        let clean = concat!(
            "hashlib.pbkdf2_hmac(\"sha256\", pw, os.urandom(16), 100000)\n",
            "def derive(password, salt):\n",
            "    return hashlib.scrypt(password, salt=salt)\n"
        );
        assert!(findings(&scan(clean), "python:S2053").is_empty());
    }

    #[test]
    fn s2053_flags_constant_salts_regardless_of_byte_length() {
        let flagged = concat!(
            "hashlib.scrypt(password, salt=b\"F3MdWpeHeeSjlUxvKBnzzA\")\n",
            "hashlib.pbkdf2_hmac(\n",
            "    \"sha256\", password, b\"0123456789abcdef0123456789abcdef0123456789\", 100000\n",
            ")\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S2053").len(), 2);

        let clean = concat!(
            "hashlib.pbkdf2_hmac(\"sha256\", password, os.urandom(32), 100000)\n",
            "def derive(password, salt):\n",
            "    return hashlib.scrypt(password, salt=salt)\n"
        );
        assert!(findings(&scan(clean), "python:S2053").is_empty());
    }
}
