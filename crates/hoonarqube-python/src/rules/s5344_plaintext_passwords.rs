use crate::engine::file_context::FileContext;
use crate::support::CREDENTIAL_WORDS;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::name_words;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5344_plaintext_passwords(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let hashes_password = FAST_HASH_NAMES
            .contains(&called_name(&call.func).unwrap_or_default())
            && call
                .arguments
                .args
                .iter()
                .chain(call.arguments.keywords.iter().map(|keyword| &keyword.value))
                .any(|arg| matches!(arg, Expr::Name(name) if is_credential_name(name.id.as_str())));
        if hashes_password {
            issues.push(issue_at(
                "python:S5344",
                "Use a slow salted hash such as Argon2 or bcrypt for this password.",
                call.range(),
                index,
                source,
            ));
        }
    }
    for stmt in &file_ctx.stmts {
        if let Stmt::Assign(assign) = stmt {
            let plaintext = string_literal_text(&assign.value).is_some();
            for target in &assign.targets {
                if let Expr::Name(name) = target
                    && plaintext
                    && is_credential_name(name.id.as_str())
                {
                    issues.push(issue_at(
                        "python:S5344",
                        "Store this password through a secure derivation instead of plaintext.",
                        assign.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}

// --- python:S5344 — passwords not stored in plaintext or fast-hashed ----------

const FAST_HASH_NAMES: [&str; 3] = ["md5", "sha1", "sha"];

fn is_credential_name(name: &str) -> bool {
    name_words(name).any(|word| CREDENTIAL_WORDS.contains(&word))
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5344_flags_plaintext_and_fast_hashed_passwords() {
        let flagged = concat!(
            "password = \"hunter2\"\n",
            "digest = md5(password_bytes)\n",
            "h = hashlib.sha1(user_password)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S5344").len(), 3);
        let clean = concat!(
            "digest = hashlib.sha256(data)\n",
            "token = secrets.token_hex(32)\n"
        );
        assert!(findings(&scan(clean), "python:S5344").is_empty());
    }
}
