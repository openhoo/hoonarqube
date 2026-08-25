use crate::engine::file_context::FileContext;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s2257_custom_cryptography(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = stmt {
            let crypto_named = function
                .name
                .as_str()
                .to_lowercase()
                .split('_')
                .any(|word| {
                    CUSTOM_CRYPTO_NAME_WORDS
                        .iter()
                        .any(|candidate| word.contains(candidate))
                });
            if crypto_named && contains_bitwise_xor(function.body.as_slice()) {
                issues.push(issue_at(
                    "python:S2257",
                    "Use a standard cryptographic library implementation instead of this hand-rolled cipher.",
                    stmt.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

// --- migrated from support/mod.rs (S2257) ---
// --- python:S2257 — custom cryptographic algorithms -----------------------------

const CUSTOM_CRYPTO_NAME_WORDS: [&str; 7] =
    ["encrypt", "decrypt", "cipher", "xor", "crypt", "rc4", "des"];

fn contains_bitwise_xor(suite: &[Stmt]) -> bool {
    let mut found = false;
    for_each_stmt_expr(suite, &mut |expr| {
        if let Expr::BinOp(binop) = expr
            && matches!(binop.op, ruff_python_ast::Operator::BitXor)
        {
            found = true;
        }
    });
    found
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2257_flags_hand_rolled_cipher_functions() {
        let flagged = concat!(
            "def xor_encrypt(data, key):\n",
            "    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S2257").len(), 1);
        let clean = "def hash_password(pw):\n    return sha256(pw).hexdigest()\n";
        assert!(findings(&scan(clean), "python:S2257").is_empty());
    }
}
