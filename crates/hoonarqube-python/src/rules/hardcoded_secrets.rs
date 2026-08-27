use crate::engine::file_context::FileContext;
use crate::support::SECRET_ENTROPY_THRESHOLD;
use crate::support::SECRET_HIGH_ENTROPY_THRESHOLD;
use crate::support::has_credential_prefix;
use crate::support::is_secret_name;
use crate::support::shannon_entropy;
use crate::support::stmt_targets;
use crate::support::string_value_text;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_hardcoded_secrets(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let value = match stmt {
            Stmt::Assign(s) => Some(&*s.value),
            Stmt::AnnAssign(s) => s.value.as_deref(),
            _ => None,
        };
        let Some(Expr::StringLiteral(literal)) = value else {
            continue;
        };
        let text = string_value_text(&literal.value);
        if text.is_empty() {
            continue;
        }
        let named = stmt_targets(stmt)
            .any(|target| matches!(target, Expr::Name(name) if is_secret_name(name.id.as_str())));
        let entropy = shannon_entropy(&text);
        let secret_shaped = named
            && (entropy > SECRET_ENTROPY_THRESHOLD
                || has_credential_prefix(&text)
                || (text.len() >= 16 && text.chars().all(|ch| ch.is_ascii_graphic())));
        if secret_shaped {
            issues.push(Issue {
                rule_key: "python:S6418".to_string(),
                message: "Review this potentially hard-coded secret.".to_string(),
                range: to_range(literal.range(), index, source),
                fix: None,
            });
        }
        let mixed = text.chars().any(|ch| ch.is_ascii_uppercase())
            && text.chars().any(|ch| ch.is_ascii_lowercase())
            && text.chars().any(|ch| ch.is_ascii_digit());
        if secret_shaped || (entropy >= SECRET_HIGH_ENTROPY_THRESHOLD && text.len() >= 20 && mixed)
        {
            issues.push(Issue {
                rule_key: "python:S6437".to_string(),
                message: "Revoke and replace this hard-coded credential with one stored securely."
                    .to_string(),
                range: to_range(literal.range(), index, source),
                fix: None,
            });
        }
    }
    issues
}

// ---------------------------------------------------------------------------
// python:S6418 / python:S6437 — hard-coded secrets.

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6418_s6437_flag_secret_named_and_high_entropy_values() {
        let named = scan("access_token = \"ghp_16charsminimum1234\"\n");
        assert_eq!(findings(&named, "python:S6418").len(), 1);
        assert_eq!(findings(&named, "python:S6437").len(), 1);
        // A credential-shaped prefix flags even low-entropy values.
        let prefixed = scan("slack_token = \"xoxb-aaaaaaaaaaaaaaaa\"\n");
        assert_eq!(findings(&prefixed, "python:S6418").len(), 1);
        assert_eq!(findings(&prefixed, "python:S6437").len(), 1);
        // The unnamed arm still catches high-entropy mixed-case blobs.
        let unnamed_blob = scan("EXAMPLE_UUID = \"A1b2C3d4E5f6G7h8I9j0KlMnOpQr\"\n");
        assert_eq!(findings(&unnamed_blob, "python:S6437").len(), 1);
        assert!(findings(&unnamed_blob, "python:S6418").is_empty());
    }

    #[test]
    fn s6418_s6437_skip_prose_paths_and_low_entropy_samples() {
        assert!(
            findings(
                &scan("author = \"Conference keynote recording, part twelve\"\n"),
                "python:S6418"
            )
            .is_empty()
        );
        assert!(
            findings(
                &scan("tokenizer_vocab = \"/models/bert-base-uncased/vocab\"\n"),
                "python:S6418"
            )
            .is_empty()
        );
        // Short low-entropy text stays silent even under a credential name.
        assert!(findings(&scan("password_hint = \"too short\"\n"), "python:S6418").is_empty());
        // Repetitive mixed-case blobs lack the entropy the unnamed arm needs.
        assert!(
            findings(
                &scan("demo_data = \"AbcAbcAbcAbcAbc12345\"\n"),
                "python:S6437"
            )
            .is_empty()
        );
    }
}
