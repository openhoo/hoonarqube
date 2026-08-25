use crate::engine::file_context::FileContext;
use crate::support::SECRET_ENTROPY_THRESHOLD;
use crate::support::SECRET_HIGH_ENTROPY_THRESHOLD;
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
        let secret_shaped = named && (entropy > SECRET_ENTROPY_THRESHOLD || text.len() >= 16);
        if secret_shaped {
            issues.push(Issue {
                rule_key: "python:S6418".to_string(),
                message: "Review this potentially hard-coded secret.".to_string(),
                range: to_range(literal.range(), index, source),
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
            });
        }
    }
    issues
}

// ---------------------------------------------------------------------------
// python:S6418 / python:S6437 — hard-coded secrets.
