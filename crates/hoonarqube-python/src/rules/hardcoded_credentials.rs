use crate::engine::file_context::FileContext;
use crate::support::CREDENTIAL_WORDS;
use crate::support::collect_string_contents;
use crate::support::embeds_credential;
use crate::support::name_words;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_hardcoded_credentials(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let (targets, value, statement_range) = match stmt {
            Stmt::Assign(s) => (s.targets.as_slice(), Some(&*s.value), s.range()),
            Stmt::AnnAssign(s) => (
                std::slice::from_ref(&*s.target),
                s.value.as_deref(),
                s.range(),
            ),
            _ => continue,
        };
        let Some(Expr::StringLiteral(literal)) = value else {
            continue;
        };
        if literal.value.is_empty() {
            continue;
        }
        for target in targets {
            if let Expr::Name(name) = target
                && name_words(name.id.as_str()).any(|word| CREDENTIAL_WORDS.contains(&word))
            {
                issues.push(Issue {
                    rule_key: "python:S2068".to_string(),
                    message: format!(
                        "\"{}\" detected here, review this potentially hard-coded credential.",
                        name_words(name.id.as_str())
                            .find(|word| CREDENTIAL_WORDS.contains(word))
                            .unwrap_or("credential")
                    ),
                    range: to_range(statement_range, index, source),
                    fix: None,
                });
            }
        }
    }
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        if embeds_credential(&text) {
            issues.push(Issue {
                rule_key: "python:S2068".to_string(),
                message: "Review this potentially hard-coded credentials.".to_string(),
                range: to_range(range, index, source),
                fix: None,
            });
        }
    }
    issues
}

// ---------------------------------------------------------------------------
// python:S2068 — hard-coded credentials.

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2068_flags_credential_named_and_embedding_strings() {
        let named = scan("password = \"hunter2\"\n");
        assert_eq!(findings(&named, "python:S2068").len(), 1);
        let passwd = scan("passwd = \"s3cret\"\n");
        assert_eq!(findings(&passwd, "python:S2068").len(), 1);
        let annotated = scan("pwd: str = \"hunter2\"\n");
        assert_eq!(findings(&annotated, "python:S2068").len(), 1);
        let embedded = scan("login_url = \"https://example.test/login?password=hunter2\"\n");
        assert_eq!(findings(&embedded, "python:S2068").len(), 1);
    }

    #[test]
    fn s2068_leaves_non_credential_assignments_alone() {
        // Empty string values never carry a credential.
        assert!(findings(&scan("password = \"\"\n"), "python:S2068").is_empty());
        // Non-string values are out of scope.
        assert!(findings(&scan("password = get_password()\n"), "python:S2068").is_empty());
        // Names without credential words stay silent.
        assert!(findings(&scan("pass_hint = \"contains a digit\"\n"), "python:S2068").is_empty());
        // Prose without a `credential=`/`credential:` pattern stays silent.
        assert!(
            findings(
                &scan("help_text = \"Pass your token to log in.\"\n"),
                "python:S2068"
            )
            .is_empty()
        );
    }
}
