use crate::engine::file_context::FileContext;
use crate::support::CREDENTIAL_WORDS;
use crate::support::CredentialInterpolation;
use crate::support::collect_string_contents;
use crate::support::embeds_credential;
use crate::support::for_each_stmt_expr;
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
                    flows: Vec::new(),
                    alternatives: Vec::new(),
                });
            }
        }
    }
    let runtime_ranges = runtime_interpolated_literal_ranges(parsed.syntax().body.as_slice());
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        let interpolation = runtime_ranges
            .iter()
            .find_map(|(literal_range, kind)| (*literal_range == range).then_some(*kind));
        if embeds_credential(&text, interpolation) {
            issues.push(Issue {
                rule_key: "python:S2068".to_string(),
                message: "Review this potentially hard-coded credentials.".to_string(),
                range: to_range(range, index, source),
                fix: None,
                flows: Vec::new(),
                alternatives: Vec::new(),
            });
        }
    }
    issues
}
fn runtime_interpolated_literal_ranges(
    stmts: &[Stmt],
) -> Vec<(ruff_text_size::TextRange, CredentialInterpolation)> {
    let mut ranges = Vec::new();
    for_each_stmt_expr(stmts, &mut |expr| match expr {
        Expr::BinOp(binary)
            if binary.op == ruff_python_ast::Operator::Mod
                && matches!(binary.left.as_ref(), Expr::StringLiteral(_)) =>
        {
            if let Expr::StringLiteral(literal) = binary.left.as_ref() {
                ranges.push((literal.range(), CredentialInterpolation::Percent));
            }
        }
        Expr::Call(call) => {
            let Expr::Attribute(attribute) = call.func.as_ref() else {
                return;
            };
            if !matches!(attribute.attr.as_str(), "format" | "format_map")
                || (call.arguments.args.is_empty() && call.arguments.keywords.is_empty())
            {
                return;
            }
            if let Expr::StringLiteral(literal) = attribute.value.as_ref() {
                ranges.push((literal.range(), CredentialInterpolation::Brace));
            }
        }
        _ => {}
    });
    ranges
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
    fn s2068_ignores_runtime_percent_placeholders_but_flags_concrete_values() {
        let literal_percent = scan("connection_string = \"host=db password=%secret\"\n");
        assert_eq!(findings(&literal_percent, "python:S2068").len(), 1);
        let literal_braces = scan("template = \"host=db password={hunter2}\"\n");
        assert_eq!(findings(&literal_braces, "python:S2068").len(), 1);
        let managed = concat!(
            "import os\n",
            "\n",
            "username = os.getenv(\"username\")\n",
            "password = os.getenv(\"password\")\n",
            "usernamePassword = \"user=%s&password=%s\" % (username, password)\n",
        );
        assert!(findings(&scan(managed), "python:S2068").is_empty());

        let concrete = scan("login_url = \"https://example.test/login?password=admin\"\n");
        assert_eq!(findings(&concrete, "python:S2068").len(), 1);
    }

    #[test]
    fn s2068_preserves_concrete_credentials_inside_formatting_expressions() {
        for source in [
            "connection = 'password=admin user=%s' % username\n",
            "connection = 'password=admin user={}' .format(username)\n",
            "connection = 'password=%secret user={}' .format(username)\n",
            "connection = 'password={secret} user=%s' % username\n",
            "connection = 'password={{secret}} user={}' .format(username)\n",
            "connection = 'password=%%secret user=%s' % username\n",
        ] {
            let report = scan(source);
            assert_eq!(findings(&report, "python:S2068").len(), 1, "{source}");
        }
        for source in [
            "connection = 'password=%s' % password\n",
            "connection = 'password={}' .format(password)\n",
            "connection = 'password={password}' .format_map(secrets)\n",
        ] {
            let report = scan(source);
            assert!(findings(&report, "python:S2068").is_empty(), "{source}");
        }
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
