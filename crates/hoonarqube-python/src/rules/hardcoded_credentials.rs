use crate::support::CREDENTIAL_WORDS;
use crate::support::collect_string_contents;
use crate::support::embeds_credential;
use crate::support::for_each_stmt;
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
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let (targets, value) = match stmt {
            Stmt::Assign(s) => (s.targets.as_slice(), Some(&*s.value)),
            Stmt::AnnAssign(s) => (std::slice::from_ref(&*s.target), s.value.as_deref()),
            _ => return,
        };
        let Some(Expr::StringLiteral(literal)) = value else {
            return;
        };
        if literal.value.is_empty() {
            return;
        }
        for target in targets {
            if let Expr::Name(name) = target
                && name_words(name.id.as_str()).any(|word| CREDENTIAL_WORDS.contains(&word))
            {
                issues.push(Issue {
                    rule_key: "python:S2068".to_string(),
                    message: "Review this potentially hard-coded credentials.".to_string(),
                    range: to_range(name.range(), index, source),
                });
            }
        }
    });
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        if embeds_credential(&text) {
            issues.push(Issue {
                rule_key: "python:S2068".to_string(),
                message: "Review this potentially hard-coded credentials.".to_string(),
                range: to_range(range, index, source),
            });
        }
    }
    issues
}
