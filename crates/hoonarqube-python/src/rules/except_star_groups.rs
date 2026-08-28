use crate::support::issue_at;
use crate::support::significant_tokens;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6468 — except* on ExceptionGroup --------------------------------------

pub(crate) fn check_except_star_groups(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let significant = significant_tokens(parsed);
    let mut issues = Vec::new();
    for (position, window) in significant.windows(2).enumerate() {
        let except_star = window[0].kind() == TokenKind::Except
            && window[1].kind() == TokenKind::Star
            && window[1].range().start() == window[0].range().end();
        if !except_star {
            continue;
        }
        let caught_group = significant[position + 2..]
            .iter()
            .take_while(|token| {
                !matches!(
                    token.kind(),
                    TokenKind::Newline | TokenKind::NonLogicalNewline
                )
            })
            .find(|token| {
                token.kind() == TokenKind::Name
                    && matches!(
                        &source[token.range()],
                        "ExceptionGroup" | "BaseExceptionGroup"
                    )
            });
        if let Some(group) = caught_group {
            issues.push(issue_at(
                "python:S6468",
                "Avoid catching ExceptionGroup exception with 'except*'",
                group.range(),
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
    fn s6468_flags_except_star_on_exception_groups() {
        let flagged = scan("try:\n    pass\nexcept* ExceptionGroup:\n    pass\n");
        assert_eq!(findings(&flagged, "python:S6468").len(), 1);
    }
}
