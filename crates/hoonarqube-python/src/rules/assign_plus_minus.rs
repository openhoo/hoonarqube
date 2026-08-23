use crate::support::significant_tokens;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

/// python:S2757 — `x =+ 1` / `x =- 1` non-existent operators.
pub(crate) fn check_assign_plus_minus(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let significant = significant_tokens(parsed);
    significant
        .windows(2)
        .filter(|pair| {
            pair[0].kind() == TokenKind::Equal
                && matches!(pair[1].kind(), TokenKind::Plus | TokenKind::Minus)
                && pair[1].range().start() == pair[0].range().end()
        })
        .map(|pair| {
            let sign = if pair[1].kind() == TokenKind::Plus {
                '+'
            } else {
                '-'
            };
            Issue {
                rule_key: "python:S2757".to_string(),
                message: format!("Was the '{sign}=' operator meant instead of '={sign}'?"),
                range: to_range(
                    TextRange::new(pair[0].range().start(), pair[1].range().end()),
                    index,
                    source,
                ),
            }
        })
        .collect()
}
