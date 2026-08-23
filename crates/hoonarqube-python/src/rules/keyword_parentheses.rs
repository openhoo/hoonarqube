use crate::support::significant_tokens;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S1721 — parentheses right after `assert`, `del`, `return`, `yield`.
/// `print` is deliberately excluded: in Python 3 it is a regular function,
/// so `print(x)` is an ordinary call, not a relic.
pub(crate) fn check_keyword_parentheses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const PAREN_KEYWORDS: [&str; 4] = ["assert", "del", "return", "yield"];
    let significant = significant_tokens(parsed);
    significant
        .windows(2)
        .filter(|pair| {
            pair[0].kind() == TokenKind::Name
                && PAREN_KEYWORDS.contains(&&source[pair[0].range()])
                && pair[1].kind() == TokenKind::Lpar
                && pair[1].range().start() == pair[0].range().end()
        })
        .map(|pair| {
            let keyword = &source[pair[0].range()];
            Issue {
                rule_key: "python:S1721".to_string(),
                message: format!("Remove the parentheses after '{keyword}'."),
                range: to_range(pair[0].range(), index, source),
            }
        })
        .collect()
}
