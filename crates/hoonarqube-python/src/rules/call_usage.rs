use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_call_usage(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    identifier: &str,
    rule_key: &str,
    message: &str,
) -> Vec<Issue> {
    let significant: Vec<&ruff_python_ast::token::Token> = parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia())
        .collect();
    significant
        .windows(2)
        .filter(|pair| {
            pair[0].kind() == TokenKind::Name
                && &source[pair[0].range()] == identifier
                && pair[1].kind() == TokenKind::Lpar
        })
        .map(|pair| Issue {
            rule_key: rule_key.to_string(),
            message: message.to_string(),
            range: to_range(pair[0].range(), index, source),
        })
        .collect()
}
