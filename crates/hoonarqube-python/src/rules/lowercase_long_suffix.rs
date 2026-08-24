use crate::support::significant_tokens;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

/// python:LongIntegerWithLowercaseSuffixUsage — `123l` Python 2 long literal.
pub(crate) fn check_lowercase_long_suffix(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let significant = significant_tokens(parsed);
    significant
        .windows(2)
        .filter(|pair| {
            matches!(
                pair[0].kind(),
                TokenKind::Int | TokenKind::Float | TokenKind::Complex
            ) && pair[1].kind() == TokenKind::Name
                && pair[1].range().start() == pair[0].range().end()
                && &source[pair[1].range()] == "l"
        })
        .map(|pair| Issue {
            rule_key: "python:LongIntegerWithLowercaseSuffixUsage".to_string(),
            message: "Remove this lowercase 'l' suffix; it is a Python 2 long literal.".to_string(),
            range: to_range(
                TextRange::new(pair[0].range().start(), pair[1].range().end()),
                index,
                source,
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    const KEY: &str = "python:LongIntegerWithLowercaseSuffixUsage";

    #[test]
    fn long_integer_lowercase_suffix_is_flagged() {
        let flagged = scan("value = 123l\n");
        let found = findings(&flagged, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);

        // The uppercase Python 2 suffix and plain literals stay clean.
        assert!(findings(&scan("value = 123L\n"), KEY).is_empty());
        assert!(findings(&scan("value = 123\n"), KEY).is_empty());
    }
}
