use crate::support::ends_operand;
use crate::support::significant_tokens;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

/// python:PreIncrementDecrement — `++x` / `--x` parsed as double unary ops.
pub(crate) fn check_pre_increment_decrement(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let significant = significant_tokens(parsed);
    let mut issues = Vec::new();
    for index_in_list in 1..significant.len().saturating_sub(1) {
        let current = significant[index_in_list];
        let next = significant[index_in_list + 1];
        let previous = significant[index_in_list - 1];
        let doubled = (current.kind() == TokenKind::Plus && next.kind() == TokenKind::Plus)
            || (current.kind() == TokenKind::Minus && next.kind() == TokenKind::Minus);
        if doubled
            && next.range().start() == current.range().end()
            && !ends_operand(previous, source)
            && let Some(operand) = significant.get(index_in_list + 2)
        {
            let operation = if current.kind() == TokenKind::Plus {
                "pre-increment"
            } else {
                "pre-decrement"
            };
            issues.push(Issue {
                rule_key: "python:PreIncrementDecrement".to_string(),
                message: format!(
                    "This statement doesn't produce the expected result, replace use of non-existent {operation} operator"
                ),
                range: to_range(
                    TextRange::new(current.range().start(), operand.range().end()),
                    index,
                    source,
                ),
                fix: None,
            });
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn pre_increment_decrement_flags_adjacent_double_unary_signs() {
        let bad = scan("first = ++value\nsecond = --value\n");
        assert_eq!(findings(&bad, "python:PreIncrementDecrement").len(), 2);

        let good = scan("first = value + 1\nsecond = value - 1\n");
        assert!(findings(&good, "python:PreIncrementDecrement").is_empty());
    }
}
