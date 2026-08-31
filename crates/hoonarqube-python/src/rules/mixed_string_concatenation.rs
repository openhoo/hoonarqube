use crate::support::is_bytes_literal;
use crate::support::significant_tokens;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S5799 — implicit concatenation mixing str and bytes literals.
pub(crate) fn check_mixed_string_concatenation(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let is_string = |kind: TokenKind| kind == TokenKind::String;
    let significant = significant_tokens(parsed);
    let mut issues = Vec::new();
    for pair in significant.windows(2) {
        if is_string(pair[0].kind())
            && is_string(pair[1].kind())
            && is_bytes_literal(&source[pair[0].range()])
                != is_bytes_literal(&source[pair[1].range()])
        {
            issues.push(Issue {
                rule_key: "python:S5799".to_string(),
                message: "Implicitly concatenating str and bytes literals fails at runtime; merge them explicitly.".to_string(),
                range: to_range(pair[1].range(), index, source),
                fix: None,
                flows: Vec::new(),
            });
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5799_flags_implicit_str_bytes_concatenation() {
        let bad = scan("mixed = 'text' b'bytes'\n");
        assert_eq!(findings(&bad, "python:S5799").len(), 1);

        let good = scan("text = 'first' 'second'\ndata = b'first' b'second'\n");
        assert!(findings(&good, "python:S5799").is_empty());
    }
}
