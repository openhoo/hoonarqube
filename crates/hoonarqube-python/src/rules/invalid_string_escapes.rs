use crate::engine::file_context::FileContext;
use crate::support::invalid_escape_offsets;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;

/// python:S1717 — invalid escape sequences in non-raw string literals.
pub(crate) fn check_invalid_string_escapes(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::StringLiteral(literal) = expr {
            // Check each concatenation part independently: a raw-suffixed
            // part must not suppress scanning of adjacent non-raw parts.
            for part in &literal.value {
                if matches!(
                    part.flags.prefix(),
                    ruff_python_ast::str_prefix::StringLiteralPrefix::Raw { .. }
                ) {
                    continue;
                }
                let part_range =
                    ruff_text_size::TextRange::new(part.range.start(), part.range.end());
                let raw = &source[part_range];
                for offset in invalid_escape_offsets(raw) {
                    let _ = offset;
                    issues.push(Issue {
                        rule_key: "python:S1717".to_string(),
                        message: "Remove this \"\\\", add another \"\\\" to escape it, or make this a raw string.".to_string(),
                        range: to_range(part_range, index, source),
                        fix: None,
                        flows: Vec::new(),
                    });
                }
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s1717_flags_non_raw_with_invalid_escape() {
        let flagged = scan("msg = \"bad \\q escape\"\n");
        assert!(!findings(&flagged, "python:S1717").is_empty());
    }

    #[test]
    fn s1717_raw_string_is_clean() {
        let flagged = scan("msg = r\"bad \\q escape\"\n");
        assert!(findings(&flagged, "python:S1717").is_empty());
    }

    #[test]
    fn s1717_implicit_concat_checks_each_part() {
        let flagged = scan("msg = r\"\\d\\w\" \"\\q\"\n");
        assert!(!findings(&flagged, "python:S1717").is_empty());
    }
}
