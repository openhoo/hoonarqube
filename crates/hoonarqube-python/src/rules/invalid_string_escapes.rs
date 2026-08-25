use crate::support::for_each_stmt_expr;
use crate::support::invalid_escape_offsets;
use crate::support::to_range;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

/// python:S1717 — invalid escape sequences in non-raw string literals.
pub(crate) fn check_invalid_string_escapes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
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
                    let at = part_range.start() + TextSize::from(to_u32(offset));
                    let escaped = raw[offset + 1..].chars().next().unwrap_or('?');
                    issues.push(Issue {
                        rule_key: "python:S1717".to_string(),
                        message: format!("Escape this backslash or make the string raw; '\\{escaped}' is not a recognized escape sequence."),
                        range: to_range(TextRange::new(at, at + TextSize::new(1)), index, source),
                    });
                }
            }
        }
    });
    issues
}
