use crate::support::to_range;
use crate::support::to_u32;
use crate::support::unmasked_segments;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

// ---------------------------------------------------------------------------
// Python 2 relics and token-level operator confusion.
// ---------------------------------------------------------------------------

/// python:BackticksUsage — backtick `repr()` quoting.
pub(crate) fn check_py2_backticks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (base, segment) in unmasked_segments(parsed, source) {
        for (offset, ch) in segment.char_indices() {
            if ch == '`' {
                let at = TextSize::from(to_u32(base + offset));
                issues.push(Issue {
                    rule_key: "python:BackticksUsage".to_string(),
                    message: "Replace the backtick quoting with a call to repr().".to_string(),
                    range: to_range(TextRange::new(at, at + TextSize::new(1)), index, source),
                });
            }
        }
    }
    issues
}
