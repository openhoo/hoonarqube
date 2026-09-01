use crate::support::to_range;
use crate::support::to_u32;
use crate::support::unmasked_segments;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

/// python:InequalityUsage — the Python 2 `<>` operator.
pub(crate) fn check_py2_inequality(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (base, segment) in unmasked_segments(parsed, source) {
        for (offset, pair) in segment.as_bytes().windows(2).enumerate() {
            if pair == [b'<', b'>'] {
                let at = TextSize::from(to_u32(base + offset));
                issues.push(Issue {
                    rule_key: "python:InequalityUsage".to_string(),
                    message: "Replace \"<>\" by \"!=\".".to_string(),
                    range: to_range(TextRange::new(at, at + TextSize::new(2)), index, source),
                    fix: None,
                    flows: Vec::new(),
                });
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn inequality_usage_flags_py2_operator_outside_strings_and_comments() {
        let bad = scan("result = left <> right\n");
        assert_eq!(findings(&bad, "python:InequalityUsage").len(), 1);

        let good = scan("result = left != right\ntext = '<>'\n# <>\n");
        assert!(findings(&good, "python:InequalityUsage").is_empty());
    }
}
