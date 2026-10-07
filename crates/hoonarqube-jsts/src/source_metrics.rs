//! JS/TS comment measures shared with project source-fact collection.
use crate::support::{LineIndex, to_u32};
use oxc_span::Span;
use std::collections::BTreeSet;

pub(crate) fn first_code_token_start(tokens: &[oxc_parser::Token]) -> Option<usize> {
    tokens
        .iter()
        .find(|token| {
            !matches!(
                token.kind(),
                oxc_parser::Kind::Eof | oxc_parser::Kind::Skip | oxc_parser::Kind::HashbangComment
            )
        })
        .map(|token| token.start() as usize)
}

/// Counts comment lines from already parsed byte ranges, without reparsing.
///
/// Ranges include the comment delimiters and must address `source`. Comments
/// before the first code token are headers and do not contribute. If there is
/// no code token, nonempty comments still contribute. Nonempty block comments
/// contribute every covered row, including decoration and blank interior rows;
/// a row containing code and a comment contributes to both metrics.
/// Empty comments and comments beginning with `NOSONAR` are excluded.
///
/// Invalid ranges and non-comment ranges are ignored. Callers retain their own
/// parse/completeness state; this metric cannot certify successful analysis.
#[must_use]
pub fn comment_line_count(
    source: &str,
    comment_ranges: &[(usize, usize)],
    first_token_start: Option<usize>,
) -> u32 {
    let index = LineIndex::new(source);
    let mut rows = BTreeSet::new();
    for &(start, end) in comment_ranges {
        if start >= end || first_token_start.is_some_and(|first| end <= first) {
            continue;
        }
        let Some(text) = source.get(start..end) else {
            continue;
        };
        let body = if let Some(body) = text.strip_prefix("//") {
            body
        } else if let Some(body) = text.strip_prefix("/*") {
            body.strip_suffix("*/").unwrap_or(body)
        } else {
            continue;
        };
        // Sonar removes the first JSDoc marker before trimming; remaining
        // stars inside a block are content, as they are in the parser value.
        let value = body.strip_prefix('*').unwrap_or(body).trim();
        if value.is_empty() || value.to_ascii_uppercase().starts_with("NOSONAR") {
            continue;
        }
        rows.extend(index.covered_lines(Span::new(to_u32(start), to_u32(end))));
    }
    to_u32(rows.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::scan_comments;

    fn measure(source: &str, first: Option<usize>) -> u32 {
        let ranges: Vec<_> = scan_comments(source)
            .iter()
            .map(|comment| (comment.token.start as usize, comment.token.end as usize))
            .collect();
        comment_line_count(source, &ranges, first)
    }

    #[test]
    fn counts_mixed_code_comment_rows_and_full_nonempty_blocks() {
        let source = "const x = 1; // trailing note\n/* body\n\n *\n */\n// last note\n";
        assert_eq!(measure(source, Some(0)), 6);
    }

    #[test]
    fn ignores_headers_empty_bodies_and_nosonar_tokens() {
        let source = "/** header */\n// header too\nconst x = 1;\n//\n/* */\n/**/\n/***/\n// nosonar deliberate\n/* NOSONAR\nreason */\n// ordinary note\n";
        assert_eq!(measure(source, source.find("const")), 1);
    }

    #[test]
    fn comment_only_source_has_no_header_token_to_exclude() {
        assert_eq!(measure("// note\n/* body\n */\n", None), 3);
        assert_eq!(measure("//\n/**/\n", None), 0);
    }

    #[test]
    fn deduplicates_comment_ranges_on_the_same_row() {
        assert_eq!(measure("const x = 1; /* one */ /* two */\n", Some(0)), 1);
    }

    #[test]
    fn honors_ecmascript_line_breaks_and_invalid_byte_ranges() {
        assert_eq!(
            measure(
                "x(); // one\r// two\u{2028}// three\u{2029}// four",
                Some(0)
            ),
            4
        );
        let source = "x(); // é";
        assert_eq!(
            comment_line_count(
                source,
                &[(5, source.len()), (9, 10), (10, 9), (0, 4)],
                Some(0)
            ),
            1
        );
    }

    #[test]
    fn directives_are_code_tokens_before_later_comments() {
        let report = crate::test_support::js("\"use strict\";\n// after directive\nconst x = 1;\n");
        assert_eq!(report.metrics.comment_lines, 1);
    }

    #[test]
    fn empty_source_still_has_one_physical_line() {
        for report in [crate::test_support::js(""), crate::test_support::ts("")] {
            assert_eq!(report.metrics.lines, 1);
            assert_eq!(report.metrics.code_lines, 0);
            assert_eq!(report.metrics.comment_lines, 0);
        }
    }

    #[test]
    fn analyzer_uses_the_shared_comment_metric() {
        let report =
            crate::test_support::js("/** header */\nconst x = 1; // trailing\n/* body\n */\n");
        assert_eq!(report.metrics.comment_lines, 3);
    }
}
