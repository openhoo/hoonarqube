// Rule module s1537_tb_trailing_commas (generated).
use super::collectors::{TrailingCommaList, TrailingCommaListCollector};
use crate::support::{IssueSink, LineIndex, RuleScope, ScannedComment, to_u32};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S1537` / `S3723`: trailing commas only where the line breaks allow them.
pub(crate) fn check_tb_trailing_commas(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    comments: &[ScannedComment],
    sink: &mut IssueSink<'_>,
) {
    for list in collect_trailing_comma_lists(program, source) {
        let closer = list.container.end - 1;
        let Some(last_element) = list.last_element else {
            continue;
        };
        if !matches!(
            source.as_bytes().get(closer as usize),
            Some(b')' | b']' | b'}' | b'>')
        ) {
            continue;
        }
        let single_line = index.pos(last_element.end).line == index.pos(closer).line;
        let trailing_comma = last_significant_char(source, last_element.end, closer, comments)
            .filter(|&(_, byte)| byte == b',');
        if single_line {
            if let Some((comma_offset, _)) = trailing_comma {
                sink.emit_span(
                    RuleScope::Both,
                    "S1537",
                    "Unexpected trailing comma.",
                    Span::new(comma_offset, comma_offset + 1),
                );
            }
        } else if trailing_comma.is_none() {
            sink.emit_span(
                RuleScope::Both,
                "S3723",
                "Missing trailing comma.",
                Span::new(last_element.end, closer),
            );
        }
    }
}

fn collect_trailing_comma_lists(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
) -> Vec<TrailingCommaList> {
    let mut collector = TrailingCommaListCollector::new(source);
    collector.visit_program(program);
    collector.lists
}

/// `S1438` (skipped): automatic semicolon insertion cannot be reconstructed
/// from a tolerant parse — hazard continuations merge into one statement, so
/// any sibling-gap heuristic only fires on legitimate semicolon-free style.
/// Last non-whitespace byte inside `source[start..end]`, ignoring comment text.
/// (The skipped `S1438` rule is why no semicolon findings exist.)
fn last_significant_char(
    source: &str,
    start: u32,
    end: u32,
    comments: &[ScannedComment],
) -> Option<(u32, u8)> {
    let bytes = source.as_bytes();
    let scan = |from: u32, to: u32| -> Option<(u32, u8)> {
        bytes
            .get(from as usize..to as usize)?
            .iter()
            .enumerate()
            .rev()
            .find(|(_, byte)| !byte.is_ascii_whitespace())
            .map(|(offset, byte)| (from + to_u32(offset), *byte))
    };
    let mut best = None;
    let mut cursor = start;
    for comment in comments {
        if comment.token.start >= end {
            break;
        }
        if comment.token.end <= cursor {
            continue;
        }
        if comment.token.start > cursor {
            best = scan(cursor, comment.token.start.min(end));
        }
        cursor = cursor.max(comment.token.end);
        if cursor >= end {
            return best;
        }
    }
    if end > cursor {
        best = scan(cursor, end);
    }
    best
}
