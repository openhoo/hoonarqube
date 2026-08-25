// --- pre-section shared items

use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::PySourceType;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::Parsed;
use ruff_python_parser::parse_unchecked_source;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

pub(crate) fn parse(source: &str) -> Parsed<ModModule> {
    parse_unchecked_source(source, PySourceType::Python)
}

pub(crate) fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

pub(crate) fn to_pos(offset: TextSize, index: &LineIndex, source: &str) -> hoonarqube_ir::Pos {
    let location = index.line_column(offset, source);
    hoonarqube_ir::Pos {
        line: to_u32(location.line.get()),
        column: to_u32(location.column.to_zero_indexed()),
    }
}

pub(crate) fn to_range(range: TextRange, index: &LineIndex, source: &str) -> hoonarqube_ir::Range {
    hoonarqube_ir::Range {
        start: to_pos(range.start(), index, source),
        end: to_pos(range.end(), index, source),
    }
}

pub(crate) fn sort_issues(issues: &mut [Issue]) {
    issues.sort_by(|a, b| {
        (
            a.range.start.line,
            a.range.start.column,
            a.range.end.line,
            a.range.end.column,
            a.rule_key.as_str(),
            a.message.as_str(),
        )
            .cmp(&(
                b.range.start.line,
                b.range.start.column,
                b.range.end.line,
                b.range.end.column,
                b.rule_key.as_str(),
                b.message.as_str(),
            ))
    });
}

/// Lines whose byte interval intersects `range`; multi-line tokens such as
/// triple-quoted strings legitimately span several lines.
pub(crate) fn covered_lines<'a>(
    range: TextRange,
    index: &'a LineIndex,
    source: &'a str,
) -> impl Iterator<Item = u32> + 'a {
    let first = to_u32(
        index
            .line_column(range.start(), source)
            .line
            .to_zero_indexed(),
    );
    let slice = &source[range];
    // A newline transitions to the next line only when characters follow it
    // inside the range; a token ending exactly at a newline stays on its line.
    let mut extra = to_u32(slice.matches('\n').count());
    if slice.ends_with('\n') && extra > 0 {
        extra -= 1;
    }
    first..=first + extra
}

pub(crate) fn file_metrics(
    parsed: &Parsed<ModModule>,
    source: &str,
    index: &LineIndex,
) -> hoonarqube_ir::FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        to_u32(source.lines().count())
    };

    let code_lines: std::collections::BTreeSet<u32> = parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia())
        .flat_map(|token| covered_lines(token.range(), index, source))
        .collect();

    let comment_lines: std::collections::BTreeSet<u32> = parsed
        .tokens()
        .iter()
        .filter(|token| token.kind().is_comment())
        .flat_map(|token| covered_lines(token.range(), index, source))
        .filter(|line| !code_lines.contains(line))
        .collect();

    hoonarqube_ir::FileMetrics {
        lines,
        code_lines: to_u32(code_lines.len()),
        comment_lines: to_u32(comment_lines.len()),
    }
}

/// Iterates `(1-based line number, line text without terminators)`.
pub(crate) fn for_each_line(source: &str, mut visit: impl FnMut(u32, &str)) {
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let text = chunk.trim_end_matches(['\r', '\n']);
        visit(to_u32(zero_based) + 1, text);
    }
}

pub(crate) fn comment_tokens(
    parsed: &Parsed<ModModule>,
) -> impl Iterator<Item = &ruff_python_ast::token::Token> {
    parsed
        .tokens()
        .iter()
        .filter(|token| token.kind() == TokenKind::Comment)
}

pub(crate) const FIXME_TAG: &str = "fixme";

pub(crate) const TODO_TAG: &str = "todo";

/// Checks the first TODO/FIXME occurrence in the comment for the person
/// reference pattern `[ ]*\([ _a-zA-Z0-9@.]+\)`.
pub(crate) fn has_person_reference(lowercased_comment: &str) -> bool {
    let Some(tag_pos) = lowercased_comment
        .find(FIXME_TAG)
        .into_iter()
        .chain(lowercased_comment.find(TODO_TAG))
        .min()
    else {
        return true;
    };
    let rest = lowercased_comment[tag_pos..]
        .trim_start_matches(|c: char| c.is_ascii_alphabetic())
        .trim_start_matches(' ');
    let Some(body) = rest.strip_prefix('(').and_then(|r| r.split_once(')')) else {
        return false;
    };
    !body.0.is_empty()
        && body
            .0
            .chars()
            .all(|c| c == '_' || c == ' ' || c == '@' || c == '.' || c.is_ascii_alphanumeric())
}

/// Validates every `noqa` occurrence in the raw comment text against
/// `# noqa` / `# noqa: E501[,F841]`.
pub(crate) fn noqa_format_valid(text: &str) -> bool {
    let lower = text.to_lowercase();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find("noqa") {
        let start = search_from + rel;
        let before = &text[..start];
        let hash_ok = match before.rfind('#') {
            Some(hash_pos) => {
                let gap = &before[hash_pos + 1..];
                !gap.is_empty() && gap.chars().all(|c| c == ' ')
            }
            None => false,
        };
        if !hash_ok {
            return false;
        }
        let after = &text[start + 4..];
        if !(after.is_empty() || after.starts_with('#')) {
            let Some(codes) = after.strip_prefix(':') else {
                return false;
            };
            for code in codes.split(',') {
                let code = code.trim();
                let valid = !code.is_empty()
                    && code
                        .chars()
                        .all(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && code.chars().any(|c: char| c.is_ascii_uppercase())
                    && code
                        .find(|c: char| c.is_ascii_digit())
                        .is_some_and(|first_digit| {
                            code[..first_digit]
                                .chars()
                                .all(|c: char| c.is_ascii_uppercase())
                        });
                if !valid {
                    return false;
                }
            }
        }
        search_from = start + 4;
    }
    true
}

/// Matches `([a-z_][a-z0-9_]*)|([A-Z][a-zA-Z0-9]+)` without a regex engine.
pub(crate) fn module_name_matches_convention(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first == '_' || first.is_ascii_lowercase() {
        name.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    } else {
        first.is_ascii_uppercase()
            && name.chars().skip(1).all(|c| c.is_ascii_alphanumeric())
            && name.len() > 1
    }
}
