//! Native JS/TS quick fixes and IDE suggestions.
//!
//! The upstream `SonarJS` rules expose edits from the IDE analyzer rather than
//! from the server.  This module keeps the edit surface next to the native
//! analyzer: every remedy is derived from the finding's source span, and a
//! suggestion is emitted only when the local syntax gives us the same safe
//! shape as the upstream rule.  In particular, an unavailable type checker is
//! never replaced by a guess.

mod bindings;
mod expressions;
mod typed_regex;

use crate::context::AnalysisContext;
use crate::project_context::{SemanticQuickfixAction, SemanticSpan};
use crate::support::to_u32;
use hoonarqube_ir::{Fix, Issue, TextEdit};
use oxc_span::Span;
pub(super) type RawEdit = (usize, usize, String);
type NativeFix = (String, Vec<RawEdit>);

pub(super) struct Candidate {
    pub(super) id: &'static str,
    pub(super) message: &'static str,
    pub(super) edits: Vec<RawEdit>,
}

pub(crate) fn attach(ctx: &AnalysisContext<'_>, issues: &mut [Issue]) {
    if issues.is_empty() {
        return;
    }
    attach_child_candidates(ctx, issues);
    attach_semantic_fixes(ctx, issues);
    attach_native_fixes(ctx, issues);
}

fn attach_child_candidates(ctx: &AnalysisContext<'_>, issues: &mut [Issue]) {
    let Some(semantic) = ctx.semantic else {
        return;
    };
    let mut child_candidates = Vec::new();
    child_candidates.extend(expressions::collect(ctx, semantic, issues));
    child_candidates.extend(bindings::collect(ctx, semantic, issues));
    child_candidates.extend(typed_regex::collect(ctx, semantic, issues));
    for (index, candidate) in child_candidates {
        let Some(issue) = issues.get_mut(index) else {
            continue;
        };
        let checker_backed = ctx.semantic_facts.is_some()
            && issue
                .rule_key
                .rsplit(':')
                .next()
                .and_then(checker_rule_key)
                .is_some();
        if checker_backed {
            continue;
        }
        add_candidate(ctx, issue, candidate);
    }
}

fn add_candidate(ctx: &AnalysisContext<'_>, issue: &mut Issue, candidate: Candidate) {
    let edits = candidate
        .edits
        .into_iter()
        .map(|edit| text_edit(ctx, edit))
        .collect();
    issue.add_alternative(candidate.id, candidate.message, edits);
}

fn attach_native_fixes(ctx: &AnalysisContext<'_>, issues: &mut [Issue]) {
    for issue in issues {
        let Some((start, end)) = issue_offsets(ctx, issue) else {
            continue;
        };
        let Some(rule) = issue.rule_key.rsplit(':').next() else {
            continue;
        };
        if let Some((message, edits)) = match rule {
            "S1264" => s1264(ctx.source, start, end),
            "S1488" => s1488(ctx.source, start, end),
            _ => None,
        } {
            issue.fix = Some(Fix::new(
                message,
                edits.into_iter().map(|edit| text_edit(ctx, edit)).collect(),
            ));
            continue;
        }
        let candidates = match rule {
            "S125" => s125(ctx.source, start, end),
            "S1110" => s1110(ctx.source, start, end),
            "S3626" => s3626(ctx.source, start, end),
            "S3972" => s3972(ctx.source, start, end),
            _ => Vec::new(),
        };
        for candidate in candidates {
            add_candidate(ctx, issue, candidate);
        }
    }
}

fn checker_rule_key(rule: &str) -> Option<&'static str> {
    match rule {
        "S1125" => Some("S1125"),
        "S2871" => Some("S2871"),
        "S4043" => Some("S4043"),
        "S4322" => Some("S4322"),
        "S4623" => Some("S4623"),
        "S4782" => Some("S4782"),
        "S6439" => Some("S6439"),
        "S6594" => Some("S6594"),
        "S6759" => Some("S6759"),
        _ => None,
    }
}

fn attach_semantic_fixes(ctx: &AnalysisContext<'_>, issues: &mut [Issue]) {
    let Some(file) = ctx.semantic_facts else {
        return;
    };
    for issue in issues {
        let Some(rule) = issue.rule_key.rsplit(':').next().and_then(checker_rule_key) else {
            continue;
        };
        let Some((start, end)) = issue_offsets(ctx, issue) else {
            continue;
        };
        let subject_span = SemanticSpan {
            start: to_u32(start),
            end: to_u32(end),
        };
        for fact in file.facts.quickfixes_for(rule, subject_span) {
            for action in &fact.actions {
                let Some(edits) = semantic_action_edits(ctx, action) else {
                    continue;
                };
                issue.add_alternative(action.id.clone(), action.message.clone(), edits);
            }
        }
    }
}

fn semantic_action_edits(
    ctx: &AnalysisContext<'_>,
    action: &SemanticQuickfixAction,
) -> Option<Vec<TextEdit>> {
    if action.id.is_empty() || action.edits.is_empty() {
        return None;
    }
    let mut bounds = Vec::with_capacity(action.edits.len());
    for edit in &action.edits {
        let start = usize::try_from(edit.span.start).ok()?;
        let end = usize::try_from(edit.span.end).ok()?;
        if start > end
            || end > ctx.source.len()
            || !ctx.source.is_char_boundary(start)
            || !ctx.source.is_char_boundary(end)
        {
            return None;
        }
        bounds.push((start, end));
    }
    bounds.sort_unstable();
    if bounds.windows(2).any(|pair| {
        let (left_start, left_end) = pair[0];
        let (right_start, right_end) = pair[1];
        if left_start == left_end && right_start == right_end {
            left_start == right_start
        } else if left_start == left_end {
            left_start >= right_start && left_start < right_end
        } else if right_start == right_end {
            right_start >= left_start && right_start < left_end
        } else {
            left_start.max(right_start) < left_end.min(right_end)
        }
    }) {
        return None;
    }
    action
        .edits
        .iter()
        .map(|edit| {
            Some(TextEdit {
                range: ctx.index.range(Span::new(edit.span.start, edit.span.end)),
                replacement: edit.replacement.clone(),
            })
        })
        .collect()
}

pub(super) fn issue_offsets(ctx: &AnalysisContext<'_>, issue: &Issue) -> Option<(usize, usize)> {
    if issue.range.start.line == 0 || issue.range.end.line == 0 {
        return None;
    }
    Some((
        offset_for_pos(ctx, issue.range.start)?,
        offset_for_pos(ctx, issue.range.end)?,
    ))
}

fn offset_for_pos(ctx: &AnalysisContext<'_>, pos: hoonarqube_ir::Pos) -> Option<usize> {
    let line = usize::try_from(pos.line).ok()?.checked_sub(1)?;
    let line_start = *ctx.index.line_starts.get(line)? as usize;
    let rest = ctx.source.get(line_start..)?;
    let column = usize::try_from(pos.column).ok()?;
    Some(rest.char_indices().nth(column).map_or_else(
        || line_start + rest.len(),
        |(offset, _)| line_start + offset,
    ))
}

fn text_edit(ctx: &AnalysisContext<'_>, edit: RawEdit) -> TextEdit {
    TextEdit {
        range: ctx.index.range(Span::new(to_u32(edit.0), to_u32(edit.1))),
        replacement: edit.2,
    }
}

pub(super) fn candidate(
    id: &'static str,
    message: &'static str,
    edits: impl IntoIterator<Item = RawEdit>,
) -> Candidate {
    Candidate {
        id,
        message,
        edits: edits.into_iter().collect(),
    }
}

fn source_slice(source: &str, start: usize, end: usize) -> Option<&str> {
    source.get(start..end)
}

fn line_bounds(source: &str, offset: usize) -> (usize, usize) {
    let start = source[..offset.min(source.len())]
        .rfind('\n')
        .map_or(0, |at| at + 1);
    let end = source[offset.min(source.len())..]
        .find('\n')
        .map_or(source.len(), |at| offset.min(source.len()) + at);
    (start, end)
}

fn matching(source: &str, open: usize, open_char: u8, close_char: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open).copied()? != open_char {
        return None;
    }
    let mut depth = 0_u32;
    let mut quote = 0_u8;
    let mut escaped = false;
    let mut i = open;
    while i < bytes.len() {
        let byte = bytes[i];
        if quote != 0 {
            (quote, escaped) = advance_quoted(byte, quote, escaped);
            i += 1;
            continue;
        }
        if let Some(next_quote) = quote_start(byte) {
            quote = next_quote;
            i += 1;
            continue;
        }
        if byte == open_char {
            depth += 1;
        } else if byte == close_char {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn advance_quoted(byte: u8, quote: u8, escaped: bool) -> (u8, bool) {
    if escaped {
        (quote, false)
    } else if byte == b'\\' {
        (quote, true)
    } else if byte == quote {
        (0, false)
    } else {
        (quote, false)
    }
}

fn quote_start(byte: u8) -> Option<u8> {
    match byte {
        b'\'' | b'"' | b'`' => Some(byte),
        _ => None,
    }
}

fn trim_range(source: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end && source.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && source.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

fn identifier_end(source: &str, start: usize) -> usize {
    let mut end = start;
    for (offset, ch) in source[start..].char_indices() {
        if !(ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()) {
            break;
        }
        end = start + offset + ch.len_utf8();
    }
    end
}

fn s1264(source: &str, start: usize, end: usize) -> Option<NativeFix> {
    let text = source_slice(source, start, end)?;
    let for_at = text.find("for")? + start;
    let open = source[for_at..end].find('(')? + for_at;
    let close = matching(source, open, b'(', b')')?;
    let inside = source.get(open + 1..close)?.trim();
    let condition = if inside.starts_with(';') {
        inside.trim_start_matches(';').trim_end_matches(';').trim()
    } else {
        inside
    };
    if condition.is_empty() || condition.contains(';') {
        return None;
    }
    Some((
        "Replace this \"for\" loop with a \"while\" loop.".to_owned(),
        vec![(for_at, close + 1, format!("while ({condition})"))],
    ))
}

fn s1488(source: &str, start: usize, end: usize) -> Option<NativeFix> {
    let (line_start, _) = line_bounds(source, start);
    let keyword = ["const ", "let ", "var "]
        .iter()
        .filter_map(|prefix| {
            source[line_start..start]
                .rfind(prefix)
                .map(|at| line_start + at)
        })
        .max()?;
    let after_keyword = keyword + source[keyword..].find(char::is_whitespace)?;
    let name_start =
        after_keyword + source[after_keyword..].len() - source[after_keyword..].trim_start().len();
    let name_end = identifier_end(source, name_start);
    if name_end == name_start {
        return None;
    }
    let equals = source[name_end..start.max(name_end)].find('=')? + name_end;
    let init_start =
        equals + 1 + source[equals + 1..].len() - source[equals + 1..].trim_start().len();
    let semi = source[end..].find(';').map(|at| end + at)?;
    let init_end = trim_range(source, init_start, semi).1;
    if init_end <= init_start
        || source[init_start..init_end].contains("//")
        || source[init_start..init_end].contains("/*")
    {
        return None;
    }
    let after = semi + 1;
    let action_start = after + source[after..].len() - source[after..].trim_start().len();
    let action = if source[action_start..].starts_with("return ") {
        "return"
    } else if source[action_start..].starts_with("throw ") {
        "throw"
    } else {
        return None;
    };
    let returned_start = action_start + action.len() + 1;
    let returned_start = returned_start + source[returned_start..].len()
        - source[returned_start..].trim_start().len();
    let returned_end = identifier_end(source, returned_start);
    if source.get(returned_start..returned_end)? != source.get(name_start..name_end)? {
        return None;
    }
    let message = format!(
        "Immediately {action} this expression instead of assigning it to the temporary variable \"{}\".",
        &source[name_start..name_end]
    );
    Some((
        message,
        vec![
            (keyword, action_start, String::new()),
            (
                returned_start,
                returned_end,
                source[init_start..init_end].to_owned(),
            ),
        ],
    ))
}

fn s125(source: &str, start: usize, end: usize) -> Vec<Candidate> {
    if end > start
        && source
            .get(start..end)
            .is_some_and(|text| text.starts_with("//") || text.starts_with("/*"))
    {
        vec![candidate(
            "s125-remove-commented-code",
            "Remove this commented out code",
            [(start, end, String::new())],
        )]
    } else {
        Vec::new()
    }
}

fn s1110(source: &str, start: usize, end: usize) -> Vec<Candidate> {
    if source.as_bytes().get(start) != Some(&b'(')
        || source.as_bytes().get(end.saturating_sub(1)) != Some(&b')')
    {
        return Vec::new();
    }
    let before = source[..start].trim_end();
    let after = source[end..].trim_start();
    if ["if", "while", "switch", "with", "catch"]
        .iter()
        .any(|keyword| before.ends_with(keyword))
        || after.starts_with("=>")
    {
        return Vec::new();
    }
    vec![candidate(
        "s1110-remove-parentheses",
        "Remove these redundant parentheses",
        [
            (start, start + 1, String::new()),
            (end - 1, end, String::new()),
        ],
    )]
}

fn s3626(source: &str, start: usize, end: usize) -> Vec<Candidate> {
    let Some(jump) = source_slice(source, start, end) else {
        return Vec::new();
    };
    if jump.trim_start().starts_with("break") {
        return Vec::new();
    }
    let mut remove_start = start;
    while remove_start > 0 && source.as_bytes()[remove_start - 1].is_ascii_whitespace() {
        remove_start -= 1;
    }
    vec![candidate(
        "s3626-remove-redundant-jump",
        "Remove this redundant jump",
        [(remove_start, end, String::new())],
    )]
}

fn s3972(source: &str, start: usize, end: usize) -> Vec<Candidate> {
    let (line_start, _) = line_bounds(source, start);
    let prefix = source[..start].trim_end();
    let Some(text) = source_slice(source, start, end) else {
        return Vec::new();
    };
    if !text.trim_start().starts_with("if") {
        return Vec::new();
    }
    let Some(previous_rel) = prefix.rfind('}') else {
        return Vec::new();
    };
    let previous = previous_rel + 1;
    let indent = source[line_start..start]
        .chars()
        .take_while(|ch| ch.is_whitespace())
        .collect::<String>();
    vec![
        candidate(
            "s3972-add-else",
            "Add \"else\" keyword",
            [(start, start, "else ".to_owned())],
        ),
        candidate(
            "s3972-move-if-new-line",
            "Move this \"if\" to a new line",
            [(previous, start, format!("\n{indent}"))],
        ),
    ]
}
