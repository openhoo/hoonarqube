//! IDE quick-fix alternatives for the Python analyzer.
//!
//! These are alternatives, never the automatic `Issue::fix`.  The rule
//! implementations retain the finding and this post-pass only attaches an
//! edit when the finding's source span contains the exact lexical shape used
//! by the pinned `SonarPython` quick-fix contract.  Rules whose upstream fix
//! needs symbol/type/CFG information that the local finding does not carry are
//! intentionally left without a fix.
pub(crate) mod bindings;
mod frameworks;
mod operators;
mod regex;
mod type_fixes;

use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::{AnyImport, FileContext};
use crate::engine::scope::{
    BindingKind, ScopeKind, SymbolTable, build_symbol_table, collect_file_facts, scope_is_within,
};
use crate::support::{for_each_stmt, parse, ranges_textually_equal, suite_span, to_range, to_u32};
use hoonarqube_ir::{Issue, TextEdit};
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtIf};
use ruff_python_parser::Parsed;
use ruff_source_file::{LineIndex, LineRanges, OneIndexed, PositionEncoding, SourceLocation};
use ruff_text_size::{Ranged, TextRange, TextSize};
use std::collections::HashSet;

struct Alternative {
    id: String,
    message: String,
    edits: Vec<TextEdit>,
}
pub(crate) fn attach_quick_fixes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issues: &mut [Issue],
) {
    for issue in issues {
        let alternatives = match issue.rule_key.as_str() {
            "python:S1244" | "python:S5795" | "python:S5796" | "python:S5799" => {
                operators::alternatives(parsed, index, source, file_ctx, issue)
            }
            "python:S5915" | "python:S6735" | "python:S6929" | "python:S6969" | "python:S6971"
            | "python:S7489" => frameworks::alternatives(parsed, index, source, file_ctx, issue),
            "python:BackticksUsage" => backticks(issue, index, source, file_ctx),
            "python:S139" => s139(issue, index, source),
            "python:S1110" => s1110(parsed, issue, index, source),
            "python:S1131" => s1131(issue, index, source),
            "python:S1186" => s1186(issue, index, source),
            "python:S1720" => s1720(parsed, issue, index, source),
            "python:S1940" => s1940(issue, index, source),
            "python:S2710" => s2710(parsed, issue, index, source),
            "python:S2772" | "python:S3626" => remove_line(issue, index, source),
            "python:S3923" => s3923(parsed, issue, index, source),
            "python:S3984" => s3984(issue, index, source),
            "python:S4144" => s4144(issue, index, source),
            "python:S5712" => s5712(issue, index, source),
            "python:S5713" => s5713(issue, index, source),
            "python:S5714" => s5714(issue, index, source),
            "python:S5717" => s5717(issue, index, source),
            "python:S5719" => s5719(issue, index, source),
            "python:S5754" => s5754(issue, index, source),
            "python:S5905" => s5905(parsed, index, source, file_ctx, issue),
            "python:S6326" => s6326(issue, index, source),
            "python:S6353" => regex::alternatives(parsed, index, source, file_ctx, issue),
            "python:S6395" => s6395(issue, index, source),
            "python:S6397" => s6397(issue, index, source),
            "python:S6538" | "python:S6545" | "python:S6552" | "python:S6978" | "python:S7500" => {
                type_fixes::alternatives(parsed, index, source, file_ctx, issue)
            }
            "python:S6553" => s6553(issue, index, source),
            "python:S6725" => s6725(issue, index, source),
            "python:S6727" => s6727(issue, index, source),
            "python:S6729" => s6729(issue, index, source),
            "python:S6730" => s6730(issue, index, source),
            "python:S6741" => s6741(issue, index, source),
            "python:S7486" => s7486(issue, index, source),
            "python:S7488" => s7488(issue, index, source, file_ctx),
            "python:S7491" => s7491(issue, index, source),
            "python:S7498" => s7498(issue, index, source),
            "python:S7501" => s7501(issue, index, source),
            "python:S7504" => s7504(issue, index, source),
            "python:S7508" => s7508(issue, index, source),
            "python:S7517" => s7517(issue, index, source),
            _ => Vec::new(),
        };
        attach(issue, alternatives);
    }
}

fn attach(issue: &mut Issue, alternatives: Vec<Alternative>) {
    let mut ids = HashSet::new();
    for alternative in alternatives {
        if ids.insert(alternative.id.clone()) {
            issue.add_alternative(alternative.id, alternative.message, alternative.edits);
        }
    }
}

fn issue_range(issue: &Issue, index: &LineIndex, source: &str) -> TextRange {
    TextRange::new(
        offset(issue.range.start, index, source),
        offset(issue.range.end, index, source),
    )
}

fn offset(pos: hoonarqube_ir::Pos, index: &LineIndex, source: &str) -> TextSize {
    if pos.line == 0 {
        return TextSize::default();
    }
    index.offset(
        SourceLocation {
            line: OneIndexed::from_zero_indexed(pos.line.saturating_sub(1) as usize),
            character_offset: OneIndexed::from_zero_indexed(pos.column as usize),
        },
        source,
        PositionEncoding::Utf32,
    )
}

fn text_edit(
    index: &LineIndex,
    source: &str,
    range: TextRange,
    replacement: impl Into<String>,
) -> TextEdit {
    TextEdit {
        range: to_range(range, index, source),
        replacement: replacement.into(),
    }
}

fn alt(id: impl Into<String>, message: impl Into<String>, edits: Vec<TextEdit>) -> Alternative {
    Alternative {
        id: id.into(),
        message: message.into(),
        edits,
    }
}
fn backticks(
    issue: &Issue,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    if file_ctx.known_bindings.resolve_name_at("repr", range) != KnownBinding::BuiltinRepr {
        return Vec::new();
    }
    let start = range.start().to_usize();
    let end = range.end().to_usize();
    let Some(text) = source.get(start..end) else {
        return Vec::new();
    };
    let Some(inner) = text
        .strip_prefix('`')
        .and_then(|text| text.strip_suffix('`'))
    else {
        return Vec::new();
    };
    if inner.trim().is_empty() || inner.contains('`') {
        return Vec::new();
    }
    let candidate = format!("__sonar_backtick = ({inner})");
    let parsed = parse(&candidate);
    if !parsed.errors().is_empty() {
        return Vec::new();
    }
    let Some(Stmt::Assign(assign)) = parsed.syntax().body.first() else {
        return Vec::new();
    };
    let tuple = matches!(assign.value.as_ref(), Expr::Tuple(_));
    let replacement = if tuple {
        format!("repr(({inner}))")
    } else {
        format!("repr({inner})")
    };
    vec![alt(
        "backticks-use-repr",
        "Replace backticks with repr().",
        vec![text_edit(index, source, range, replacement)],
    )]
}

fn line_info(range: TextRange, source: &str) -> (TextSize, TextSize, TextSize, &str) {
    let start = source.line_start(range.start());
    let end = source.line_end(range.start());
    let full_end = source.full_line_end(range.start());
    (start, end, full_end, &source[TextRange::new(start, end)])
}

fn indent(line: &str) -> &str {
    &line[..line.len() - line.trim_start_matches([' ', '\t']).len()]
}

fn newline(source: &str, end: TextSize, full_end: TextSize) -> &'static str {
    if source[end.to_usize()..full_end.to_usize()].starts_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

fn next_code_line(source: &str, from: usize) -> Option<(usize, usize, String)> {
    let mut cursor = from;
    while cursor < source.len() {
        let full_end = source[cursor..]
            .find('\n')
            .map_or(source.len(), |n| cursor + n + 1);
        let end = if full_end > cursor && source.as_bytes()[full_end - 1] == b'\n' {
            if full_end > cursor + 1 && source.as_bytes()[full_end - 2] == b'\r' {
                full_end - 2
            } else {
                full_end - 1
            }
        } else {
            full_end
        };
        let line = source[cursor..end].to_string();
        if !line.trim().is_empty() {
            return Some((cursor, full_end, line));
        }
        cursor = full_end;
    }
    None
}

#[derive(Default)]
struct MatchingState {
    depth: usize,
    quote: Option<u8>,
    comment: bool,
}
fn matching(source: &str, open: usize, left: u8, right: u8) -> Option<usize> {
    let mut state = MatchingState::default();
    for (relative, &byte) in source.as_bytes()[open..].iter().enumerate() {
        let index = open + relative;
        if let Some(found) = matching_byte(source, index, byte, left, right, &mut state) {
            return Some(found);
        }
    }
    None
}

fn matching_byte(
    source: &str,
    index: usize,
    byte: u8,
    left: u8,
    right: u8,
    state: &mut MatchingState,
) -> Option<usize> {
    if consume_matching_comment(byte, &mut state.comment)
        || consume_matching_quote(byte, index, source, &mut state.quote)
    {
        return None;
    }
    match byte {
        b'\'' | b'"' => state.quote = Some(byte),
        b'#' => state.comment = true,
        byte if byte == left => state.depth += 1,
        byte if byte == right => {
            state.depth = state.depth.saturating_sub(1);
            if state.depth == 0 {
                return Some(index);
            }
        }
        _ => {}
    }
    None
}

fn consume_matching_comment(byte: u8, comment: &mut bool) -> bool {
    if !*comment {
        return false;
    }
    if byte == b'\n' {
        *comment = false;
    }
    true
}

fn consume_matching_quote(byte: u8, index: usize, source: &str, quote: &mut Option<u8>) -> bool {
    let Some(quote_byte) = *quote else {
        return false;
    };
    if byte == quote_byte && (index == 0 || source.as_bytes()[index - 1] != b'\\') {
        *quote = None;
    }
    true
}

fn function_context(source: &str, at: usize) -> Option<(usize, usize, usize, String)> {
    let mut candidate = None;
    let mut cursor = 0;
    while cursor < at {
        let next = source[cursor..]
            .find('\n')
            .map_or(at, |n| (cursor + n + 1).min(at));
        let line = &source[cursor..next];
        if let Some(relative) = line.find("def ") {
            let prefix = &line[..relative];
            if prefix.trim().is_empty()
                || prefix.chars().all(|c| c == ' ' || c == '\t')
                || prefix.trim_end().ends_with("async")
            {
                candidate = Some(cursor + relative);
            }
        }
        if next == at {
            break;
        }
        cursor = next;
    }
    let def = candidate?;
    let declaration_start = source[..def].rfind('\n').map_or(0, |n| n + 1);
    let open = source[def..].find('(').map_or(def, |n| def + n);
    let close = matching(source, open, b'(', b')')?;
    let header_end = source[def..].find('\n').map_or(source.len(), |n| def + n);
    let header = &source[declaration_start..header_end];
    let name = source[def + 4..open].trim().to_string();
    let colon = source[close..].find(':').map_or(close, |n| close + n);
    let body = source[colon..]
        .find('\n')
        .map_or(source.len(), |n| colon + n + 1);
    let function_indent = indent(header).len();
    let mut end = source.len();
    let mut body_cursor = body;
    while body_cursor < source.len() {
        let next = source[body_cursor..]
            .find('\n')
            .map_or(source.len(), |n| body_cursor + n + 1);
        let line = source[body_cursor..next].trim_end_matches(['\r', '\n']);
        if !line.trim().is_empty() && indent(line).len() <= function_indent {
            end = body_cursor;
            break;
        }
        body_cursor = next;
    }
    Some((def, body, end, name))
}

fn s139(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let (line_start, line_end, full_end, line) = line_info(range, source);
    let before = &line[..range
        .start()
        .to_usize()
        .saturating_sub(line_start.to_usize())];
    let comment = source[range].trim_end_matches(['\r', '\n']);
    if comment.is_empty() || before.trim().is_empty() {
        return Vec::new();
    }
    let mut remove_start = range.start().to_usize();
    while remove_start > line_start.to_usize()
        && matches!(source.as_bytes()[remove_start - 1], b' ' | b'\t')
    {
        remove_start -= 1;
    }
    let eol = newline(source, line_end, full_end);
    vec![alt(
        "s139-move-comment",
        "Move this trailing comment on the previous empty line.",
        vec![
            text_edit(
                index,
                source,
                TextRange::new(line_start, line_start),
                format!("{}{comment}{eol}", indent(line)),
            ),
            text_edit(
                index,
                source,
                TextRange::new(TextSize::from(to_u32(remove_start)), line_end),
                "",
            ),
        ],
    )]
}

fn s1110(
    parsed: &Parsed<ModModule>,
    issue: &Issue,
    index: &LineIndex,
    source: &str,
) -> Vec<Alternative> {
    if !parsed.errors().is_empty() {
        return Vec::new();
    }
    let range = issue_range(issue, index, source);
    if &source[range] != "(" {
        return Vec::new();
    }
    let Some(pair) = crate::rules::redundant_parentheses_range(parsed, range.start()) else {
        return Vec::new();
    };
    let close = TextSize::from(to_u32(pair.end().to_usize().saturating_sub(1)));
    vec![alt(
        "s1110-remove-parentheses",
        "Remove the redundant parentheses",
        vec![
            text_edit(
                index,
                source,
                TextRange::new(pair.start(), pair.start() + TextSize::new(1)),
                "",
            ),
            text_edit(index, source, TextRange::new(close, pair.end()), ""),
        ],
    )]
}

fn s1131(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let (line_start, line_end, _, line) = line_info(range, source);
    let trimmed = line.trim_end_matches([' ', '\t']);
    if trimmed.len() == line.len() {
        return Vec::new();
    }
    vec![alt(
        "s1131-remove-trailing-whitespace",
        "Remove trailing whitespaces",
        vec![text_edit(
            index,
            source,
            TextRange::new(
                TextSize::from(to_u32(line_start.to_usize() + trimmed.len())),
                line_end,
            ),
            "",
        )],
    )]
}

fn s1186(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let at = issue_range(issue, index, source).start().to_usize();
    let Some((_, body, end, name)) = function_context(source, at) else {
        return Vec::new();
    };
    if source[body..end]
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
        != 1
    {
        return Vec::new();
    }
    let Some((line_start, full_end, line)) = next_code_line(source, body) else {
        return Vec::new();
    };
    if line.trim() != "pass" {
        return Vec::new();
    }
    let eol = if source[line_start..full_end].ends_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let body_indent = indent(&line);
    let placeholder = text_edit(
        index,
        source,
        TextRange::new(
            TextSize::from(to_u32(line_start)),
            TextSize::from(to_u32(line_start + line.len())),
        ),
        format!("{body_indent}# TODO document why this method is empty{eol}{line}"),
    );
    let mut result = vec![alt(
        "s1186-placeholder-comment",
        "Insert placeholder comment",
        vec![placeholder],
    )];
    let replacement = if [
        "__eq__",
        "__ne__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__add__",
        "__sub__",
        "__mul__",
        "__truediv__",
    ]
    .contains(&name.as_str())
    {
        (
            "s1186-return-notimplemented",
            "Return NotImplemented constant",
            format!("{body_indent}return NotImplemented"),
        )
    } else {
        (
            "s1186-raise-notimplemented",
            "Raise NotImplementedError()",
            format!("{body_indent}raise NotImplementedError()"),
        )
    };
    result.push(alt(
        replacement.0,
        replacement.1,
        vec![text_edit(
            index,
            source,
            TextRange::new(
                TextSize::from(to_u32(line_start)),
                TextSize::from(to_u32(line_start + line.len())),
            ),
            replacement.2,
        )],
    ));
    result
}
fn s1720(
    parsed: &Parsed<ModModule>,
    issue: &Issue,
    index: &LineIndex,
    source: &str,
) -> Vec<Alternative> {
    if issue.range.is_file_level() {
        let insertion = text_edit(
            index,
            source,
            TextRange::new(TextSize::default(), TextSize::default()),
            "\"\"\" doc \"\"\"\n",
        );
        return vec![alt("s1720-add-docstring", "Add docstring", vec![insertion])];
    }
    let issue_span = issue_range(issue, index, source);
    match s1720_class_context(parsed, issue_span, source) {
        S1720ClassContext::Body {
            line_start,
            indentation,
        } => {
            let insertion = text_edit(
                index,
                source,
                TextRange::new(
                    TextSize::from(to_u32(line_start)),
                    TextSize::from(to_u32(line_start)),
                ),
                format!("{indentation}\"\"\" doc \"\"\"\n"),
            );
            return vec![alt("s1720-add-docstring", "Add docstring", vec![insertion])];
        }
        S1720ClassContext::Unsafe => return Vec::new(),
        S1720ClassContext::NotClass => {}
    }
    let at = issue_span.start().to_usize();
    let Some((_, body, _, _)) = function_context(source, at) else {
        return Vec::new();
    };
    let Some((line_start, _, line)) = next_code_line(source, body) else {
        return Vec::new();
    };
    let body_indent = indent(&line);
    let insertion = text_edit(
        index,
        source,
        TextRange::new(
            TextSize::from(to_u32(line_start)),
            TextSize::from(to_u32(line_start)),
        ),
        format!("{body_indent}\"\"\" doc \"\"\"\n"),
    );
    vec![alt("s1720-add-docstring", "Add docstring", vec![insertion])]
}

enum S1720ClassContext {
    NotClass,
    Unsafe,
    Body {
        line_start: usize,
        indentation: String,
    },
}

fn s1720_class_context(
    parsed: &Parsed<ModModule>,
    issue_span: TextRange,
    source: &str,
) -> S1720ClassContext {
    let mut context = S1720ClassContext::NotClass;
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |statement| {
        if !matches!(&context, S1720ClassContext::NotClass) {
            return;
        }
        let Stmt::ClassDef(class) = statement else {
            return;
        };
        if class.name.range() != issue_span {
            return;
        }
        context = S1720ClassContext::Unsafe;
        let Some(first) = class.body.first() else {
            return;
        };
        let class_line = source.line_start(class.name.range().start());
        let first_start = first.range().start();
        let first_line = source.line_start(first_start);
        if class_line == first_line {
            return;
        }
        let Some(class_line_text) = source
            .get(class_line.to_usize()..source.line_end(class.name.range().start()).to_usize())
        else {
            return;
        };
        let Some(indentation) = source.get(first_line.to_usize()..first_start.to_usize()) else {
            return;
        };
        if !indentation.chars().all(char::is_whitespace)
            || indentation.len() <= indent(class_line_text).len()
        {
            return;
        }
        context = S1720ClassContext::Body {
            line_start: first_line.to_usize(),
            indentation: indentation.to_string(),
        };
    });
    context
}

fn remove_line(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    if source[range].contains(['\r', '\n']) {
        return Vec::new();
    }
    let Some(edit_range) = line_removal_range(source, range) else {
        return Vec::new();
    };
    let (id, message) = if issue.rule_key.ends_with("S2772") {
        ("s2772-remove-pass", "Remove the pass statement")
    } else {
        ("s3626-remove-jump", "Remove this redundant jump")
    };
    let edit = text_edit(index, source, edit_range, "");
    vec![alt(id, message, vec![edit])]
}

fn line_removal_range(source: &str, range: TextRange) -> Option<TextRange> {
    let (start, _, full_end, line) = line_info(range, source);
    let local_start = range.start().to_usize().saturating_sub(start.to_usize());
    let local_end = range.end().to_usize().saturating_sub(start.to_usize());
    let before = line.get(..local_start.min(line.len())).unwrap_or("");
    let after = line.get(local_end.min(line.len())..).unwrap_or("");
    if before.trim().is_empty() && after.trim().is_empty() {
        if let Some((_, body, end, _)) = function_context(source, range.start().to_usize()) {
            let statements = source[body..end]
                .lines()
                .filter(|candidate| !candidate.trim().is_empty())
                .count();
            if statements <= 1 {
                return None;
            }
        }
        return Some(TextRange::new(start, full_end));
    }
    if after.trim_start().starts_with(';') {
        let separator = local_end + after.find(';').unwrap_or(0);
        let mut end = separator + 1;
        while end < line.len() && line.as_bytes()[end].is_ascii_whitespace() {
            end += 1;
        }
        return Some(TextRange::new(
            range.start(),
            TextSize::from(to_u32(start.to_usize() + end)),
        ));
    }
    if before.trim_end().ends_with(';') {
        let separator = before.rfind(';').unwrap_or(local_start);
        let mut begin = separator;
        while begin > 0 && line.as_bytes()[begin - 1].is_ascii_whitespace() {
            begin -= 1;
        }
        return Some(TextRange::new(
            TextSize::from(to_u32(start.to_usize() + begin)),
            range.end(),
        ));
    }
    None
}

fn s1940(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    let inner = text.strip_prefix("not").map_or(text, str::trim);
    let inner = strip_parens(inner);
    let Some((at, op)) = single_comparison_operator(inner) else {
        return Vec::new();
    };
    let opposite = match op {
        "==" => "!=",
        "!=" => "==",
        "<" => ">=",
        "<=" => ">",
        ">" => "<=",
        ">=" => "<",
        "is" => "is not",
        "is not" => "is",
        "in" => "not in",
        "not in" => "in",
        _ => return Vec::new(),
    };
    let replacement = format!(
        "{} {} {}",
        inner[..at].trim(),
        opposite,
        inner[at + op.len()..].trim()
    );
    let edit = text_edit(index, source, range, replacement);
    vec![alt(
        "s1940-use-opposite-operator",
        format!("Use {opposite} instead"),
        vec![edit],
    )]
}

fn single_comparison_operator(text: &str) -> Option<(usize, &'static str)> {
    const OPERATORS: [&str; 10] = [
        "is not", "not in", "==", "!=", "<=", ">=", "<", ">", "is", "in",
    ];
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut found = None;
    let mut index = 0usize;
    while index < bytes.len() {
        index += comparison_scan_advance(
            bytes,
            index,
            &OPERATORS,
            &mut depth,
            &mut quote,
            &mut escaped,
            &mut found,
        )
        .ok()?;
    }
    found
}

fn comparison_scan_advance(
    bytes: &[u8],
    index: usize,
    operators: &[&'static str],
    depth: &mut usize,
    quote: &mut Option<u8>,
    escaped: &mut bool,
    found: &mut Option<(usize, &'static str)>,
) -> Result<usize, ()> {
    let byte = bytes[index];
    if consume_comparison_quote(byte, quote, escaped) {
        return Ok(1);
    }
    if byte == b'\'' || byte == b'"' {
        *quote = Some(byte);
        return Ok(1);
    }
    if consume_comparison_delimiter(byte, depth) {
        return Ok(1);
    }
    if *depth == 0
        && let Some(operator) = comparison_operator_at(bytes, index, operators)
    {
        if found.is_some() {
            return Err(());
        }
        *found = Some((index, operator));
        return Ok(operator.len() + 1);
    }
    Ok(1)
}

fn consume_comparison_quote(byte: u8, quote: &mut Option<u8>, escaped: &mut bool) -> bool {
    let Some(delimiter) = *quote else {
        return false;
    };
    if *escaped {
        *escaped = false;
    } else if byte == b'\\' {
        *escaped = true;
    } else if byte == delimiter {
        *quote = None;
    }
    true
}

fn consume_comparison_delimiter(byte: u8, depth: &mut usize) -> bool {
    match byte {
        b'(' | b'[' | b'{' => {
            *depth += 1;
            true
        }
        b')' | b']' | b'}' => {
            *depth = depth.saturating_sub(1);
            true
        }
        _ => false,
    }
}

fn comparison_operator_at(
    bytes: &[u8],
    index: usize,
    operators: &[&'static str],
) -> Option<&'static str> {
    for &operator in operators {
        if !bytes[index..].starts_with(operator.as_bytes()) {
            continue;
        }
        if is_word_comparison_operator(operator)
            && operator_has_identifier_neighbor(bytes, index, operator.len())
        {
            continue;
        }
        return Some(operator);
    }
    None
}

fn is_word_comparison_operator(operator: &str) -> bool {
    matches!(operator, "is" | "in" | "is not" | "not in")
}

fn operator_has_identifier_neighbor(bytes: &[u8], index: usize, length: usize) -> bool {
    let before = index
        .checked_sub(1)
        .and_then(|position| bytes.get(position))
        .copied();
    let after = bytes.get(index + length).copied();
    before.is_some_and(|value| value.is_ascii_alphanumeric() || value == b'_')
        || after.is_some_and(|value| value.is_ascii_alphanumeric() || value == b'_')
}

fn s2710(
    parsed: &Parsed<ModModule>,
    issue: &Issue,
    index: &LineIndex,
    source: &str,
) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let table = build_symbol_table(parsed);
    let Some((param_scope, flagged, kind)) = parameter_binding_at(&table, range) else {
        return Vec::new();
    };
    if kind != BindingKind::Parameter || flagged == "cls" {
        return Vec::new();
    }
    if collect_file_facts(parsed, source).dynamic_names {
        return Vec::new();
    }
    let target = "cls";
    let parameter_scope = &table.scopes[param_scope];
    if parameter_scope.bindings.contains_key(target)
        || parameter_scope.declares_global(target)
        || parameter_scope.declares_nonlocal(target)
    {
        return Vec::new();
    }
    let Some(method_span) = function_span_containing(parsed, range) else {
        return Vec::new();
    };
    let Some(mut renames) =
        s2710_collect_renames(&table, param_scope, flagged, target, method_span, range)
    else {
        return Vec::new();
    };
    renames.sort_by_key(Ranged::start);
    renames.dedup();
    let edits = renames
        .iter()
        .map(|rename| text_edit(index, source, *rename, target))
        .collect();
    vec![alt(
        "s2710-rename-class-parameter",
        format!("Rename the class parameter to '{target}'."),
        edits,
    )]
}

fn s2710_collect_renames(
    table: &SymbolTable,
    param_scope: usize,
    flagged: &str,
    target: &str,
    method_span: TextRange,
    range: TextRange,
) -> Option<Vec<TextRange>> {
    for (scope_index, scope) in table.scopes.iter().enumerate() {
        if scope_is_within(table, scope_index, param_scope)
            && (scope.declares_global(flagged) || scope.declares_nonlocal(flagged))
        {
            return None;
        }
    }
    let mut renames = vec![range];
    if let Some(bindings) = table.scopes[param_scope].bindings.get(flagged) {
        renames.extend(bindings.iter().map(|binding| binding.range));
    }
    for load in &table.resolved_loads {
        if load.name != flagged || !method_span.contains(load.range.start()) {
            continue;
        }
        match load.target {
            Some(binding_scope) if binding_scope == param_scope => {
                if intermediate_scope_binds(table, load.scope, param_scope, target) {
                    return None;
                }
                renames.push(load.range);
            }
            Some(_) => {}
            None => return None,
        }
    }
    for load in &table.resolved_loads {
        if load.name == target
            && method_span.contains(load.range.start())
            && post_rename_rebinds_to(table, load.scope, param_scope, target)
        {
            return None;
        }
    }
    Some(renames)
}

fn parameter_binding_at(
    table: &SymbolTable,
    span: TextRange,
) -> Option<(usize, &str, BindingKind)> {
    table
        .scopes
        .iter()
        .enumerate()
        .find_map(|(scope_index, scope)| {
            scope.bindings.iter().find_map(|(name, bindings)| {
                bindings
                    .iter()
                    .find(|binding| binding.range == span)
                    .map(|binding| (scope_index, name.as_str(), binding.kind))
            })
        })
}

fn function_span_containing(parsed: &Parsed<ModModule>, span: TextRange) -> Option<TextRange> {
    let mut found: Option<TextRange> = None;
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.range().contains(span.start())
        {
            let candidate = function.range();
            if found.is_none_or(|current| candidate.len() < current.len()) {
                found = Some(candidate);
            }
        }
    });
    found
}

fn intermediate_scope_binds(
    table: &SymbolTable,
    from_scope: usize,
    to_scope: usize,
    name: &str,
) -> bool {
    let mut cursor = Some(from_scope);
    while let Some(scope_index) = cursor {
        if scope_index == to_scope {
            return false;
        }
        let scope = &table.scopes[scope_index];
        if scope.bindings.contains_key(name)
            || scope.declares_global(name)
            || scope.declares_nonlocal(name)
        {
            return true;
        }
        cursor = scope.parent;
    }
    true
}

fn post_rename_rebinds_to(
    table: &SymbolTable,
    from_scope: usize,
    added_scope: usize,
    name: &str,
) -> bool {
    let mut cursor = Some(from_scope);
    while let Some(scope_index) = cursor {
        if scope_index == added_scope {
            return true;
        }
        let scope = &table.scopes[scope_index];
        if scope.kind == ScopeKind::Class {
            return true;
        }
        if scope.bindings.contains_key(name)
            || scope.declares_global(name)
            || scope.declares_nonlocal(name)
        {
            return false;
        }
        cursor = scope.parent;
    }
    false
}

fn s3923_find_if(parsed: &Parsed<ModModule>, range: TextRange) -> Option<&StmtIf> {
    let mut flagged: Option<&StmtIf> = None;
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::If(if_stmt) = stmt
            && if_stmt.start() == range.start()
        {
            flagged = Some(if_stmt);
        }
    });
    flagged
}

fn s3923(
    parsed: &Parsed<ModModule>,
    issue: &Issue,
    index: &LineIndex,
    source: &str,
) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let Some(if_stmt) = s3923_find_if(parsed, range) else {
        return Vec::new();
    };
    let [clause] = &if_stmt.elif_else_clauses[..] else {
        return Vec::new();
    };
    if clause.test.is_some() || if_stmt.body.is_empty() || clause.body.is_empty() {
        return Vec::new();
    }
    let if_suite = suite_span(&if_stmt.body);
    let else_suite = suite_span(&clause.body);
    if !ranges_textually_equal(if_suite, else_suite, source)
        || branch_strings_unsafe(parsed, source, if_suite, else_suite)
        || !builtin_bool_is_unshadowed(parsed, source)
    {
        return Vec::new();
    }
    let test = source[if_stmt.test.range()].trim();
    if test.is_empty() {
        return Vec::new();
    }
    let stmt_start = if_stmt.start();
    let stmt_end = else_suite.end();
    let Some(replacement) = s3923_replacement(if_stmt, source, if_suite, test) else {
        return Vec::new();
    };
    vec![alt(
        "s3923-remove-if-statement",
        "Collapse identical if/else branches while preserving condition evaluation",
        vec![text_edit(
            index,
            source,
            TextRange::new(stmt_start, stmt_end),
            replacement,
        )],
    )]
}

fn s3923_replacement(
    if_stmt: &StmtIf,
    source: &str,
    if_suite: TextRange,
    test: &str,
) -> Option<String> {
    let stmt_start = if_stmt.start();
    let if_prefix = indentation_prefix(source, stmt_start)?;
    let body_inline = !source[stmt_start.to_usize()..if_suite.start().to_usize()].contains('\n');
    let body_pass_only = matches!(if_stmt.body.as_slice(), [Stmt::Pass(_)]);
    if body_inline {
        let mut replacement = format!("bool(({test}))");
        if !body_pass_only {
            for stmt in &if_stmt.body {
                replacement.push('\n');
                replacement.push_str(if_prefix);
                replacement.push_str(source[stmt.range()].trim());
            }
        }
        return Some(replacement);
    }
    let body_prefix = indentation_prefix(source, if_suite.start())?;
    if body_pass_only {
        return Some(format!("bool(({test}))"));
    }
    let extra = body_prefix.strip_prefix(if_prefix)?;
    let mut replacement = format!("bool(({test}))\n");
    let region = &source[source.line_start(if_suite.start()).to_usize()..if_suite.end().to_usize()];
    for line in region.split_inclusive('\n') {
        if line.trim().is_empty() {
            replacement.push_str(line);
        } else if line.starts_with(body_prefix) {
            replacement.push_str(&line[extra.len()..]);
        } else {
            replacement.push_str(line);
        }
    }
    Some(replacement)
}
fn builtin_bool_is_unshadowed(parsed: &Parsed<ModModule>, source: &str) -> bool {
    let facts = collect_file_facts(parsed, source);
    !facts.dynamic_names
        && !facts.has_wildcard_import
        && build_symbol_table(parsed).scopes.iter().all(|scope| {
            !scope.bindings.contains_key("bool")
                && !scope.declares_global("bool")
                && !scope.declares_nonlocal("bool")
        })
}

fn indentation_prefix(source: &str, offset: TextSize) -> Option<&str> {
    let line_start = source.line_start(offset).to_usize();
    let prefix = source.get(line_start..offset.to_usize())?;
    prefix
        .chars()
        .all(|character| character == ' ' || character == '\t')
        .then_some(prefix)
}

fn branch_strings_unsafe(
    parsed: &Parsed<ModModule>,
    source: &str,
    left: TextRange,
    right: TextRange,
) -> bool {
    let mut left_strings = Vec::new();
    let mut right_strings = Vec::new();
    let mut interpolated = false;
    for token in parsed.tokens() {
        let in_left = left.contains_range(token.range());
        let in_right = right.contains_range(token.range());
        if !in_left && !in_right {
            continue;
        }
        match token.kind() {
            TokenKind::String => {
                let text = &source[token.range()];
                if text.contains('\n') {
                    return true;
                }
                if in_left {
                    left_strings.push(text);
                } else {
                    right_strings.push(text);
                }
            }
            TokenKind::FStringStart
            | TokenKind::FStringEnd
            | TokenKind::TStringStart
            | TokenKind::TStringEnd => interpolated = true,
            _ => {}
        }
    }
    interpolated || left_strings != right_strings
}

fn s3984(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    let names = [
        "Exception",
        "RuntimeError",
        "ValueError",
        "TypeError",
        "KeyError",
        "IndexError",
        "LookupError",
        "OSError",
        "IOError",
        "AssertionError",
        "NotImplementedError",
        "StopIteration",
        "StopAsyncIteration",
        "KeyboardInterrupt",
        "GeneratorExit",
        "SystemExit",
    ];
    let name = text.split('(').next().unwrap_or(text).trim();
    if !names.contains(&name) {
        return Vec::new();
    }
    let (start, _, _, line) = line_info(range, source);
    let local_start = range
        .start()
        .to_usize()
        .saturating_sub(start.to_usize())
        .min(line.len());
    let local_end = range
        .end()
        .to_usize()
        .saturating_sub(start.to_usize())
        .min(line.len());
    let before = line.get(..local_start).unwrap_or("");
    let after = line.get(local_end..).unwrap_or("");
    if !before.trim().is_empty() || !after.trim().is_empty() {
        return Vec::new();
    }
    vec![alt(
        "s3984-raise-exception",
        "Raise this exception",
        vec![text_edit(
            index,
            source,
            TextRange::new(range.start(), range.start()),
            "raise ",
        )],
    )]
}

fn s4144(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let at = issue_range(issue, index, source).start().to_usize();
    let Some((def, body, end, _name)) = function_context(source, at) else {
        return Vec::new();
    };
    let Some(class_position) = source[..def].rfind("class ") else {
        return Vec::new();
    };
    if !source[def..].starts_with("def ") {
        return Vec::new();
    }
    let open = source[def..].find('(').map_or(def, |offset| def + offset);
    let Some(close) = matching(source, open, b'(', b')') else {
        return Vec::new();
    };
    let params = source[open + 1..close].trim();
    if params != "self" && params != "cls" {
        return Vec::new();
    }
    let original = issue
        .message
        .split('"')
        .nth(1)
        .or_else(|| issue.message.split('\'').nth(1))
        .unwrap_or("");
    if original.is_empty() || !source[body..end].contains("self.") {
        return Vec::new();
    }
    if !s4144_original_method_is_compatible(source, class_position, def, original) {
        return Vec::new();
    }
    let Some((first, replacement)) =
        s4144_call_replacement(source, def, body, end, class_position, original)
    else {
        return Vec::new();
    };
    let edit = text_edit(
        index,
        source,
        TextRange::new(TextSize::from(to_u32(first)), TextSize::from(to_u32(end))),
        replacement,
    );
    vec![alt(
        "s4144-call-original-method",
        format!("Call {original} inside this function."),
        vec![edit],
    )]
}

fn s4144_original_method_is_compatible(
    source: &str,
    class_position: usize,
    def: usize,
    original: &str,
) -> bool {
    let marker = format!("def {original}(");
    let class_before_current = &source[class_position..def];
    let Some(original_relative) = class_before_current.find(&marker) else {
        return false;
    };
    let original_def = class_position + original_relative;
    let original_open = original_def + marker.len() - 1;
    let Some(original_close) = matching(source, original_open, b'(', b')') else {
        return false;
    };
    let original_params = source[original_open + 1..original_close].trim();
    original_params.is_empty() || original_params == "self" || original_params == "cls"
}

fn s4144_call_replacement(
    source: &str,
    def: usize,
    body: usize,
    end: usize,
    class_position: usize,
    original: &str,
) -> Option<(usize, String)> {
    let class_line_start = source[..class_position]
        .rfind('\n')
        .map_or(0, |position| position + 1);
    let class_line_end = source[class_position..]
        .find('\n')
        .map_or(source.len(), |offset| class_position + offset);
    let class_header = &source[class_line_start..class_line_end];
    let class_name = class_header
        .trim_start()
        .strip_prefix("class ")
        .and_then(|header| header.split(['(', ':', ' ']).next())
        .unwrap_or("");
    if class_name.is_empty() {
        return None;
    }

    let decorator_line_start = source[..def].rfind('\n').map_or(0, |position| position + 1);
    let header_end = source[def..]
        .find('\n')
        .map_or(source.len(), |offset| def + offset);
    let method_indent = indent(&source[decorator_line_start..header_end]);
    let mut decorator_start = decorator_line_start;
    let mut cursor = decorator_line_start;
    while cursor > 0 {
        let previous_end = cursor.saturating_sub(1);
        let previous_start = source[..previous_end]
            .rfind('\n')
            .map_or(0, |position| position + 1);
        let previous_line = &source[previous_start..previous_end];
        if indent(previous_line) == method_indent && previous_line.trim_start().starts_with('@') {
            decorator_start = previous_start;
            cursor = previous_start;
        } else {
            break;
        }
    }
    let decorators = &source[decorator_start..decorator_line_start];
    let class_method = decorators.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "@classmethod" || trimmed == "@staticmethod"
    });
    let prefix = if source[body..end].contains("return ") {
        "return "
    } else {
        ""
    };
    let call = if class_method {
        format!("{prefix}{class_name}.{original}()")
    } else {
        format!("{prefix}self.{original}()")
    };
    let (first, _, first_line) = next_code_line(source, body)?;
    Some((first, format!("{}{call}\n", indent(&first_line))))
}

fn s5712(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    const PROTOCOL_METHODS: [&str; 48] = [
        "__add__",
        "__sub__",
        "__mul__",
        "__matmul__",
        "__truediv__",
        "__floordiv__",
        "__mod__",
        "__divmod__",
        "__pow__",
        "__lshift__",
        "__rshift__",
        "__and__",
        "__or__",
        "__xor__",
        "__radd__",
        "__rsub__",
        "__rmul__",
        "__rmatmul__",
        "__rtruediv__",
        "__rfloordiv__",
        "__rmod__",
        "__rdivmod__",
        "__rpow__",
        "__rlshift__",
        "__rrshift__",
        "__rand__",
        "__ror__",
        "__rxor__",
        "__iadd__",
        "__isub__",
        "__imul__",
        "__imatmul__",
        "__itruediv__",
        "__ifloordiv__",
        "__imod__",
        "__ipow__",
        "__ilshift__",
        "__irshift__",
        "__iand__",
        "__ior__",
        "__ixor__",
        "__eq__",
        "__ne__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__length_hint__",
    ];
    let at = issue_range(issue, index, source).start().to_usize();
    let Some((_, _, _, name)) = function_context(source, at) else {
        return Vec::new();
    };
    if !PROTOCOL_METHODS.contains(&name.as_str()) {
        return Vec::new();
    }
    let range = issue_range(issue, index, source);
    let edit = text_edit(index, source, range, "return NotImplemented");
    vec![alt(
        "s5712-return-notimplemented",
        "Replace the raised exception with return NotImplemented",
        vec![edit],
    )]
}

fn s5713(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let at = range.start().to_usize();
    let Some(open) = source[..at].rfind('(') else {
        return Vec::new();
    };
    let Some(close) = matching(source, open, b'(', b')') else {
        return Vec::new();
    };
    if close < range.end().to_usize() {
        return Vec::new();
    }
    let before = &source[open + 1..at];
    let after = &source[range.end().to_usize()..close];
    if source[open + 1..close].matches(',').count() != 1 {
        let (start, end) = if let Some(comma) = after.find(',') {
            let comma = range.end().to_usize() + comma;
            (range.start(), TextSize::from(to_u32(comma + 1)))
        } else if let Some(comma) = before.rfind(',') {
            (TextSize::from(to_u32(open + 1 + comma)), range.end())
        } else {
            return Vec::new();
        };
        let edit = text_edit(index, source, TextRange::new(start, end), "");
        return vec![alt(
            "s5713-remove-redundant-exception",
            "Remove this redundant Exception class",
            vec![edit],
        )];
    }
    let remaining = if before.contains(',') {
        before
            .rsplit_once(',')
            .map_or("", |(prefix, _)| prefix.trim())
    } else {
        after
            .trim_start()
            .strip_prefix(',')
            .map_or_else(|| after.trim(), str::trim)
    };
    if remaining.is_empty() {
        return Vec::new();
    }
    vec![alt(
        "s5713-remove-redundant-exception",
        "Remove this redundant Exception class",
        vec![text_edit(
            index,
            source,
            TextRange::new(
                TextSize::from(to_u32(open)),
                TextSize::from(to_u32(close + 1)),
            ),
            remaining,
        )],
    )]
}
fn s5714(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    let parts: Vec<&str> = text.split(" or ").map(str::trim).collect();
    if parts.len() < 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.chars().all(|character| {
                    character.is_ascii_alphanumeric() || character == '_' || character == '.'
                })
                || part.starts_with('.')
                || part.ends_with('.')
        })
    {
        return Vec::new();
    }
    let replacement = format!("({})", parts.join(", "));
    let edit = text_edit(index, source, range, replacement);
    vec![alt(
        "s5714-use-exception-tuple",
        "Rewrite this expression as a tuple of exception classes",
        vec![edit],
    )]
}

fn s5717(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].to_string();
    let Some(eq) = text.find('=') else {
        return Vec::new();
    };
    let name = text[..eq]
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('*')
        .trim();
    let default = text[eq + 1..].trim();
    if name.is_empty() || default.is_empty() {
        return Vec::new();
    }
    let is_supported_default = default.starts_with('[')
        || default.starts_with('{')
        || default.ends_with(')')
        || default.starts_with("set(");
    if !is_supported_default {
        return Vec::new();
    }
    let Some((_, body, _, _)) = function_context(source, range.start().to_usize()) else {
        return Vec::new();
    };
    let Some((first, first_full_end, first_line)) = next_code_line(source, body) else {
        return Vec::new();
    };
    let body_indent = indent(&first_line);
    let default_offset = text[eq + 1..]
        .find(default)
        .map_or(eq + 1, |offset| eq + 1 + offset);
    let default_start = TextSize::from(to_u32(range.start().to_usize() + default_offset));
    let eol = if source[first..first_full_end].ends_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let default_edit = text_edit(
        index,
        source,
        TextRange::new(
            default_start,
            default_start + TextSize::from(to_u32(default.len())),
        ),
        "None",
    );
    let initializer =
        format!("{body_indent}if {name} is None:{eol}{body_indent}    {name} = {default}{eol}");
    let insertion = text_edit(
        index,
        source,
        TextRange::new(TextSize::from(to_u32(first)), TextSize::from(to_u32(first))),
        initializer,
    );
    vec![alt(
        "s5717-initialize-parameter",
        "Initialize this parameter inside the function/method",
        vec![default_edit, insertion],
    )]
}

fn s5719(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let at = range.start().to_usize();
    let Some(open_offset) = source[at..].find('(') else {
        return Vec::new();
    };
    let open = at + open_offset;
    let header_start = source[..at].rfind('\n').map_or(0, |position| position + 1);
    let header_end = source[at..]
        .find('\n')
        .map_or(source.len(), |offset| at + offset);
    let header = &source[header_start..header_end];
    let method_indent = indent(header);
    let mut decorator_start = header_start;
    let mut cursor = header_start;
    while cursor > 0 {
        let previous_end = cursor.saturating_sub(1);
        let previous_start = source[..previous_end]
            .rfind('\n')
            .map_or(0, |position| position + 1);
        let previous_line = &source[previous_start..previous_end];
        if indent(previous_line) == method_indent && previous_line.trim_start().starts_with('@') {
            decorator_start = previous_start;
            cursor = previous_start;
        } else {
            break;
        }
    }
    let decorators = &source[decorator_start..header_start];
    let function_name = source[at + "def ".len()..open].trim();
    let class_method = function_name == "__new__"
        || function_name == "__init_subclass__"
        || decorators.lines().any(|line| line.trim() == "@classmethod");
    let static_method = decorators.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "@staticmethod" || trimmed == "@abstractstaticmethod"
    });
    if static_method {
        return Vec::new();
    }
    let separator = if source[open + 1..].trim_start().starts_with(')') {
        ""
    } else {
        ", "
    };
    let names: &[&str] = if class_method {
        &["cls"]
    } else {
        &["cls", "self"]
    };
    names
        .iter()
        .map(|name| {
            let insertion = text_edit(
                index,
                source,
                TextRange::new(
                    TextSize::from(to_u32(open + 1)),
                    TextSize::from(to_u32(open + 1)),
                ),
                format!("{name}{separator}"),
            );
            alt(
                format!("s5719-add-{name}"),
                format!("Add '{name}' as the first parameter."),
                vec![insertion],
            )
        })
        .collect()
}

fn s5754(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let (_, _, _, header) = line_info(range, source);
    let header_indent = indent(header).len();
    let mut cursor = source.full_line_end(range.start()).to_usize();
    let mut body = Vec::new();
    while cursor < source.len() {
        let next = source[cursor..]
            .find('\n')
            .map_or(source.len(), |n| cursor + n + 1);
        let line = source[cursor..next].trim_end_matches(['\r', '\n']);
        if !line.trim().is_empty() && indent(line).len() <= header_indent {
            break;
        }
        if !line.trim().is_empty() {
            body.push((cursor, next, line.to_string()));
        }
        cursor = next;
    }
    let Some((last_start, last_end, last_line)) = body.last() else {
        return Vec::new();
    };
    if matches!(last_line.trim(), "pass" | "...") {
        let end = TextSize::from(to_u32(*last_start + last_line.len()));
        return vec![alt(
            "s5754-propagate-exception",
            "Propagate the exception",
            vec![text_edit(
                index,
                source,
                TextRange::new(TextSize::from(to_u32(*last_start)), end),
                format!("{}raise", indent(last_line)),
            )],
        )];
    }
    if body.iter().any(|(_, _, line)| line.trim() == "raise") {
        return Vec::new();
    }
    let (_, _, first_line) = body.first().expect("body is non-empty");
    let body_indent = indent(first_line);
    let eol = if *last_end >= 2 && source[*last_end - 2..*last_end].ends_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    vec![alt(
        "s5754-propagate-exception",
        "Propagate the exception",
        vec![text_edit(
            index,
            source,
            TextRange::new(
                TextSize::from(to_u32(*last_end)),
                TextSize::from(to_u32(*last_end)),
            ),
            format!("{body_indent}raise{eol}"),
        )],
    )]
}

fn s5905(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let Some(()) = file_ctx.stmts.iter().find_map(|stmt| {
        let Stmt::Assert(assert) = stmt else {
            return None;
        };
        if assert.msg.is_some() || assert.test.range() != range {
            return None;
        }
        match assert.test.as_ref() {
            Expr::Tuple(tuple) if tuple.elts.len() == 1 => Some(()),
            _ => None,
        }
    }) else {
        return Vec::new();
    };
    let open = range.start().to_usize();
    let Some(close) = matching(source, open, b'(', b')') else {
        return Vec::new();
    };
    let mut comma_end = close;
    while comma_end > open && source.as_bytes()[comma_end - 1].is_ascii_whitespace() {
        comma_end -= 1;
    }
    if comma_end <= open || source.as_bytes()[comma_end - 1] != b',' {
        return Vec::new();
    }
    let edits = vec![
        text_edit(
            index,
            source,
            TextRange::new(range.start(), range.start() + TextSize::new(1)),
            "",
        ),
        text_edit(
            index,
            source,
            TextRange::new(
                TextSize::from(to_u32(comma_end - 1)),
                TextSize::from(to_u32(close)),
            ),
            "",
        ),
        text_edit(
            index,
            source,
            TextRange::new(
                TextSize::from(to_u32(close)),
                TextSize::from(to_u32(close + 1)),
            ),
            "",
        ),
    ];
    vec![alt("s5905-remove-parentheses", "Remove parentheses", edits)]
}
fn s6326(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].to_string();
    let count = 1 + text
        .chars()
        .filter(|character| character.is_whitespace())
        .count();
    if count < 2 {
        return Vec::new();
    }
    vec![alt(
        "s6326-use-quantifier",
        format!("Replace spaces with quantifier {{{count}}}."),
        vec![text_edit(index, source, range, format!("{{{count}}}"))],
    )]
}

fn s6395(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].to_string();
    if !text.starts_with("(?:") || !text.ends_with(')') {
        return Vec::new();
    }
    vec![alt(
        "s6395-remove-group",
        "Unwrap this unnecessarily grouped subpattern.",
        vec![text_edit(index, source, range, &text[3..text.len() - 1])],
    )]
}

fn s6397(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let start = range.start().to_usize();
    let end = range.end().to_usize();
    let Some(text) = source.get(start..end) else {
        return Vec::new();
    };
    if text.chars().count() != 1 {
        return Vec::new();
    }
    let Some(open) = start
        .checked_sub(1)
        .and_then(|at| source.as_bytes().get(at))
    else {
        return Vec::new();
    };
    let Some(close) = source.as_bytes().get(end) else {
        return Vec::new();
    };
    if *open != b'[' || *close != b']' {
        return Vec::new();
    }
    vec![alt(
        "s6397-remove-character-class",
        "Replace this character class by the character itself.",
        vec![
            text_edit(
                index,
                source,
                TextRange::new(TextSize::from(to_u32(start - 1)), range.start()),
                "",
            ),
            text_edit(
                index,
                source,
                TextRange::new(range.end(), TextSize::from(to_u32(end + 1))),
                "",
            ),
        ],
    )]
}

fn s6553(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].to_string();
    let Some(relative) = text.find("null=True") else {
        return Vec::new();
    };
    let start = TextSize::from(to_u32(range.start().to_usize() + relative));
    let edit = text_edit(
        index,
        source,
        TextRange::new(start, start + TextSize::from(to_u32("null=True".len()))),
        "blank=True",
    );
    vec![alt(
        "s6553-use-blank",
        "Use blank=True rather than null=True.",
        vec![edit],
    )]
}

fn s6725(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    let Some(eq) = text.find("==").or_else(|| text.find("!=")) else {
        return Vec::new();
    };
    let op = if text[eq..].starts_with("==") {
        "=="
    } else {
        "!="
    };
    let left = text[..eq].trim();
    let right = text[eq + op.len()..].trim();
    let (prefix, value) = if left == "np.nan" || left == "numpy.nan" {
        (&left[..left.len() - 4], right)
    } else if right == "np.nan" || right == "numpy.nan" {
        (&right[..right.len() - 4], left)
    } else {
        return Vec::new();
    };
    let replacement = if op == "==" {
        format!("{prefix}.isnan({value})")
    } else {
        format!("not {prefix}.isnan({value})")
    };
    vec![alt(
        "s6725-use-isnan",
        "Use isnan to test for NaN.",
        vec![text_edit(index, source, range, replacement)],
    )]
}

fn s6727(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].to_string();
    if text.contains("abs_tol") {
        return Vec::new();
    }
    let Some(close) = text.rfind(')') else {
        return Vec::new();
    };
    let args = &text[..close];
    if !args.contains(", 0") && !args.ends_with("(0") {
        return Vec::new();
    }
    let at = TextSize::from(to_u32(range.start().to_usize() + close));
    vec![alt(
        "s6727-add-abs-tol",
        "Add the abs_tol parameter.",
        vec![text_edit(
            index,
            source,
            TextRange::new(at, at),
            ", abs_tol=1e-9",
        )],
    )]
}

fn s6729(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    let Some(open) = text.find('(') else {
        return Vec::new();
    };
    let callee = text[..open].trim();
    if callee != "np.where" && callee != "numpy.where" {
        return Vec::new();
    }
    let where_at = callee.len().saturating_sub("where".len());
    let start = TextSize::from(to_u32(
        range.start().to_usize() + text.find(callee).unwrap_or(0) + where_at,
    ));
    let edit = text_edit(
        index,
        source,
        TextRange::new(start, start + TextSize::from(to_u32("where".len()))),
        "nonzero",
    );
    vec![alt(
        "s6729-use-nonzero",
        "Replace numpy.where with numpy.nonzero",
        vec![edit],
    )]
}

fn s6730(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].to_string();
    let replacement = match text.rsplit('.').next().unwrap_or("") {
        "int" | "long" => "int",
        "float" => "float",
        "complex" => "complex",
        "object" => "object",
        "str" | "unicode" => "str",
        _ => return Vec::new(),
    };
    vec![alt(
        "s6730-use-builtin-type",
        format!("Replace with {replacement}."),
        vec![text_edit(index, source, range, replacement)],
    )]
}

fn s6741(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    if !text.ends_with(".values") {
        return Vec::new();
    }
    let values_start = range.end().to_usize().saturating_sub("values".len());
    let values_range = TextRange::new(TextSize::from(to_u32(values_start)), range.end());
    vec![alt(
        "s6741-use-to-numpy",
        "Replace with DataFrame.to_numpy()",
        vec![text_edit(index, source, values_range, "to_numpy()")],
    )]
}

fn import_aliases(source: &str, module: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    for line in source.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("import ") {
            collect_module_aliases(rest, module, &mut aliases);
        }
        if let Some(rest) = line.strip_prefix(&format!("from {module} import ")) {
            collect_sleep_aliases(rest, &mut aliases);
        }
    }
    let mut unique = Vec::new();
    for alias in aliases {
        if !unique.contains(&alias) {
            unique.push(alias);
        }
    }
    unique
}

fn collect_module_aliases(rest: &str, module: &str, aliases: &mut Vec<String>) {
    for item in rest.split(',').map(str::trim) {
        if item == module {
            aliases.push(module.to_string());
        }
        if let Some(alias) = item.strip_prefix(&format!("{module} as ")) {
            aliases.push(alias.to_string());
        }
    }
}

fn collect_sleep_aliases(rest: &str, aliases: &mut Vec<String>) {
    for item in rest.split(',').map(str::trim) {
        if item == "sleep" {
            aliases.push("sleep".to_string());
        }
        if let Some(alias) = item.strip_prefix("sleep as ") {
            aliases.push(alias.to_string());
        }
    }
}

fn s7486(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].to_string();
    let mut result = Vec::new();
    for module in ["trio", "anyio"] {
        for alias in import_aliases(source, module) {
            let callee = if alias == "sleep" {
                "sleep(".to_string()
            } else {
                format!("{alias}.sleep(")
            };
            if text.contains(&callee) {
                let replacement = if alias == "sleep" {
                    "sleep_forever()".to_string()
                } else {
                    format!("{alias}.sleep_forever()")
                };
                let edit = text_edit(index, source, range, replacement.clone());
                result.push(alt(
                    format!("s7486-sleep-forever-{module}-{alias}"),
                    format!("Replace with {replacement}"),
                    vec![edit],
                ));
            }
        }
    }
    result
}

fn s7488(
    issue: &Issue,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let Some(call) = file_ctx.calls.iter().find(|call| call.range() == range) else {
        return Vec::new();
    };
    if file_ctx.known_bindings.resolve_call(call) != KnownBinding::TimeSleep {
        return Vec::new();
    }
    let Some(already_awaited) = s7488_already_awaited(file_ctx, range) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for (alias, module) in s7488_candidates(file_ctx, range) {
        if let Some(alternative) = s7488_candidate_alternative(
            index,
            source,
            call.func.range(),
            already_awaited,
            alias.as_str(),
            module,
        ) {
            result.push(alternative);
        }
    }
    result
}

fn s7488_already_awaited(file_ctx: &FileContext<'_>, range: TextRange) -> Option<bool> {
    file_ctx.stmts.iter().find_map(|stmt| {
        let Stmt::Expr(expression) = stmt else {
            return None;
        };
        match expression.value.as_ref() {
            Expr::Call(candidate) if candidate.range() == range => Some(false),
            Expr::Await(await_expression) => match await_expression.value.as_ref() {
                Expr::Call(candidate) if candidate.range() == range => Some(true),
                _ => None,
            },
            _ => None,
        }
    })
}

fn s7488_candidates(file_ctx: &FileContext<'_>, range: TextRange) -> Vec<(String, KnownBinding)> {
    let mut candidates = Vec::new();
    for import in &file_ctx.imports {
        let AnyImport::Plain(import) = import else {
            continue;
        };
        for alias in &import.names {
            if alias.range().start() > range.start() {
                continue;
            }
            let module = match alias.name.as_str() {
                "asyncio" => KnownBinding::AsyncioModule,
                "trio" => KnownBinding::TrioModule,
                "anyio" => KnownBinding::AnyioModule,
                _ => continue,
            };
            let local = alias.asname.as_deref().map_or_else(
                || {
                    alias
                        .name
                        .as_str()
                        .split('.')
                        .next()
                        .unwrap_or("")
                        .to_string()
                },
                str::to_string,
            );
            if file_ctx.known_bindings.resolve_name_at(&local, range) == module {
                candidates.push((local, module));
            }
        }
    }
    candidates
}

fn s7488_candidate_alternative(
    index: &LineIndex,
    source: &str,
    function_range: TextRange,
    already_awaited: bool,
    alias: &str,
    module: KnownBinding,
) -> Option<Alternative> {
    let module_name = match module {
        KnownBinding::AsyncioModule => "asyncio",
        KnownBinding::TrioModule => "trio",
        KnownBinding::AnyioModule => "anyio",
        _ => return None,
    };
    let display = format!("{alias}.sleep");
    let replacement = if already_awaited {
        display.clone()
    } else {
        format!("await {display}")
    };
    let message = format!("Await {display} instead of blocking the event loop with time.sleep.");
    let edit = text_edit(index, source, function_range, replacement);
    Some(alt(
        format!("s7488-use-async-sleep-{module_name}-{alias}"),
        message,
        vec![edit],
    ))
}

fn s7491(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].to_string();
    if !text.contains("sleep(0") {
        return Vec::new();
    }
    let mut result = Vec::new();
    for module in ["trio", "anyio"] {
        for alias in import_aliases(source, module) {
            let replacement = if alias == "sleep" {
                "checkpoint()".to_string()
            } else {
                format!("{alias}.lowlevel.checkpoint()")
            };
            let replacement = if text.trim_start().starts_with("await ") {
                format!("await {replacement}")
            } else {
                replacement
            };
            let message = format!("Replace sleep(0) with {replacement}.");
            let edit = text_edit(index, source, range, replacement);
            result.push(alt(
                format!("s7491-use-checkpoint-{module}-{alias}"),
                message,
                vec![edit],
            ));
        }
    }
    result
}

fn s7498(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    let replacement = if text.ends_with("dict()") {
        "{}"
    } else if text.ends_with("list()") {
        "[]"
    } else if text.ends_with("tuple()") {
        "()"
    } else {
        return Vec::new();
    };
    vec![alt(
        "s7498-replace-with-literal",
        "Replace with literal",
        vec![text_edit(index, source, range, replacement)],
    )]
}

fn s7501(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    if !text.starts_with("input(") || !text.ends_with(')') {
        return Vec::new();
    }
    let args = &text["input(".len()..text.len() - 1];
    let call_args = if args.trim().is_empty() {
        "input".to_string()
    } else {
        format!("input, {args}")
    };
    let mut result = Vec::new();
    for module in ["asyncio", "trio", "anyio"] {
        for alias in import_aliases(source, module) {
            let replacement = if module == "asyncio" {
                format!("await {alias}.to_thread({call_args})")
            } else {
                format!("await {alias}.to_thread.run_sync({call_args})")
            };
            let edit = text_edit(index, source, range, replacement);
            result.push(alt(
                format!("s7501-run-input-off-loop-{module}-{alias}"),
                format!("Run input asynchronously with {alias}"),
                vec![edit],
            ));
        }
    }
    result
}

fn s7504(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    if !text.starts_with("list(") || !text.ends_with(')') {
        return Vec::new();
    }
    let replacement = text[5..text.len() - 1].trim();
    let edit = text_edit(index, source, range, replacement);
    vec![alt(
        "s7504-iterate-directly",
        "Iterate over the iterable directly",
        vec![edit],
    )]
}

fn s7508(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    let text = source[range].trim();
    let Some(open) = text.find('(') else {
        return Vec::new();
    };
    let constructor = text[..open].trim();
    if !matches!(constructor, "tuple" | "frozenset") {
        return Vec::new();
    }
    let inner = text[open + 1..].strip_suffix(')').unwrap_or("").trim();
    if !inner.starts_with(&format!("{constructor}(")) || !inner.ends_with(')') {
        return Vec::new();
    }
    let edit = text_edit(index, source, range, inner);
    vec![alt(
        "s7508-remove-nested-constructor",
        "Remove the redundant nested call",
        vec![edit],
    )]
}

fn s7517(issue: &Issue, index: &LineIndex, source: &str) -> Vec<Alternative> {
    let range = issue_range(issue, index, source);
    if source[range].trim().is_empty() {
        return Vec::new();
    }
    let insertion = TextRange::new(range.end(), range.end());
    vec![alt(
        "s7517-use-items",
        "Use '.items()' when iterating over dictionary keys and values.",
        vec![text_edit(index, source, insertion, ".items()")],
    )]
}

fn strip_parens(mut text: &str) -> &str {
    loop {
        if !text.starts_with('(') || !text.ends_with(')') {
            return text;
        }
        let Some(close) = matching(text, 0, b'(', b')') else {
            return text;
        };
        if close + 1 != text.len() {
            return text;
        }
        text = text[1..text.len() - 1].trim();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{findings, scan};
    use std::process::{Command, Output};

    fn projected(source: &str, key: &str, id: &str) -> Option<String> {
        let report = scan(source);
        let issue = findings(&report, key).into_iter().next()?;
        let edits = issue
            .alternatives
            .iter()
            .find(|alternative| alternative.id == id)
            .map(|alternative| alternative.fix.edits.clone())?;
        let references: Vec<&TextEdit> = edits.iter().collect();
        hoonarqube_ir::apply_fixes(source, &references).ok()
    }

    fn assert_refused(source: &str, key: &str, id: &str) {
        let report = scan(source);
        let matches = findings(&report, key);
        assert_eq!(matches.len(), 1, "expected exactly one {key} finding");
        assert!(
            !matches[0]
                .alternatives
                .iter()
                .any(|alternative| alternative.id == id),
            "{id} must be withheld"
        );
    }

    fn run_python(source: &str) -> Output {
        Command::new("python3")
            .arg("-c")
            .arg(source)
            .output()
            .expect("run Python quickfix fixture")
    }

    fn assert_same_runtime(original_source: &str, projected_source: &str) {
        let original = run_python(original_source);
        let projected = run_python(projected_source);
        assert_eq!(projected.status, original.status);
        assert_eq!(projected.stdout, original.stdout);
        assert_eq!(projected.stderr, original.stderr);
    }
    fn assert_same_exception_runtime(original_source: &str, projected_source: &str) {
        let original = run_python(original_source);
        let projected = run_python(projected_source);
        assert_eq!(projected.status, original.status);
        assert_eq!(projected.stdout, original.stdout);
        let last_line = |stderr: &[u8]| {
            String::from_utf8_lossy(stderr)
                .lines()
                .last()
                .map(str::to_owned)
        };
        assert_eq!(last_line(&projected.stderr), last_line(&original.stderr));
    }

    #[test]
    fn s2710_renames_declaration_and_all_resolving_references() {
        let source = "other = str\n\n\nclass C:\n    @classmethod\n    def make(other):\n        return other.__name__\n\n\nprint(C.make())\n";
        let projected = projected(source, "python:S2710", "s2710-rename-class-parameter")
            .expect("binding-aware rename expected");
        assert!(projected.contains("def make(cls):"));
        assert!(projected.contains("return cls.__name__"));
        assert_same_runtime(source, &projected);
    }

    #[test]
    fn s2710_renames_nested_references_and_rebindings() {
        let closure = "class C:\n    @classmethod\n    def make(other):\n        def helper():\n            return other.__name__\n        return helper()\n\n\nprint(C.make())\n";
        let closure_projected = projected(closure, "python:S2710", "s2710-rename-class-parameter")
            .expect("nested capture rename expected");
        assert!(closure_projected.contains("return cls.__name__"));
        assert_same_runtime(closure, &closure_projected);

        let rebinding = "class C:\n    @classmethod\n    def make(other):\n        other = 2\n        return other\n";
        let rebinding_projected =
            projected(rebinding, "python:S2710", "s2710-rename-class-parameter")
                .expect("parameter rebinding rename expected");
        assert!(rebinding_projected.contains("cls = 2"));
        assert!(rebinding_projected.contains("return cls"));
    }

    #[test]
    fn s2710_refuses_collisions_and_lexical_directive_changes() {
        assert_refused(
            "class C:\n    @classmethod\n    def make(other):\n        cls = 1\n        return other, cls\n",
            "python:S2710",
            "s2710-rename-class-parameter",
        );
        assert_refused(
            "cls = int\n\n\nclass C:\n    @classmethod\n    def make(other):\n        return other, cls\n",
            "python:S2710",
            "s2710-rename-class-parameter",
        );
        assert_refused(
            "class C:\n    @classmethod\n    def make(other):\n        global cls\n        return other\n",
            "python:S2710",
            "s2710-rename-class-parameter",
        );
        assert_refused(
            "def outer():\n    cls = int\n    class C:\n        @classmethod\n        def make(other):\n            nonlocal cls\n            return other\n",
            "python:S2710",
            "s2710-rename-class-parameter",
        );
        assert_refused(
            "class C:\n    @classmethod\n    def make(other):\n        def inner(cls):\n            return other\n        return inner(1)\n",
            "python:S2710",
            "s2710-rename-class-parameter",
        );
    }

    #[test]
    fn s3923_preserves_condition_truth_testing_and_side_effects() {
        let source = "class Flag:\n    def __bool__(self):\n        print('truth-tested')\n        return True\n\n\ndef select(flag):\n    value = 1\n    if flag:\n        value = 2\n    else:\n        value = 2\n    return value\n\n\nprint(select(Flag()))\n";
        let projected_source = projected(source, "python:S3923", "s3923-remove-if-statement")
            .expect("condition-preserving rewrite expected");
        let projected_report = scan(&projected_source);
        assert!(findings(&projected_report, "python:S3923").is_empty());
        assert!(findings(&projected_report, "python:S108").is_empty());
        assert_same_runtime(source, &projected_source);

        let comparison = "class Flag:\n    def __eq__(self, other):\n        print('comparison-tested')\n        return True\n\n\nleft = Flag()\nright = object()\nvalue = 1\nif left == right:\n    value = 2\nelse:\n    value = 2\nprint(value)\n";
        let comparison_projected =
            projected(comparison, "python:S3923", "s3923-remove-if-statement")
                .expect("comparison-preserving rewrite expected");
        assert_same_runtime(comparison, &comparison_projected);
    }

    #[test]
    fn s3923_preserves_len_and_truth_conversion_exceptions() {
        let len_source = "class Flag:\n    def __len__(self):\n        print('len-tested')\n        return 0\n\n\ndef select(flag):\n    if flag:\n        value = 2\n    else:\n        value = 2\n    return value\n\n\nprint(select(Flag()))\n";
        let len_projected = projected(len_source, "python:S3923", "s3923-remove-if-statement")
            .expect("__len__ condition rewrite expected");
        assert_same_runtime(len_source, &len_projected);

        let exception_source = "class Flag:\n    def __bool__(self):\n        raise RuntimeError('truth-failed')\n\n\nflag = Flag()\nif flag:\n    value = 2\nelse:\n    value = 2\nprint(value)\n";
        let exception_projected = projected(
            exception_source,
            "python:S3923",
            "s3923-remove-if-statement",
        )
        .expect("exception-preserving rewrite expected");
        assert_same_exception_runtime(exception_source, &exception_projected);
        assert!(!run_python(&exception_projected).status.success());
    }

    #[test]
    fn s3923_handles_parenthesized_and_inline_conditions() {
        let parenthesized = "def probe():\n    print('probe-called')\n    return True\n\n\nif (probe()):\n    print('branch')\nelse:\n    print('branch')\n";
        let parenthesized_projected =
            projected(parenthesized, "python:S3923", "s3923-remove-if-statement")
                .expect("parenthesized condition rewrite expected");
        assert_same_runtime(parenthesized, &parenthesized_projected);

        let inline = "def probe():\n    print('probe-called')\n    return True\n\n\nif probe(): print('branch')\nelse: print('branch')\n";
        let inline_projected = projected(inline, "python:S3923", "s3923-remove-if-statement")
            .expect("inline condition rewrite expected");
        assert_same_runtime(inline, &inline_projected);
    }

    #[test]
    fn s3923_refuses_unsafe_or_nonmatching_shapes() {
        let differing = "if flag:\n    value = 2\nelse:\n    value = 3\n";
        assert!(projected(differing, "python:S3923", "s3923-remove-if-statement").is_none());
        let shadowed_bool =
            "bool = lambda value: False\nif flag:\n    value = 2\nelse:\n    value = 2\n";
        assert_refused(shadowed_bool, "python:S3923", "s3923-remove-if-statement");

        let elif_chain =
            "if flag:\n    value = 2\nelif other:\n    value = 2\nelse:\n    value = 2\n";
        assert!(findings(&scan(elif_chain), "python:S3923").is_empty());

        let multiline = "if flag:\n    value = \"\"\"\n        same\n    \"\"\"\nelse:\n    value = \"\"\"\n        same\n    \"\"\"\n";
        assert_refused(multiline, "python:S3923", "s3923-remove-if-statement");
    }
}
