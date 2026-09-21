use crate::JstsLanguage;
use crate::engine::pattern_parser::{regex_can_start, skip_regex_literal};
use hoonarqube_ir::Issue;
use oxc_ast::ast::Statement;
use oxc_span::{GetSpan, SourceType, Span};
use std::collections::BTreeSet;
use std::path::Path;

/// Catalog membership of one rule: which language catalogs contain it and
/// therefore for which file language an issue may be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleScope {
    /// Present in both `javascript` and `typescript` catalogs.
    Both,
    /// `[J]` in the rule-batch classification: `javascript.json` only.
    JsOnly,
    /// `[TS]`: `typescript.json` only.
    TsOnly,
}

impl RuleScope {
    pub(crate) fn active(self, language: JstsLanguage) -> bool {
        match self {
            Self::Both => true,
            Self::JsOnly => language == JstsLanguage::JavaScript,
            Self::TsOnly => language == JstsLanguage::TypeScript,
        }
    }
}

pub(crate) fn source_type_for(language: JstsLanguage, path: &Path) -> SourceType {
    // Oxc distinguishes CommonJS, modules, JSX, and declaration files.
    // Normalize because the repository router accepts extensions without
    // regard to ASCII case.
    let detected = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| SourceType::from_path(name.to_ascii_lowercase()).ok());
    detected
        .map(|source_type| {
            if source_type.is_javascript() {
                // JavaScript tooling commonly accepts JSX in `.js`, `.mjs`,
                // and `.cjs`; Oxc documents that tolerant behavior too.
                source_type.with_jsx(true)
            } else {
                source_type
            }
        })
        .filter(|source_type| match language {
            JstsLanguage::JavaScript => source_type.is_javascript(),
            JstsLanguage::TypeScript => source_type.is_typescript(),
        })
        .unwrap_or_else(|| match language {
            JstsLanguage::JavaScript => SourceType::mjs(),
            JstsLanguage::TypeScript => SourceType::ts(),
        })
}

pub(crate) use hoonarqube_ir::u32_saturating as to_u32;

/// Character-offset line index; positions follow the `SonarQube` convention
/// (`line` 1-based, `column` 0-based **character** offset within the line,
/// not a byte offset). Keeps the source text so columns match the crate's
/// character-counting text scans (`S103` line length, tab columns) and the
/// Python family's Utf32 code-point columns for multi-byte content.
pub(crate) struct LineIndex<'src> {
    pub(crate) line_starts: Vec<u32>,
    source: &'src str,
    /// Last `(line index, byte offset, character count)` resolved by
    /// [`LineIndex::pos`]. Positions are queried in roughly source order
    /// (issue spans, statement spans), so continuing the character count
    /// from the cached offset turns repeated `pos` calls on one long line
    /// into amortized O(1) instead of an O(line length) rescan each time.
    /// Backward or cross-line queries simply recount from the line start,
    /// matching the previous behavior exactly.
    column_cursor: std::cell::Cell<(usize, usize, u32)>,
}

impl<'src> LineIndex<'src> {
    pub(crate) fn new(source: &'src str) -> Self {
        let mut line_starts = vec![0_u32];
        // Byte-level scan: the ECMAScript line terminators are `\n`, `\r`,
        // and the two UTF-8 sequences for U+2028/U+2029, so decoding every
        // character is unnecessary. Offsets pushed are identical to the
        // former `char_indices` walk.
        let bytes = source.as_bytes();
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let line_start = match bytes[offset] {
                b'\r' => {
                    if bytes.get(offset + 1) == Some(&b'\n') {
                        offset + 2
                    } else {
                        offset + 1
                    }
                }
                b'\n' => offset + 1,
                0xE2 if bytes.get(offset..offset + 3) == Some(&[0xE2, 0x80, 0xA8][..])
                    || bytes.get(offset..offset + 3) == Some(&[0xE2, 0x80, 0xA9][..]) =>
                {
                    offset + 3
                }
                _ => {
                    offset += 1;
                    continue;
                }
            };
            line_starts.push(to_u32(line_start));
            offset = line_start;
        }
        Self {
            line_starts,
            source,
            column_cursor: std::cell::Cell::new((0, 0, 0)),
        }
    }

    /// Iterates logical source lines with 1-based line numbers. ECMAScript
    /// line terminators are omitted from each returned line, and the
    /// trailing empty row after a final terminator is not yielded.
    pub(crate) fn lines(&self) -> impl Iterator<Item = (u32, &'src str)> + '_ {
        let source_len = to_u32(self.source.len());
        let mut line_count = self.line_starts.len();
        if self.line_starts.last().copied() == Some(source_len) {
            line_count = line_count.saturating_sub(1);
        }
        let source = self.source;
        let line_starts = &self.line_starts;
        (0..line_count).map(move |zero_based| {
            let start = line_starts[zero_based] as usize;
            let end = line_starts
                .get(zero_based + 1)
                .copied()
                .unwrap_or(source_len) as usize;
            let line = &source[start..end];
            (to_u32(zero_based) + 1, strip_line_terminator(line))
        })
    }

    /// Byte offset where the line containing `offset` begins (for callers
    /// that slice raw source bytes rather than report columns).
    pub(crate) fn line_start(&self, offset: u32) -> u32 {
        self.line_starts[self.line_of(offset) - 1]
    }

    pub(crate) fn pos(&self, offset: u32) -> hoonarqube_ir::Pos {
        // Tolerant rules sometimes derive a nearby token offset. Clamp those
        // callers to a valid UTF-8 boundary so reporting malformed source can
        // never panic.
        let mut offset = usize::try_from(offset)
            .unwrap_or(self.source.len())
            .min(self.source.len());
        while offset > 0 && !self.source.is_char_boundary(offset) {
            offset -= 1;
        }
        let offset = to_u32(offset);
        let line = self.line_of(offset);
        let line_start = self.line_starts[line - 1];
        // Continue the character count from the cached position when the
        // query lands on the same line at or after it; otherwise recount
        // from the line start. Both paths yield the identical column.
        let (cursor_line, cursor_offset, cursor_chars) = self.column_cursor.get();
        let column = if cursor_line == line - 1 && cursor_offset <= offset as usize {
            cursor_chars + to_u32(self.source[cursor_offset..offset as usize].chars().count())
        } else {
            to_u32(
                self.source[line_start as usize..offset as usize]
                    .chars()
                    .count(),
            )
        };
        self.column_cursor.set((line - 1, offset as usize, column));
        hoonarqube_ir::Pos {
            line: to_u32(line),
            column,
        }
    }

    fn line_of(&self, offset: u32) -> usize {
        self.line_starts.partition_point(|&start| start <= offset)
    }

    pub(crate) fn range(&self, span: Span) -> hoonarqube_ir::Range {
        hoonarqube_ir::Range {
            start: self.pos(span.start),
            end: self.pos(span.end),
        }
    }

    /// 1-based lines whose byte interval intersects `span`; a span ending
    /// exactly on a line break stays on its own line.
    pub(crate) fn covered_lines(&self, span: Span) -> std::ops::RangeInclusive<u32> {
        // Only line numbers are needed, so the binary-search `line_of`
        // replaces two `pos` calls that each counted characters across the
        // line prefix — an O(line length) cost per statement that made
        // single-line (minified) sources quadratic.
        let first = to_u32(self.line_of(span.start));
        let mut last = to_u32(self.line_of(span.end));
        if self.line_starts.binary_search(&span.end).is_ok() && last > first {
            last -= 1;
        }
        first..=last
    }

    /// Merged, sorted 1-based line ranges covering `spans`. Adjacent and
    /// overlapping ranges coalesce; the result supports binary-search
    /// membership via [`line_in_ranges`].
    pub(crate) fn merged_line_ranges(
        &self,
        spans: impl IntoIterator<Item = Span>,
    ) -> Vec<(u32, u32)> {
        let mut ranges: Vec<(u32, u32)> = spans
            .into_iter()
            .map(|span| {
                let covered = self.covered_lines(span);
                (*covered.start(), *covered.end())
            })
            // An inverted span covers no lines, matching the empty
            // `RangeInclusive` the per-line iteration produced.
            .filter(|(start, end)| start <= end)
            .collect();
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some((_, last_end)) if start <= last_end.saturating_add(1) => {
                    *last_end = (*last_end).max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        merged
    }

    /// Total number of distinct 1-based lines covered by `spans`.
    pub(crate) fn covered_line_count(&self, spans: impl IntoIterator<Item = Span>) -> usize {
        self.merged_line_ranges(spans)
            .iter()
            .map(|(start, end)| usize::try_from(end - start + 1).unwrap_or(usize::MAX))
            .sum()
    }
}

/// Whether `line` (1-based) lies inside one of the merged ranges produced
/// by [`LineIndex::merged_line_ranges`].
pub(crate) fn line_in_ranges(ranges: &[(u32, u32)], line: u32) -> bool {
    let index = ranges.partition_point(|(start, _)| *start <= line);
    index > 0 && ranges[index - 1].1 >= line
}

fn strip_line_terminator(line: &str) -> &str {
    line.strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\r'))
        .or_else(|| line.strip_suffix('\n'))
        .or_else(|| line.strip_suffix('\u{2028}'))
        .or_else(|| line.strip_suffix('\u{2029}'))
        .unwrap_or(line)
}

pub(crate) use hoonarqube_ir::sort_issues;

pub(crate) fn file_metrics(
    body: &[Statement<'_>],
    source: &str,
    index: &LineIndex,
    comments: &[ScannedComment],
) -> hoonarqube_ir::FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        let mut line_count = index.line_starts.len();
        if index.line_starts.last().copied() == Some(to_u32(source.len())) {
            line_count = line_count.saturating_sub(1);
        }
        to_u32(line_count)
    };

    // Code lines derive from statement spans; the oxc lexer skips comments
    // entirely (no trivia tokens exist), so comment rows derive from the one
    // scanner pass stored on `AnalysisContext` (`covered_lines` spans every
    // row a comment token covers, including multi-line block interiors).
    // Statement coverage is merged into intervals instead of materializing
    // every covered row: a single multi-thousand-line function inserts one
    // range, not one set entry per line.
    let code_ranges = index.merged_line_ranges(body.iter().map(GetSpan::span));
    let code_lines: usize = code_ranges
        .iter()
        .map(|(start, end)| usize::try_from(end - start + 1).unwrap_or(usize::MAX))
        .sum();
    let comment_rows: BTreeSet<u32> = comments
        .iter()
        .flat_map(|comment| index.covered_lines(comment.token))
        .filter(|row| !line_in_ranges(&code_ranges, *row))
        .collect();

    hoonarqube_ir::FileMetrics {
        lines,
        code_lines: to_u32(code_lines),
        comment_lines: to_u32(comment_rows.len()),
    }
}

/// Byte offset of the first `needle` occurrence in `haystack` at or after
/// `offset`, comparing ASCII case-insensitively. Equivalent to searching
/// `haystack.to_ascii_lowercase()` for an ASCII-lowercase `needle` (the
/// lowercase map is byte-position preserving), without materializing the
/// lowered copy.
pub(crate) fn find_ascii_case_insensitive(
    haystack: &[u8],
    needle: &[u8],
    offset: usize,
) -> Option<usize> {
    let last_start = haystack.len().checked_sub(needle.len())?;
    (offset..=last_start)
        .find(|index| haystack[*index..*index + needle.len()].eq_ignore_ascii_case(needle))
}

pub(crate) fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    find_ascii_case_insensitive(haystack, needle, 0).is_some()
}

/// Byte spans of one scanned comment: `token` covers the delimiters
/// (`// …`, `/* … */`), `body` only the text between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScannedComment {
    pub(crate) token: Span,
    pub(crate) body: Span,
}

/// One-pass scanner over raw source collecting comments with their byte
/// spans, in source order. Understands `'…'`, `"…"`, template literals with
/// `${}` nesting, and a regex-literal heuristic (`/` after an operator,
/// opening delimiter, or keyword such as `return` starts a regex, not a
/// division).
///
/// Runs once per analyzed file in `analyze_with_rules`; rule checks consume
/// the resulting slice stored on `AnalysisContext`.
pub(crate) fn scan_comments(source: &str) -> Vec<ScannedComment> {
    let mut scan = Scanner::new(source);
    scan.run();
    scan.comments
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ScanState {
    Code,
    LineComment,
    BlockComment,
    SingleQuote,
    DoubleQuote,
    Template,
}

fn is_ecmascript_line_terminator(character: char) -> bool {
    matches!(character, '\r' | '\n' | '\u{2028}' | '\u{2029}')
}

pub(crate) struct Scanner<'a> {
    /// Raw source; the scan decodes characters on demand instead of
    /// materializing `Vec<char>`/`Vec<u32>` copies of the whole file.
    pub(crate) source: &'a str,
    pub(crate) source_len: u32,
    pub(crate) state: ScanState,
    /// States suspended by `${` inside template literals, each with the
    /// open-brace depth of its substitution so nested `{ … }` blocks do not
    /// end it prematurely.
    pub(crate) template_stack: Vec<(ScanState, u32)>,
    pub(crate) prev_significant: Option<char>,
    pub(crate) prev_word: String,
    pub(crate) comments: Vec<ScannedComment>,
    /// `(token start, body start)` of the comment currently being consumed.
    pub(crate) open_comment: Option<(u32, u32)>,
}

impl<'a> Scanner<'a> {
    pub(crate) fn new(source: &'a str) -> Self {
        Self {
            source,
            source_len: to_u32(source.len()),
            state: ScanState::Code,
            template_stack: Vec::new(),
            prev_significant: None,
            prev_word: String::new(),
            comments: Vec::new(),
            open_comment: None,
        }
    }

    /// Character at byte offset `i` (`i` is always a char boundary).
    fn char_at(&self, i: usize) -> Option<char> {
        self.source.get(i..)?.chars().next()
    }

    pub(crate) fn run(&mut self) {
        let mut i = 0_usize;
        while i < self.source.len() {
            let Some(c) = self.char_at(i) else {
                break;
            };
            if is_ecmascript_line_terminator(c) {
                if self.state == ScanState::LineComment {
                    self.close_comment(to_u32(i), to_u32(i));
                    self.state = ScanState::Code;
                }
                i += c.len_utf8();
                if c == '\r' && self.char_at(i) == Some('\n') {
                    i += 1;
                }
            } else {
                let next = self.char_at(i + c.len_utf8());
                let (jump, _) = self.step(i, c, next);
                i += jump;
            }
        }
        // Unterminated `//` or `/* …` at end of file still yields a span.
        self.close_comment(self.source_len, self.source_len);
    }

    /// Records a comment that starts at byte offset `i` (byte span starts
    /// there, body after the two delimiter characters).
    pub(crate) fn open_comment(&mut self, i: usize) {
        let token_start = to_u32(i);
        self.open_comment = Some((token_start, token_start + 2));
    }

    /// Closes the currently open comment at byte offset `end` (exclusive for
    /// the body, inclusive for the token).
    pub(crate) fn close_comment(&mut self, token_end: u32, body_end: u32) {
        if let Some((token_start, body_start)) = self.open_comment.take() {
            self.comments.push(ScannedComment {
                token: Span::new(token_start, token_end),
                body: Span::new(body_start, body_end),
            });
        }
    }

    /// Advances one non-newline character; returns `(bytes consumed, whether
    /// a comment starts here)`.
    pub(crate) fn step(&mut self, i: usize, c: char, next: Option<char>) -> (usize, bool) {
        match self.state {
            ScanState::Code => self.step_code(i, c, next),
            ScanState::LineComment => (c.len_utf8(), false),
            ScanState::BlockComment => {
                let closing = c == '*' && next == Some('/');
                if closing {
                    self.close_comment(to_u32(i) + 2, to_u32(i));
                    self.state = ScanState::Code;
                }
                (if closing { 2 } else { c.len_utf8() }, closing)
            }
            ScanState::SingleQuote => self.step_quoted(c, next, '\''),
            ScanState::DoubleQuote => self.step_quoted(c, next, '"'),
            ScanState::Template => self.step_template(c, next),
        }
    }

    pub(crate) fn step_code(&mut self, i: usize, c: char, next: Option<char>) -> (usize, bool) {
        if c == '{'
            && let Some((_, depth)) = self.template_stack.last_mut()
        {
            // A `{ … }` block opened inside a `${ … }` substitution.
            *depth += 1;
        }
        if c == '}'
            && let Some((_, depth)) = self.template_stack.last_mut()
        {
            if *depth > 0 {
                // Closes a block inside the substitution; it continues.
                *depth -= 1;
                return (1, false);
            }
            let (resumed, _) = self.template_stack.pop().unwrap_or((ScanState::Code, 0));
            // `${ … }` ends; resume the suspended template literal.
            self.state = resumed;
            self.prev_significant = Some('`');
            return (1, false);
        }
        if c == '/' && next == Some('/') {
            self.open_comment(i);
            self.state = ScanState::LineComment;
            return (2, true);
        }
        if c == '/' && next == Some('*') {
            self.open_comment(i);
            self.state = ScanState::BlockComment;
            return (2, true);
        }
        if c == '/' && regex_can_start(self.prev_significant, &self.prev_word) {
            self.prev_word.clear();
            self.prev_significant = Some('/');
            return (skip_regex_literal(self.source, i + 1) - i, false);
        }
        match c {
            '\'' => self.state = ScanState::SingleQuote,
            '"' => self.state = ScanState::DoubleQuote,
            '`' => self.state = ScanState::Template,
            _ => {}
        }
        if c.is_alphanumeric() || c == '_' || c == '$' {
            self.prev_word.push(c);
        } else {
            self.prev_word.clear();
        }
        if !c.is_whitespace() {
            self.prev_significant = Some(c);
        }
        (c.len_utf8(), false)
    }

    pub(crate) fn step_quoted(
        &mut self,
        c: char,
        next: Option<char>,
        quote: char,
    ) -> (usize, bool) {
        if c == '\\' {
            // Consume the escaped character too; a dangling backslash at end
            // of input consumes one byte past it, ending the scan.
            (1 + next.map_or(1, char::len_utf8), false)
        } else {
            if c == quote {
                self.state = ScanState::Code;
                self.prev_significant = Some(quote);
            }
            (c.len_utf8(), false)
        }
    }

    pub(crate) fn step_template(&mut self, c: char, next: Option<char>) -> (usize, bool) {
        if c == '\\' {
            (1 + next.map_or(1, char::len_utf8), false)
        } else if c == '`' {
            self.state = ScanState::Code;
            self.prev_significant = Some('`');
            (1, false)
        } else if c == '$' && next == Some('{') {
            self.template_stack.push((ScanState::Template, 0));
            self.state = ScanState::Code;
            self.prev_significant = Some('(');
            (2, false)
        } else {
            (c.len_utf8(), false)
        }
    }
}

/// One finding covering `span`, positioned through [`LineIndex`].
pub(crate) fn span_issue(
    index: &LineIndex,
    rule_key: String,
    message: impl Into<String>,
    span: Span,
) -> Issue {
    Issue {
        rule_key,
        message: message.into(),
        range: index.range(span),
        fix: None,
        flows: Vec::new(),
        alternatives: Vec::new(),
    }
}

/// Central issue emitter: applies catalog scope gating, the language rule-key
/// prefix, and `LineIndex` positioning for every batch rule.
pub(crate) struct IssueSink<'index> {
    pub(crate) index: &'index LineIndex<'index>,
    pub(crate) language: JstsLanguage,
    pub(crate) issues: Vec<Issue>,
}

impl IssueSink<'_> {
    pub(crate) fn emit_span(&mut self, scope: RuleScope, rule: &str, message: &str, span: Span) {
        if !scope.active(self.language) {
            return;
        }
        self.issues.push(span_issue(
            self.index,
            format!("{}:{rule}", self.language.prefix()),
            message,
            span,
        ));
    }

    pub(crate) fn emit_pos(
        &mut self,
        scope: RuleScope,
        rule: &str,
        message: &str,
        start: (u32, u32),
        end: (u32, u32),
    ) {
        if !scope.active(self.language) {
            return;
        }
        self.issues.push(Issue {
            rule_key: format!("{}:{rule}", self.language.prefix()),
            message: message.to_string(),
            range: hoonarqube_ir::Range {
                start: hoonarqube_ir::Pos {
                    line: start.0,
                    column: start.1,
                },
                end: hoonarqube_ir::Pos {
                    line: end.0,
                    column: end.1,
                },
            },
            fix: None,
            flows: Vec::new(),
            alternatives: Vec::new(),
        });
    }
}

/// Whether the raw source text of `span` contains `needle` (used where the
/// AST cannot distinguish `import {a}` from `import {a as a}`).
pub(crate) fn span_text_contains(source: &str, span: Span, needle: &str) -> bool {
    let start = usize::try_from(span.start).unwrap_or(0);
    let end = usize::try_from(span.end).unwrap_or(source.len());
    source
        .get(start..end.min(source.len()))
        .is_some_and(|text| text.contains(needle))
}

/// Raw source text of `span`, or an empty string when out of bounds.
pub(crate) fn span_text(source: &str, span: Span) -> &str {
    let start = usize::try_from(span.start).unwrap_or(0);
    let end = usize::try_from(span.end).unwrap_or(source.len());
    source.get(start..end.min(source.len())).unwrap_or_default()
}

/// Shannon entropy in bits per character of `value`.
pub(crate) fn shannon_entropy_per_char(value: &str) -> f64 {
    let mut counts = std::collections::BTreeMap::new();
    let mut total = 0_usize;
    for c in value.chars() {
        *counts.entry(c).or_insert(0_usize) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = f64::from(to_u32(total));
    counts
        .values()
        .map(|&count| {
            let probability = f64::from(to_u32(count)) / total;
            -probability * probability.log2()
        })
        .sum()
}

/// Whether a string literal's value embeds a `credential=` / `credential:`
/// pair for one of `words` — the value-shape scan shared with the Python
/// family's `embeds_credential` (`S2068`). Matching is case-insensitive;
/// only spaces and tabs may separate word, separator, and first value
/// character, mirroring the reference implementation.
pub(crate) fn embeds_credential(text: &str, words: &[String]) -> bool {
    let lower = text.to_lowercase();
    words.iter().any(|word| {
        let word = word.to_lowercase();
        lower.match_indices(word.as_str()).any(|(position, _)| {
            let rest = lower[position + word.len()..].trim_start_matches([' ', '\t']);
            let Some(separator) = rest.chars().next() else {
                return false;
            };
            (separator == '=' || separator == ':')
                && rest[1..]
                    .trim_start_matches([' ', '\t'])
                    .chars()
                    .next()
                    .is_some_and(|ch| !ch.is_whitespace())
        })
    })
}

pub(crate) fn source_slice(source: &str, span: Span) -> &str {
    let start = usize::try_from(span.start).unwrap_or(0);
    let end = usize::try_from(span.end).unwrap_or(source.len());
    source.get(start..end).unwrap_or("")
}

pub(crate) fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

/// Byte offset of the last character before `offset` that is neither
/// whitespace nor part of a comment; `None` when only trivia precedes.
/// `//` comment lines and `/* … */` comments are skipped in full so the scan
/// lands on the token before the trivia run.
pub(crate) fn previous_non_trivia_offset(source: &str, offset: u32) -> Option<u32> {
    let bytes = source.as_bytes();
    let mut i = usize::try_from(offset)
        .unwrap_or(bytes.len())
        .min(bytes.len());
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b'\n' => {
                if line_is_comment_only(bytes, i) {
                    i = line_start(bytes, i);
                }
            }
            b' ' | b'\t' | b'\r' => {}
            b'/' if i > 0 && bytes[i - 1] == b'*' => {
                // Tail of a block comment: resume before its head.
                let mut j = i - 1;
                while j > 0 && !(bytes[j] == b'*' && bytes[j - 1] == b'/') {
                    j -= 1;
                }
                if j == 0 {
                    return None;
                }
                i = j - 1;
            }
            _ => return Some(to_u32(i)),
        }
    }
    None
}

/// Start offset of the line whose newline sits at `newline_index`.
pub(crate) fn line_start(bytes: &[u8], newline_index: usize) -> usize {
    let mut j = newline_index;
    while j > 0 && bytes[j - 1] != b'\n' {
        j -= 1;
    }
    j
}

/// Whether the line ending at `newline_index` carries nothing but a `//`
/// comment (leading whitespace allowed).
pub(crate) fn line_is_comment_only(bytes: &[u8], newline_index: usize) -> bool {
    let start = line_start(bytes, newline_index);
    let mut k = start;
    while k < newline_index && (bytes[k] == b' ' || bytes[k] == b'\t') {
        k += 1;
    }
    k + 1 < bytes.len() && bytes[k] == b'/' && bytes[k + 1] == b'/'
}

/// First non-trivia byte offset at or after `start`, skipping whitespace and
/// comments; `None` at end of input.
pub(crate) fn next_non_trivia_offset(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2.min(bytes.len() - i);
            }
            _ => return Some(i),
        }
    }
    None
}

/// Whether `path` looks like a test file (`foo.test.js`, `foo.spec.ts`, or
/// anywhere under a `__tests__` directory), matching the pinned server's
/// filename-based MAIN/TEST classification shared by scoped rules.
pub(crate) fn is_test_file(path: &Path) -> bool {
    let stem_is_test =
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| match stem.rsplit_once('.') {
                Some((_, extension)) => {
                    matches!(extension.to_ascii_lowercase().as_str(), "test" | "spec")
                }
                None => false,
            });
    let in_tests_dir = path
        .components()
        .any(|component| component.as_os_str() == "__tests__");
    stem_is_test || in_tests_dir
}

pub(crate) use ast::{
    assignment_target_name, binding_identifier_name, callee_name, constructor_name,
    expression_root_name, identifier_name, member_object, member_root_name, member_rooted_at,
    module_export_name_name, property_key_name, statement_as_expression, static_property_name,
    unparenthesized, update_target_name,
};
pub(crate) mod ast;
#[cfg(test)]
mod scanner_tests {
    use super::*;
    use crate::test_support::{count_key, js, js_keys, pos};

    #[test]
    fn source_type_preserves_path_semantics_case_insensitively() {
        let jsx = source_type_for(JstsLanguage::JavaScript, Path::new("Component.JS"));
        assert!(jsx.is_jsx());
        assert!(jsx.is_unambiguous());

        let cjs = source_type_for(JstsLanguage::JavaScript, Path::new("module.CJS"));
        assert!(cjs.is_commonjs());
        assert!(cjs.is_jsx());

        let tsx = source_type_for(JstsLanguage::TypeScript, Path::new("Component.TSX"));
        assert!(tsx.is_typescript());
        assert!(tsx.is_jsx());

        let declaration = source_type_for(JstsLanguage::TypeScript, Path::new("types.D.CTS"));
        assert!(declaration.is_typescript_definition());
        assert!(declaration.is_commonjs());
    }

    #[test]
    fn line_index_clamps_synthetic_offsets_to_utf8_boundaries() {
        let source = "café";
        let index = LineIndex::new(source);
        assert_eq!(index.pos(4), hoonarqube_ir::Pos { line: 1, column: 3 });
        assert_eq!(
            index.pos(u32::MAX),
            hoonarqube_ir::Pos { line: 1, column: 4 }
        );
    }

    #[test]
    fn line_index_handles_ecmascript_terminators_and_unicode_columns() {
        let source = "é\r\nβ\u{2028}γ\u{2029}δ\n";
        let index = LineIndex::new(source);
        assert_eq!(index.line_starts, vec![0, 4, 9, 14, 17]);
        assert_eq!(
            index.lines().collect::<Vec<_>>(),
            vec![(1, "é"), (2, "β"), (3, "γ"), (4, "δ")]
        );
        assert_eq!(index.pos(2), hoonarqube_ir::Pos { line: 1, column: 1 });
        assert_eq!(index.pos(4), hoonarqube_ir::Pos { line: 2, column: 0 });
        assert_eq!(index.pos(6), hoonarqube_ir::Pos { line: 2, column: 1 });
        assert_eq!(index.pos(9), hoonarqube_ir::Pos { line: 3, column: 0 });
        assert_eq!(index.pos(11), hoonarqube_ir::Pos { line: 3, column: 1 });
        assert_eq!(index.pos(14), hoonarqube_ir::Pos { line: 4, column: 0 });
        assert_eq!(index.pos(16), hoonarqube_ir::Pos { line: 4, column: 1 });
        assert_eq!(index.pos(17), hoonarqube_ir::Pos { line: 5, column: 0 });
        assert_eq!(index.covered_lines(Span::new(0, 4)), 1..=1);
        assert_eq!(index.covered_lines(Span::new(4, 9)), 2..=2);
        assert_eq!(index.covered_lines(Span::new(0, 14)), 1..=3);
    }

    #[test]
    fn line_index_retains_lf_line_starts_and_covered_lines() {
        let source = "first\nsecond\n";
        let index = LineIndex::new(source);
        assert_eq!(index.line_starts, vec![0, 6, 13]);
        assert_eq!(index.pos(6), hoonarqube_ir::Pos { line: 2, column: 0 });
        assert_eq!(index.covered_lines(Span::new(0, 6)), 1..=1);
    }

    #[test]
    fn cr_line_comments_close_and_metrics_follow_each_line() {
        let source = "// TODO\rconst x=1;\rconst y=2;";
        let report = js(source);
        let todo_positions: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S1135")
            .map(|issue| {
                (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.range.end.line,
                    issue.range.end.column,
                )
            })
            .collect();
        assert_eq!(todo_positions, vec![(1, 3, 1, 7)]);
        assert_eq!(comment_bodies(source), vec![" TODO"]);
        assert_eq!(report.metrics.lines, 3);
        assert_eq!(report.metrics.code_lines, 2);
        assert_eq!(report.metrics.comment_lines, 1);

        let clean = js("const x=1\rconst y=2");
        assert!(scan_comments("const x=1\rconst y=2").is_empty());
        assert_eq!(clean.metrics.lines, 2);
        assert_eq!(clean.metrics.code_lines, 2);
        assert_eq!(clean.metrics.comment_lines, 0);
    }

    #[test]
    fn crlf_line_comments_close_once_and_keep_line_starts_unique() {
        let source = "// TODO\r\nconst x=1;\r\nconst y=2;";
        let index = LineIndex::new(source);
        assert_eq!(index.line_starts, vec![0, 9, 21]);

        let report = js(source);
        let todo_positions: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S1135")
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(todo_positions, vec![(1, 3)]);
        assert_eq!(comment_bodies(source), vec![" TODO"]);
        assert_eq!(report.metrics.lines, 3);
        assert_eq!(report.metrics.code_lines, 2);
        assert_eq!(report.metrics.comment_lines, 1);
    }

    #[test]
    fn unicode_line_comments_close_and_metrics_use_unicode_breaks() {
        let source = "// TODO\u{2028}const x=1;\u{2029}// TODO";
        let index = LineIndex::new(source);
        assert_eq!(index.line_starts, vec![0, 10, 23]);

        let report = js(source);
        let todo_positions: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S1135")
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(todo_positions, vec![(1, 3), (3, 3)]);
        assert_eq!(comment_bodies(source), vec![" TODO", " TODO"]);
        assert_eq!(report.metrics.lines, 3);
        assert_eq!(report.metrics.code_lines, 1);
        assert_eq!(report.metrics.comment_lines, 2);

        let clean = js("const x=1\u{2028}const y=2");
        assert!(scan_comments("const x=1\u{2028}const y=2").is_empty());
        assert_eq!(clean.metrics.lines, 2);
        assert_eq!(clean.metrics.code_lines, 2);
        assert_eq!(clean.metrics.comment_lines, 0);
    }

    #[test]
    fn line_terminators_inside_literals_and_block_comments_do_not_start_comments() {
        let source = "const single = '// hidden\rTODO'; const template = `// hidden\u{2028}TODO`; \
             /* // hidden\u{2029} */\n// TODO";
        assert_eq!(comment_bodies(source), vec![" // hidden\u{2029} ", " TODO"]);
    }

    fn comment_bodies(source: &str) -> Vec<&str> {
        scan_comments(source)
            .iter()
            .map(|comment| source_slice(source, comment.body))
            .collect()
    }

    #[test]
    fn simple_substitution_still_ends_at_own_closing_brace() {
        let source = "const s = `${a}b`;\n// tail note\n";
        assert_eq!(comment_bodies(source), vec![" tail note"]);
    }

    #[test]
    fn block_body_inside_substitution_keeps_comments_visible() {
        let source = "const s = `${xs.map(x => { /* inner */ return x; })}`;\n// TODO fix\n";
        assert_eq!(comment_bodies(source), vec![" inner ", " TODO fix"]);

        let flagged = js_keys("const s = `${xs.map(x => { return x; })}`;\n// TODO refactor\n");
        assert!(count_key(&flagged, "javascript:S1135") >= 1);
    }

    #[test]
    fn braced_substitution_without_later_backtick_keeps_comments() {
        let source = "const s = `${ {a: 1} \n// gone\n";
        assert_eq!(comment_bodies(source), vec![" gone"]);
    }

    #[test]
    fn object_literal_braces_inside_substitution_balance() {
        let source = "const s = `${ {a: 1}.a }`;\n// after\n";
        assert_eq!(comment_bodies(source), vec![" after"]);
    }
    #[test]
    fn nested_template_inside_substitution_scopes_depth_per_frame() {
        let source = "const v = `${x ? `${y}zz` : w}`;\n// note\n";
        assert_eq!(comment_bodies(source), vec![" note"]);
    }

    #[test]
    fn braces_track_per_template_frame_independently() {
        let source = "const v = `${ fn({ k: `${ {m: 1}.m }` }) }`;\n// note\n";
        assert_eq!(comment_bodies(source), vec![" note"]);
    }

    /// Byte-level scanner equivalence fixture: multi-byte characters,
    /// U+2028/U+2029 inside strings and comments, escapes (including a
    /// dangling backslash), regex literals versus division, nested
    /// templates with `${}` blocks, and an unterminated trailing comment.
    /// Expected spans were produced by the former `Vec<char>` scanner.
    const BYTE_SCAN_SOURCE: &str = "const caf\u{e9} = 'na\u{ef}ve';\n// comment \u{fc}\u{f1}\u{ef}code \u{2029}inside\nconst re = /ab[c\\/]d\\\\/gi;\nconst div = x / y / z;\nconst t = `outer ${ { /* inner */ a: 1 } } tail ${`n${deep}`}`;\nconst esc = 'q\\'s \\\\';\n/* block\n   multi \u{fc}\u{f1}\u{ef}code */\nconst after = 1; // trailing\nconst r2 = return2 / 3;\nconst r3 = return /re$/;\nconst u = '\u{2028}';\u{2028}const v = 2;\u{2029}// last comment";

    #[test]
    fn byte_scanner_matches_char_scanner_spans() {
        let comments = scan_comments(BYTE_SCAN_SOURCE);
        let spans: Vec<(u32, u32, u32, u32)> = comments
            .iter()
            .map(|comment| {
                (
                    comment.token.start,
                    comment.token.end,
                    comment.body.start,
                    comment.body.end,
                )
            })
            .collect();
        // The U+2029 inside the first comment terminates it mid-comment
        // (line terminators close comments regardless of state); the
        // U+2028 inside the string literal is a line break for the index
        // but not a comment boundary.
        assert_eq!(
            spans,
            vec![
                (24, 46, 26, 46),
                (128, 139, 130, 137),
                (193, 224, 195, 222),
                (242, 253, 244, 253),
                (337, 352, 339, 352),
            ]
        );
        let bodies: Vec<&str> = comments
            .iter()
            .map(|comment| source_slice(BYTE_SCAN_SOURCE, comment.body))
            .collect();
        assert_eq!(
            bodies,
            vec![
                " comment \u{fc}\u{f1}\u{ef}code ",
                " inner ",
                " block\n   multi \u{fc}\u{f1}\u{ef}code ",
                " trailing",
                " last comment",
            ]
        );
    }

    #[test]
    fn byte_scanner_metrics_and_positions_match_baseline() {
        let report = js(BYTE_SCAN_SOURCE);
        assert_eq!(report.metrics.lines, 16);
        // The U+2028-in-string parse error leaves an empty program body, so
        // `analyze` reports zero code lines and every comment row counts
        // (the CLI's 12/4 come from tree-sitter source_facts, a different
        // observable surface). Comment tokens land on lines {2,6,8,9,10,16}.
        assert_eq!(report.metrics.code_lines, 0);
        assert_eq!(report.metrics.comment_lines, 6);
        // `return /re$/` on line 12 is a parse error (S2260) spanning that
        // line; the U+2029 inside the comment leaves trailing whitespace
        // (S1131) before it.
        let s2260 = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S2260")
            .expect("parse error finding");
        assert_eq!(s2260.range.start, pos(12, 0));
        assert_eq!(s2260.range.end, pos(12, 24));
        let s1131 = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S1131")
            .expect("trailing whitespace finding");
        assert_eq!(s1131.range.start, pos(2, 18));
        assert_eq!(s1131.range.end, pos(2, 19));
        let s113 = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S113")
            .expect("missing newline finding");
        assert_eq!(s113.range.start, pos(16, 0));
        assert_eq!(s113.range.end, pos(16, 15));
    }

    #[test]
    fn pos_cursor_handles_forward_backward_and_mid_utf8_queries() {
        // Mixed-direction queries over multi-byte content: the cursor must
        // continue forward counts and recount backward/cross-line queries
        // from the line start, always yielding the baseline column.
        let index = LineIndex::new(BYTE_SCAN_SOURCE);
        let expected = [
            (0, pos(1, 0)),
            (9, pos(1, 9)),
            (10, pos(1, 9)),
            (11, pos(1, 10)),
            (17, pos(1, 16)),
            (18, pos(1, 16)),
            (19, pos(1, 17)),
            (24, pos(2, 0)),
            (34, pos(2, 10)),
            (35, pos(2, 11)),
            (36, pos(2, 11)),
            (45, pos(2, 18)),
            (46, pos(2, 19)),
            (47, pos(2, 19)),
            (48, pos(2, 19)),
            (55, pos(3, 6)),
            (100, pos(5, 17)),
            (128, pos(6, 22)),
            (163, pos(6, 57)),
            (200, pos(8, 7)),
            (293, pos(12, 15)),
            (307, pos(13, 4)),
            (308, pos(13, 5)),
            (309, pos(13, 6)),
            (310, pos(13, 7)),
            (322, pos(15, 0)),
            (323, pos(15, 1)),
            (352, pos(16, 15)),
            (351, pos(16, 14)),
            (350, pos(16, 13)),
        ];
        for (offset, expected_pos) in expected {
            assert_eq!(index.pos(offset), expected_pos, "offset {offset}");
        }
        // Reverse order exercises the recount path after the cursor moved.
        for (offset, expected_pos) in expected.iter().rev() {
            assert_eq!(index.pos(*offset), *expected_pos, "offset {offset}");
        }
    }

    #[test]
    fn merged_line_ranges_union_and_membership() {
        let index = LineIndex::new("a\nb\nc\nd\ne\nf\ng\nh\n");
        let ranges = index.merged_line_ranges([
            Span::new(0, 4),
            Span::new(4, 8),
            Span::new(10, 11),
            Span::new(12, 16),
        ]);
        assert_eq!(ranges, vec![(1, 4), (6, 8)]);
        assert!(line_in_ranges(&ranges, 2));
        assert!(line_in_ranges(&ranges, 7));
        assert!(!line_in_ranges(&ranges, 5));
        assert!(!line_in_ranges(&ranges, 9));
        let count = index.covered_line_count([
            Span::new(0, 4),
            Span::new(4, 8),
            Span::new(10, 11),
            Span::new(12, 16),
        ]);
        assert_eq!(count, 7);
    }

    #[test]
    fn find_ascii_case_insensitive_short_and_empty_haystacks() {
        // Needle longer than haystack must return None, never panic
        // (regression: saturating_sub yielded a 0..=0 range that sliced
        // past the end).
        assert_eq!(find_ascii_case_insensitive(b"ab", b"abc", 0), None);
        assert_eq!(find_ascii_case_insensitive(b"", b"a", 0), None);
        assert_eq!(find_ascii_case_insensitive(b"", b"", 0), Some(0));
        assert_eq!(find_ascii_case_insensitive(b"abc", b"", 2), Some(2));
        assert_eq!(find_ascii_case_insensitive(b"abc", b"", 4), None);
        assert_eq!(find_ascii_case_insensitive(b"abc", b"c", 3), None);
        assert_eq!(find_ascii_case_insensitive(b"abc", b"C", 2), Some(2));
        assert!(!contains_ascii_case_insensitive(b"ab", b"abc"));
        assert!(contains_ascii_case_insensitive(b"Ab", b"aB"));
    }
}
