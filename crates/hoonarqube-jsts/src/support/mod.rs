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
}

impl<'src> LineIndex<'src> {
    pub(crate) fn new(source: &'src str) -> Self {
        let mut line_starts = vec![0_u32];
        for (offset, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(to_u32(offset + 1));
            }
        }
        Self {
            line_starts,
            source,
        }
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
        let column = to_u32(
            self.source[line_start as usize..offset as usize]
                .chars()
                .count(),
        );
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
        let first = self.pos(span.start).line;
        let mut last = self.pos(span.end).line;
        if self.line_starts.binary_search(&span.end).is_ok() && last > first {
            last -= 1;
        }
        first..=last
    }
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
        to_u32(source.lines().count())
    };

    // Code lines derive from statement spans; the oxc lexer skips comments
    // entirely (no trivia tokens exist), so comment rows derive from the one
    // scanner pass stored on `AnalysisContext` (`covered_lines` spans every
    // row a comment token covers, including multi-line block interiors).
    let code_lines: BTreeSet<u32> = body
        .iter()
        .flat_map(|statement| index.covered_lines(statement.span()))
        .collect();
    let comment_rows: BTreeSet<u32> = comments
        .iter()
        .flat_map(|comment| index.covered_lines(comment.token))
        .filter(|row| !code_lines.contains(row))
        .collect();

    hoonarqube_ir::FileMetrics {
        lines,
        code_lines: to_u32(code_lines.len()),
        comment_lines: to_u32(comment_rows.len()),
    }
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

pub(crate) struct Scanner {
    pub(crate) chars: Vec<char>,
    /// Byte offset of `chars[i]`, kept parallel so spans stay byte-accurate.
    pub(crate) offsets: Vec<u32>,
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

impl Scanner {
    pub(crate) fn new(source: &str) -> Self {
        let chars: Vec<char> = source.chars().collect();
        let mut offsets = Vec::with_capacity(chars.len());
        let mut byte = 0_u32;
        for c in &chars {
            offsets.push(byte);
            byte += to_u32(c.len_utf8());
        }
        Self {
            offsets,
            source_len: to_u32(source.len()),
            chars,
            state: ScanState::Code,
            template_stack: Vec::new(),
            prev_significant: None,
            prev_word: String::new(),
            comments: Vec::new(),
            open_comment: None,
        }
    }

    pub(crate) fn run(&mut self) {
        let mut i = 0;
        while i < self.chars.len() {
            let c = self.chars[i];
            if c == '\n' {
                if self.state == ScanState::LineComment {
                    self.close_comment(self.offsets[i], self.offsets[i]);
                    self.state = ScanState::Code;
                }
                i += 1;
            } else {
                let next = self.chars.get(i + 1).copied();
                let (jump, _) = self.step(i, c, next);
                i += jump;
            }
        }
        // Unterminated `//` or `/* …` at end of file still yields a span.
        self.close_comment(self.source_len, self.source_len);
    }

    /// Records a comment that starts at `i` (byte span starts there, body
    /// after the two delimiter characters).
    pub(crate) fn open_comment(&mut self, i: usize) {
        let token_start = self.offsets[i];
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

    /// Advances one non-newline character; returns `(chars consumed, whether
    /// a comment starts here)`.
    pub(crate) fn step(&mut self, i: usize, c: char, next: Option<char>) -> (usize, bool) {
        match self.state {
            ScanState::Code => self.step_code(i, c, next),
            ScanState::LineComment => (1, false),
            ScanState::BlockComment => {
                let closing = c == '*' && next == Some('/');
                if closing {
                    self.close_comment(self.offsets[i] + 2, self.offsets[i]);
                    self.state = ScanState::Code;
                }
                (if closing { 2 } else { 1 }, closing)
            }
            ScanState::SingleQuote => self.step_quoted(c, '\''),
            ScanState::DoubleQuote => self.step_quoted(c, '"'),
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
            return (skip_regex_literal(&self.chars, i + 1) - i, false);
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
        (1, false)
    }

    pub(crate) fn step_quoted(&mut self, c: char, quote: char) -> (usize, bool) {
        if c == '\\' {
            (2, false)
        } else {
            if c == quote {
                self.state = ScanState::Code;
                self.prev_significant = Some(quote);
            }
            (1, false)
        }
    }

    pub(crate) fn step_template(&mut self, c: char, next: Option<char>) -> (usize, bool) {
        if c == '\\' {
            (2, false)
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
            (1, false)
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
    use crate::test_support::{count_key, js_keys};

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
}
