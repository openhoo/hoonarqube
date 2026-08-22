//! Tolerant JavaScript/TypeScript analyzer lowering starter-rule findings into
//! `hoonarqube-ir`.
//!
//! The crate parses JS/TS/JSX/TSX with the embedded oxc parser and lowers its
//! checks into [`hoonarqube_ir::FileReport`]s. Rule keys use the repository
//! prefix of the file's language (`javascript:S103` / `typescript:S103`);
//! severity and type always resolve through the frozen `hoonarqube-catalog`
//! catalog via [`hoonarqube_ir::Issue::rule_key`], never duplicated here.
//!
//! Parsing is tolerant: a partial `Program` is analyzed even when the parser
//! reports recoverable errors, and parse errors themselves emit no issues (the
//! frozen js/ts catalogs contain no `ParsingError` rule).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hoonarqube_ir::Issue;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrayExpression, ArrayExpressionElement, ArrowFunctionExpression, AssignmentExpression,
    AssignmentOperator, BinaryExpression, BinaryOperator, BindingPattern, BlockStatement,
    CallExpression, Class, ClassElement, ConditionalExpression, ContinueStatement,
    DebuggerStatement, Declaration, EmptyStatement, ExportDefaultDeclarationKind, ExportSpecifier,
    Expression, ExpressionStatement, FormalParameter, FunctionBody, IfStatement, ImportDeclaration,
    ImportDeclarationSpecifier, ImportSpecifier, LabeledStatement, LogicalExpression,
    LogicalOperator, MemberExpression, MethodDefinition, MethodDefinitionKind, ModuleDeclaration,
    ModuleExportName, NewExpression, NumericLiteral, ObjectProperty, ParenthesizedExpression,
    PropertyKey, RegExpLiteral, ReturnStatement, SequenceExpression, Statement, StaticBlock,
    StringLiteral, SwitchCase, TSInterfaceDeclaration, TSSignature, TemplateLiteral,
    ThrowStatement, UnaryExpression, UnaryOperator, VariableDeclaration, VariableDeclarationKind,
    VariableDeclarator, WithStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_array_expression, walk_arrow_function_expression, walk_assignment_expression,
    walk_binary_expression, walk_block_statement, walk_call_expression, walk_class,
    walk_declaration, walk_export_default_declaration_kind, walk_expression,
    walk_expression_statement, walk_formal_parameter, walk_function_body, walk_if_statement,
    walk_import_declaration, walk_labeled_statement, walk_method_definition, walk_new_expression,
    walk_parenthesized_expression, walk_return_statement, walk_sequence_expression,
    walk_static_block, walk_switch_case, walk_template_literal, walk_throw_statement,
    walk_ts_interface_declaration, walk_unary_expression, walk_variable_declaration,
    walk_variable_declarator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

/// Language of one analyzed file; selects the issue `rule_key` prefix and the
/// parser's source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JstsLanguage {
    JavaScript,
    TypeScript,
}

impl JstsLanguage {
    /// Repository prefix used in issue `rule_key`s (`javascript:S103`).
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
        }
    }
}

/// Catalog membership of one rule: which language catalogs contain it and
/// therefore for which file language an issue may be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleScope {
    /// Present in both `javascript` and `typescript` catalogs.
    Both,
    /// `[J]` in the rule-batch classification: `javascript.json` only.
    JsOnly,
    /// `[TS]`: `typescript.json` only.
    TsOnly,
}

impl RuleScope {
    fn active(self, language: JstsLanguage) -> bool {
        match self {
            Self::Both => true,
            Self::JsOnly => language == JstsLanguage::JavaScript,
            Self::TsOnly => language == JstsLanguage::TypeScript,
        }
    }
}

/// Maps a file extension to a language; `.js .jsx .mjs .cjs` map to
/// JavaScript, `.ts .tsx .mts .cts` to TypeScript, anything else to `None`.
#[must_use]
pub fn language_for_extension(ext: &str) -> Option<JstsLanguage> {
    match ext {
        "js" | "jsx" | "mjs" | "cjs" => Some(JstsLanguage::JavaScript),
        "ts" | "tsx" | "mts" | "cts" => Some(JstsLanguage::TypeScript),
        _ => None,
    }
}

/// Knobs for the JS/TS analyzer; defaults mirror the frozen catalog
/// `ParameterFact` defaults (`maximumLineLength` default `180` for both
/// `javascript:S103` and `typescript:S103`).
///
/// The public shape is deliberately stable (`hoonarqube-cli` constructs this
/// struct literally); the remaining catalog parameters live in the private
/// [`RuleOptions`] until the CLI bundle threads them through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: u32,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_line_length: 180,
        }
    }
}

/// Catalog-backed parameters for the batch rules that are not surfaced
/// through [`AnalyzerOptions`] yet. Defaults are the frozen catalog values:
/// `S104` `maximum=1000`, `S138` `max=200`, `S1451`
/// `headerFormat=<empty>` / `isRegularExpression=false`, `S139`
/// `pattern="^\s*[^\s]+$"`, `S2068`
/// `passwordWords="password,pwd,passwd,passphrase"`, `S6418`
/// `randomnessSensibility=5.0` and
/// `secretWords="api[_.-]?key,auth,credential,secret,token"`.
#[derive(Debug, Clone, PartialEq)]
struct RuleOptions {
    maximum_lines_of_code: u32,
    maximum_function_lines: u32,
    header_format: String,
    header_is_regular_expression: bool,
    comment_pattern: String,
    password_words: Vec<String>,
    secret_entropy_sensibility: f64,
    secret_words: Vec<String>,
}

impl Default for RuleOptions {
    fn default() -> Self {
        let split_words = |value: &str| {
            value
                .split(',')
                .filter(|word| !word.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        };
        Self {
            maximum_lines_of_code: 1000,
            maximum_function_lines: 200,
            header_format: String::new(),
            header_is_regular_expression: false,
            comment_pattern: r"^\s*[^\s]+$".to_string(),
            password_words: split_words("password,pwd,passwd,passphrase"),
            secret_entropy_sensibility: 5.0,
            secret_words: split_words("api[_.-]?key,auth,credential,secret,token"),
        }
    }
}

#[must_use]
pub fn analyze(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    // Catalog-backed rule parameters beyond `maximumLineLength` are not
    // threaded through the CLI bundle yet; the library defaults mirror the
    // frozen catalog values (see `RuleOptions`).
    let rules = RuleOptions::default();
    analyze_with_rules(path, source, language, options, &rules)
}

fn analyze_with_rules(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
    rules: &RuleOptions,
) -> hoonarqube_ir::FileReport {
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        source,
        source_type_for(language, extension_of(&path)),
    )
    .parse();
    let index = LineIndex::new(source);
    let body = parsed.program.body.as_slice();

    let mut issues = Vec::new();
    issues.extend(check_line_length(source, language, options));
    issues.extend(check_tab_characters(source, language));
    issues.extend(check_missing_newline_at_eof(source, language, &index));
    issues.extend(check_trailing_whitespace(source, language));
    issues.extend(check_too_many_lines_of_code(body, &index, language, rules));
    issues.extend(check_file_header(source, language, rules));
    issues.extend(check_comment_rules(source, &index, language, rules));
    // `S2260` (`ParsingError`) hook: `parsed.errors` is deliberately not
    // reported — see the module documentation for the tolerant-parse
    // decision; the partial AST below is analyzed regardless.
    let _ = &parsed.diagnostics;
    issues.extend(check_one_statement_per_line(body, &index, language));
    issues.extend(check_statement_rules(
        &parsed.program,
        source,
        &index,
        language,
    ));
    issues.extend(check_expression_rules(&parsed.program, &index, language));
    issues.extend(check_binding_rules(
        &parsed.program,
        source,
        &index,
        language,
        rules,
    ));
    issues.extend(check_function_lengths(
        &parsed.program,
        &index,
        language,
        rules,
    ));
    issues.extend(check_eval_usage(&parsed.program, &index, language));
    sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: language.prefix().to_string(),
        issues,
        metrics: file_metrics(body, source, &index),
    }
}

fn extension_of(path: &Path) -> Option<&str> {
    path.extension().and_then(|ext| ext.to_str())
}

fn source_type_for(language: JstsLanguage, extension: Option<&str>) -> SourceType {
    let mut source_type = match language {
        JstsLanguage::JavaScript => SourceType::mjs(),
        JstsLanguage::TypeScript => SourceType::ts(),
    };
    if matches!(extension, Some("jsx" | "tsx")) {
        source_type = source_type.with_jsx(true);
    }
    source_type
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Byte-offset line index; positions follow the `SonarQube` convention
/// (`line` 1-based, `column` 0-based byte offset within the line).
struct LineIndex {
    line_starts: Vec<u32>,
}

impl LineIndex {
    fn new(source: &str) -> Self {
        let mut line_starts = vec![0_u32];
        for (offset, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(to_u32(offset + 1));
            }
        }
        Self { line_starts }
    }

    fn pos(&self, offset: u32) -> hoonarqube_ir::Pos {
        let line = self.line_starts.partition_point(|&start| start <= offset);
        hoonarqube_ir::Pos {
            line: to_u32(line),
            column: offset - self.line_starts[line - 1],
        }
    }

    fn range(&self, span: Span) -> hoonarqube_ir::Range {
        hoonarqube_ir::Range {
            start: self.pos(span.start),
            end: self.pos(span.end),
        }
    }

    /// 1-based lines whose byte interval intersects `span`; a span ending
    /// exactly on a line break stays on its own line.
    fn covered_lines(&self, span: Span) -> std::ops::RangeInclusive<u32> {
        let first = self.pos(span.start).line;
        let mut last = self.pos(span.end).line;
        if self.line_starts.binary_search(&span.end).is_ok() && last > first {
            last -= 1;
        }
        first..=last
    }
}

fn sort_issues(issues: &mut [Issue]) {
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

fn file_metrics(
    body: &[Statement<'_>],
    source: &str,
    index: &LineIndex,
) -> hoonarqube_ir::FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        to_u32(source.lines().count())
    };

    // Code lines derive from statement spans; the oxc lexer skips comments
    // entirely (no trivia tokens exist), so comment rows come from a small
    // string/template/regex-aware source scanner instead.
    let code_lines: BTreeSet<u32> = body
        .iter()
        .flat_map(|statement| index.covered_lines(statement.span()))
        .collect();
    let comment_rows: BTreeSet<u32> = scan_comment_lines(source)
        .into_iter()
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
struct ScannedComment {
    token: Span,
    body: Span,
}

/// One-pass scanner over raw source collecting the rows that contain comment
/// text. Understands `'…'`, `"…"`, template literals with `${}` nesting, and
/// a regex-literal heuristic (`/` after an operator, opening delimiter, or
/// keyword such as `return` starts a regex, not a division).
///
/// Rows are 1-based to match [`LineIndex`].
fn scan_comment_lines(source: &str) -> Vec<u32> {
    let mut scan = Scanner::new(source);
    scan.run();
    scan.rows
}

/// Scans all comments with their byte spans, in source order. The comment
/// rows behind [`scan_comment_lines`] derive from the same pass.
fn scan_comments(source: &str) -> Vec<ScannedComment> {
    let mut scan = Scanner::new(source);
    scan.run();
    scan.comments
}

#[derive(Clone, Copy, PartialEq)]
enum ScanState {
    Code,
    LineComment,
    BlockComment,
    SingleQuote,
    DoubleQuote,
    Template,
}

struct Scanner {
    chars: Vec<char>,
    /// Byte offset of `chars[i]`, kept parallel so spans stay byte-accurate.
    offsets: Vec<u32>,
    source_len: u32,
    state: ScanState,
    /// States suspended by `${` inside template literals.
    template_stack: Vec<ScanState>,
    prev_significant: Option<char>,
    prev_word: String,
    rows: Vec<u32>,
    last_pushed_row: u32,
    comments: Vec<ScannedComment>,
    /// `(token start, body start)` of the comment currently being consumed.
    open_comment: Option<(u32, u32)>,
}

impl Scanner {
    fn new(source: &str) -> Self {
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
            rows: Vec::new(),
            last_pushed_row: u32::MAX,
            comments: Vec::new(),
            open_comment: None,
        }
    }

    fn run(&mut self) {
        let mut row = 0_u32;
        let mut i = 0;
        while i < self.chars.len() {
            let c = self.chars[i];
            if c == '\n' {
                if self.state == ScanState::LineComment {
                    self.close_comment(self.offsets[i]);
                    self.state = ScanState::Code;
                } else if self.state == ScanState::BlockComment {
                    self.push_row(row);
                }
                i += 1;
                row += 1;
                continue;
            }
            let next = self.chars.get(i + 1).copied();
            let (jump, comment_start) = self.step(i, c, next);
            if comment_start {
                self.push_row(row);
            }
            i += jump;
        }
        // Unterminated `//` or `/* …` at end of file still yields a span.
        self.close_comment(self.source_len);
    }

    /// Records a comment that starts at `i` (byte span starts there, body
    /// after the two delimiter characters).
    fn open_comment(&mut self, i: usize) {
        let token_start = self.offsets[i];
        self.open_comment = Some((token_start, token_start + 2));
    }

    /// Closes the currently open comment at byte offset `end` (exclusive for
    /// the body, inclusive for the token).
    fn close_comment(&mut self, end: u32) {
        if let Some((token_start, body_start)) = self.open_comment.take() {
            self.comments.push(ScannedComment {
                token: Span::new(token_start, end),
                body: Span::new(body_start, end),
            });
        }
    }

    fn push_row(&mut self, row: u32) {
        if self.last_pushed_row != row {
            self.rows.push(row + 1);
            self.last_pushed_row = row;
        }
    }

    /// Advances one non-newline character; returns `(chars consumed, whether
    /// a comment starts here)`.
    fn step(&mut self, i: usize, c: char, next: Option<char>) -> (usize, bool) {
        match self.state {
            ScanState::Code => self.step_code(i, c, next),
            ScanState::LineComment => (1, false),
            ScanState::BlockComment => {
                let closing = c == '*' && next == Some('/');
                if closing {
                    self.close_comment(self.offsets[i] + 2);
                    self.state = ScanState::Code;
                }
                (if closing { 2 } else { 1 }, closing)
            }
            ScanState::SingleQuote => self.step_quoted(c, '\''),
            ScanState::DoubleQuote => self.step_quoted(c, '"'),
            ScanState::Template => self.step_template(c, next),
        }
    }

    fn step_code(&mut self, i: usize, c: char, next: Option<char>) -> (usize, bool) {
        if c == '}' && !self.template_stack.is_empty() {
            // `${ … }` ends; resume the suspended template literal.
            self.state = self.template_stack.pop().unwrap_or(ScanState::Code);
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

    fn step_quoted(&mut self, c: char, quote: char) -> (usize, bool) {
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

    fn step_template(&mut self, c: char, next: Option<char>) -> (usize, bool) {
        if c == '\\' {
            (2, false)
        } else if c == '`' {
            self.state = ScanState::Code;
            self.prev_significant = Some('`');
            (1, false)
        } else if c == '$' && next == Some('{') {
            self.template_stack.push(ScanState::Template);
            self.state = ScanState::Code;
            self.prev_significant = Some('(');
            (2, false)
        } else {
            (1, false)
        }
    }
}

/// Whether a `/` at this point starts a regex literal instead of a division.
fn regex_can_start(prev: Option<char>, word: &str) -> bool {
    match prev {
        None => true,
        Some(c) => {
            matches!(
                c,
                '(' | ','
                    | '='
                    | ':'
                    | '['
                    | '!'
                    | '&'
                    | '|'
                    | '?'
                    | '{'
                    | '}'
                    | ';'
                    | '+'
                    | '-'
                    | '*'
                    | '%'
                    | '~'
                    | '^'
                    | '<'
                    | '>'
            ) || matches!(
                word,
                "return"
                    | "typeof"
                    | "case"
                    | "in"
                    | "of"
                    | "new"
                    | "delete"
                    | "void"
                    | "instanceof"
                    | "do"
                    | "else"
                    | "yield"
                    | "await"
            )
        }
    }
}

/// Skips a regex literal starting at `chars[i - 1] == '/'`; returns the index
/// of the closing `/` (or the line end on unterminated regexes).
fn skip_regex_literal(chars: &[char], mut i: usize) -> usize {
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == '[' {
            // Character class: `/` inside is literal.
            i += 1;
            while i < chars.len() && chars[i] != ']' {
                i += if chars[i] == '\\' { 2 } else { 1 };
            }
        } else if chars[i] == '/' || chars[i] == '\n' {
            break;
        }
        i += 1;
    }
    i
}

/// Minimal backtracking regex matcher for catalog string parameters
/// (`S139` `pattern`, `S1451` regular-expression header formats, `S6418`
/// `secretWords`). Supported: literals, `.`, `[…]` classes with ranges and
/// negation, `\d \D \w \W \s \S \t \n \r \\` escapes, `(…)` groups,
/// alternation, `* + ? {m} {m,} {m,n}` quantifiers, and `^`/`$` anchors
/// bound to the whole subject. Patterns using anything else fail to compile
/// and match nothing (tolerant, never panics).

#[derive(Debug, Clone, PartialEq, Eq)]
enum RegexNode {
    Char(char),
    /// `.`: any character except `\n`.
    AnyChar,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
    StartAnchor,
    EndAnchor,
    Group(Vec<Vec<RegexNode>>),
    Repeat {
        node: Box<RegexNode>,
        min: usize,
        max: Option<usize>,
    },
}

const CLASS_DIGIT: [(char, char); 1] = [('0', '9')];
const CLASS_WORD: [(char, char); 3] = [('a', 'z'), ('A', 'Z'), ('0', '9')];

fn regex_search(pattern: &str, subject: &str) -> bool {
    let Some(alternatives) = parse_regex(pattern) else {
        return false;
    };
    let chars: Vec<char> = subject.chars().collect();
    (0..=chars.len()).any(|start| match_alternatives(&alternatives, &chars, start, &mut |_| true))
}

/// Matches `subject` only where the match starts at offset zero.
fn regex_prefix_match(pattern: &str, subject: &str) -> bool {
    let Some(alternatives) = parse_regex(pattern) else {
        return false;
    };
    let chars: Vec<char> = subject.chars().collect();
    match_alternatives(&alternatives, &chars, 0, &mut |_| true)
}

fn match_alternatives(
    alternatives: &[Vec<RegexNode>],
    text: &[char],
    pos: usize,
    tail: &mut dyn FnMut(usize) -> bool,
) -> bool {
    alternatives
        .iter()
        .any(|sequence| match_sequence(sequence, text, pos, tail))
}

fn match_sequence(
    nodes: &[RegexNode],
    text: &[char],
    pos: usize,
    tail: &mut dyn FnMut(usize) -> bool,
) -> bool {
    let Some((first, rest)) = nodes.split_first() else {
        return tail(pos);
    };
    match_node(first, text, pos, &mut |next| {
        match_sequence(rest, text, next, tail)
    })
}

fn match_node(
    node: &RegexNode,
    text: &[char],
    pos: usize,
    tail: &mut dyn FnMut(usize) -> bool,
) -> bool {
    match node {
        RegexNode::Char(expected) => text.get(pos) == Some(expected) && tail(pos + 1),
        RegexNode::AnyChar => pos < text.len() && text[pos] != '\n' && tail(pos + 1),
        RegexNode::Class { negated, ranges } => {
            let Some(c) = text.get(pos) else {
                return false;
            };
            let hit = ranges.iter().any(|(low, high)| low <= c && c <= high);
            (hit != *negated) && tail(pos + 1)
        }
        RegexNode::StartAnchor => pos == 0 && tail(pos),
        RegexNode::EndAnchor => pos == text.len() && tail(pos),
        RegexNode::Group(alternatives) => match_alternatives(alternatives, text, pos, tail),
        RegexNode::Repeat { node, min, max } => match_repeat(node, *min, *max, 0, text, pos, tail),
    }
}

fn match_repeat(
    node: &RegexNode,
    min: usize,
    max: Option<usize>,
    count: usize,
    text: &[char],
    pos: usize,
    tail: &mut dyn FnMut(usize) -> bool,
) -> bool {
    let may_repeat_more = max.is_none_or(|limit| count < limit);
    if may_repeat_more
        && match_node(node, text, pos, &mut |next| {
            // Zero-width repetitions would loop forever; reject them.
            next != pos && match_repeat(node, min, max, count + 1, text, next, tail)
        })
    {
        return true;
    }
    count >= min && tail(pos)
}

fn parse_regex(pattern: &str) -> Option<Vec<Vec<RegexNode>>> {
    let mut parser = RegexParser {
        chars: pattern.chars().collect(),
        pos: 0,
    };
    let alternatives = parser.parse_group_body()?;
    parser.expect_end()?;
    Some(alternatives)
}

struct RegexParser {
    chars: Vec<char>,
    pos: usize,
}

impl RegexParser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_end(&self) -> Option<()> {
        (self.pos == self.chars.len()).then_some(())
    }

    /// Alternatives up to an unmatched closing parenthesis.
    fn parse_group_body(&mut self) -> Option<Vec<Vec<RegexNode>>> {
        let mut alternatives = vec![self.parse_sequence()?];
        while self.eat('|') {
            alternatives.push(self.parse_sequence()?);
        }
        Some(alternatives)
    }

    fn parse_sequence(&mut self) -> Option<Vec<RegexNode>> {
        let mut nodes = Vec::new();
        while let Some(c) = self.peek()
            && c != '|'
            && c != ')'
        {
            nodes.push(self.parse_atom_quantified()?);
        }
        Some(nodes)
    }

    fn parse_atom_quantified(&mut self) -> Option<RegexNode> {
        let atom = self.parse_atom()?;
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, None)
            }
            Some('+') => {
                self.pos += 1;
                (1, None)
            }
            Some('?') => {
                self.pos += 1;
                (0, Some(1))
            }
            Some('{') => self.parse_counted_range()?,
            _ => return Some(atom),
        };
        Some(RegexNode::Repeat {
            node: Box::new(atom),
            min,
            max,
        })
    }

    /// `{m}`, `{m,}` or `{m,n}` (the opening brace is unconsumed).
    fn parse_counted_range(&mut self) -> Option<(usize, Option<usize>)> {
        let saved = self.pos;
        self.pos += 1; // consume `{`
        let minimum = self.parse_number()?;
        let maximum = if self.eat(',') {
            if self.peek() == Some('}') {
                None
            } else {
                Some(self.parse_number()?)
            }
        } else {
            Some(minimum)
        };
        if !self.eat('}') || maximum.is_some_and(|max| max < minimum) {
            self.pos = saved;
            return None;
        }
        Some((minimum, maximum))
    }

    fn parse_number(&mut self) -> Option<usize> {
        let digits = self.chars[self.pos..]
            .iter()
            .copied()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        if digits.is_empty() {
            return None;
        }
        self.pos += digits.len();
        digits.parse().ok()
    }

    fn parse_atom(&mut self) -> Option<RegexNode> {
        match self.bump()? {
            '(' => {
                let alternatives = self.parse_group_body()?;
                if !self.eat(')') {
                    return None;
                }
                Some(RegexNode::Group(alternatives))
            }
            '[' => self.parse_class(),
            '.' => Some(RegexNode::AnyChar),
            '^' => Some(RegexNode::StartAnchor),
            '$' => Some(RegexNode::EndAnchor),
            '\\' => self.parse_escape(),
            '*' | '+' | '?' => None,
            literal => Some(RegexNode::Char(literal)),
        }
    }

    fn parse_class(&mut self) -> Option<RegexNode> {
        let negated = self.eat('^');
        let mut ranges = Vec::new();
        // A `]` directly after the (optional) `^` is a literal.
        if self.peek() == Some(']') {
            ranges.push((']', ']'));
            self.pos += 1;
        }
        loop {
            let first = match self.bump()? {
                ']' => break,
                '\\' => self.escape_ranges()?,
                literal => vec![(literal, literal)],
            };
            if self.peek() == Some('-')
                && self
                    .chars
                    .get(self.pos + 1)
                    .is_some_and(|&next| next != ']')
            {
                self.pos += 1; // consume `-`
                let upper = match self.bump()? {
                    '\\' => self.escape_ranges()?.pop()?.0,
                    upper => upper,
                };
                ranges.push((first.first()?.0, upper));
            } else {
                ranges.extend(first);
            }
        }
        Some(RegexNode::Class { negated, ranges })
    }

    /// One escape inside or outside a class as a range list.
    fn escape_ranges(&mut self) -> Option<Vec<(char, char)>> {
        match self.bump()? {
            'd' => Some(CLASS_DIGIT.to_vec()),
            // Negated shorthand inside classes (`[\D]`) is unsupported;
            // such patterns compile to nothing instead.
            'D' | 'W' => None,
            'w' => Some(CLASS_WORD.to_vec()),
            's' => Some(vec![(' ', ' '), ('\t', '\t'), ('\n', '\r')]),
            't' => Some(vec![('\t', '\t')]),
            'n' => Some(vec![('\n', '\n')]),
            'r' => Some(vec![('\r', '\r')]),
            escaped => Some(vec![(escaped, escaped)]),
        }
    }

    fn parse_escape(&mut self) -> Option<RegexNode> {
        match self.bump()? {
            'd' => Some(RegexNode::Class {
                negated: false,
                ranges: CLASS_DIGIT.to_vec(),
            }),
            'D' => Some(RegexNode::Class {
                negated: true,
                ranges: CLASS_DIGIT.to_vec(),
            }),
            'w' => Some(RegexNode::Class {
                negated: false,
                ranges: CLASS_WORD.to_vec(),
            }),
            'W' => Some(RegexNode::Class {
                negated: true,
                ranges: CLASS_WORD.to_vec(),
            }),
            's' => Some(RegexNode::Class {
                negated: false,
                ranges: vec![(' ', ' '), ('\t', '\t'), ('\n', '\r')],
            }),
            'S' => Some(RegexNode::Class {
                negated: true,
                ranges: vec![(' ', ' '), ('\t', '\t'), ('\n', '\r')],
            }),
            escaped => Some(RegexNode::Char(escaped)),
        }
    }
}

/// One finding covering `span`, positioned through [`LineIndex`].
fn span_issue(
    index: &LineIndex,
    rule_key: String,
    message: impl Into<String>,
    span: Span,
) -> Issue {
    Issue {
        rule_key,
        message: message.into(),
        range: index.range(span),
    }
}

fn check_tab_characters(source: &str, language: JstsLanguage) -> Vec<Issue> {
    let rule_key = format!("{}:S105", language.prefix());
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line_number = to_u32(zero_based) + 1;
        let column = chunk.find('\t');
        if let Some(column) = column {
            let column = to_u32(column);
            issues.push(Issue {
                rule_key: rule_key.clone(),
                message: "Replace all tab characters in this file by sequences of spaces."
                    .to_string(),
                range: hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: line_number,
                        column,
                    },
                    end: hoonarqube_ir::Pos {
                        line: line_number,
                        column: column + 1,
                    },
                },
            });
        }
    }
    issues
}

fn check_missing_newline_at_eof(
    source: &str,
    language: JstsLanguage,
    index: &LineIndex,
) -> Vec<Issue> {
    // Empty files have no last byte to violate the rule.
    if source.is_empty() || source.ends_with('\n') {
        return Vec::new();
    }
    let end = index.pos(to_u32(source.len()));
    vec![Issue {
        rule_key: format!("{}:S113", language.prefix()),
        message: "Add a new line at the end of this file.".to_string(),
        range: hoonarqube_ir::Range {
            start: end.clone(),
            end,
        },
    }]
}

fn check_trailing_whitespace(source: &str, language: JstsLanguage) -> Vec<Issue> {
    let rule_key = format!("{}:S1131", language.prefix());
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches('\n');
        let content = line.strip_suffix('\r').unwrap_or(line);
        let trailing = content.len() - content.trim_end_matches([' ', '\t']).len();
        if trailing == 0 || content.is_empty() {
            continue;
        }
        let line_number = to_u32(zero_based) + 1;
        let start_column = to_u32(content.len() - trailing);
        issues.push(Issue {
            rule_key: rule_key.clone(),
            message: "Remove all trailing whitespaces.".to_string(),
            range: hoonarqube_ir::Range {
                start: hoonarqube_ir::Pos {
                    line: line_number,
                    column: start_column,
                },
                end: hoonarqube_ir::Pos {
                    line: line_number,
                    column: to_u32(content.len()),
                },
            },
        });
    }
    issues
}

fn check_too_many_lines_of_code(
    body: &[Statement<'_>],
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    // Same notion of code lines as `file_metrics`: statement coverage
    // excludes blank lines and pure-comment lines.
    let code_lines: BTreeSet<u32> = body
        .iter()
        .flat_map(|statement| index.covered_lines(statement.span()))
        .collect();
    let count = code_lines.len();
    let maximum = usize::try_from(rules.maximum_lines_of_code).unwrap_or(usize::MAX);
    if count <= maximum {
        return Vec::new();
    }
    vec![Issue {
        rule_key: format!("{}:S104", language.prefix()),
        message: format!(
            "This file has {} lines of code, which is greater than {} authorized. \
             Split it into smaller pieces.",
            count, rules.maximum_lines_of_code
        ),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    }]
}

fn check_file_header(source: &str, language: JstsLanguage, rules: &RuleOptions) -> Vec<Issue> {
    // An empty `headerFormat` disables the rule, mirroring the catalog's
    // null default.
    if rules.header_format.is_empty() {
        return Vec::new();
    }
    let header_present = if rules.header_is_regular_expression {
        regex_prefix_match(&rules.header_format, source)
    } else {
        source.starts_with(rules.header_format.as_str())
    };
    if header_present {
        return Vec::new();
    }
    vec![Issue {
        rule_key: format!("{}:S1451", language.prefix()),
        message: "Add or update the header of this file.".to_string(),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    }]
}

fn check_line_length(
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let maximum = usize::try_from(options.maximum_line_length).unwrap_or(usize::MAX);
    let rule_key = format!("{}:S103", language.prefix());
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches(['\r', '\n']);
        let length = line.chars().count();
        if length > maximum {
            let line_number = to_u32(zero_based) + 1;
            issues.push(Issue {
                rule_key: rule_key.clone(),
                message: format!(
                    "This line exceeds the maximum allowed length of {} characters.",
                    options.maximum_line_length
                ),
                range: hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: line_number,
                        column: 0,
                    },
                    end: hoonarqube_ir::Pos {
                        line: line_number,
                        column: to_u32(length),
                    },
                },
            });
        }
    }
    issues
}

fn check_one_statement_per_line(
    body: &[Statement<'_>],
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    check_suite(body, index, language, &mut issues);
    issues
}

/// Groups consecutive statements sharing a start line; every additional
/// statement on that line gets one issue, then nesting is walked.
fn check_suite(
    body: &[Statement<'_>],
    index: &LineIndex,
    language: JstsLanguage,
    issues: &mut Vec<Issue>,
) {
    let line_of = |stmt: &Statement<'_>| index.pos(GetSpan::span(stmt).start).line;

    let mut start = 0;
    while start < body.len() {
        let first_line = line_of(&body[start]);
        let mut end = start + 1;
        while end < body.len() && line_of(&body[end]) == first_line {
            end += 1;
        }
        for stmt in &body[start + 1..end] {
            issues.push(Issue {
                rule_key: format!("{}:S122", language.prefix()),
                message: "Only one statement per line is allowed.".to_string(),
                range: index.range(stmt.span()),
            });
        }
        for stmt in &body[start..end] {
            check_nested_bodies(stmt, index, language, issues);
        }
        start = end;
    }
}

fn check_one(
    stmt: &Statement<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    issues: &mut Vec<Issue>,
) {
    check_suite(std::slice::from_ref(stmt), index, language, issues);
}

fn check_class_methods(
    elements: &[ClassElement<'_>],
    index: &LineIndex,
    language: JstsLanguage,
    issues: &mut Vec<Issue>,
) {
    for element in elements {
        if let ClassElement::MethodDefinition(method) = element
            && let Some(body) = &method.value.body
        {
            check_suite(body.statements.as_slice(), index, language, issues);
        }
    }
}

fn check_nested_bodies(
    stmt: &Statement<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    issues: &mut Vec<Issue>,
) {
    // Concrete variants first; `Declaration` and `ModuleDeclaration` are
    // inherited variant groups on `Statement` in oxc 0.146, reached through
    // the generated `as_*` helpers in the final fallback arm.
    match stmt {
        Statement::BlockStatement(block) => {
            check_suite(block.body.as_slice(), index, language, issues);
        }
        Statement::IfStatement(statement) => {
            check_one(&statement.consequent, index, language, issues);
            if let Some(alternate) = &statement.alternate {
                check_one(alternate, index, language, issues);
            }
        }
        Statement::ForStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::ForInStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::ForOfStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::WhileStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::DoWhileStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::SwitchStatement(statement) => {
            for case in &statement.cases {
                check_suite(case.consequent.as_slice(), index, language, issues);
            }
        }
        Statement::TryStatement(statement) => {
            check_suite(statement.block.body.as_slice(), index, language, issues);
            if let Some(handler) = &statement.handler {
                check_suite(handler.body.body.as_slice(), index, language, issues);
            }
            if let Some(finalizer) = &statement.finalizer {
                check_suite(finalizer.body.as_slice(), index, language, issues);
            }
        }
        Statement::LabeledStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::WithStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        _ => {
            if let Some(declaration) = stmt.as_declaration() {
                match declaration {
                    Declaration::FunctionDeclaration(function) => {
                        if let Some(body) = &function.body {
                            check_suite(body.statements.as_slice(), index, language, issues);
                        }
                    }
                    Declaration::ClassDeclaration(class) => {
                        check_class_methods(&class.body.body, index, language, issues);
                    }
                    _ => {}
                }
            } else if let Some(ModuleDeclaration::ExportDefaultDeclaration(declaration)) =
                stmt.as_module_declaration()
            {
                match &declaration.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                        if let Some(body) = &function.body {
                            check_suite(body.statements.as_slice(), index, language, issues);
                        }
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                        check_class_methods(&class.body.body, index, language, issues);
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Collects `eval(...)` calls and `new Function(...)` expressions anywhere in
/// the tree, anchored at the callee span.
struct EvalUsageCollector<'index> {
    index: &'index LineIndex,
    language: JstsLanguage,
    issues: Vec<Issue>,
}

impl<'a> Visit<'a> for EvalUsageCollector<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee
            && callee.name == "eval"
        {
            self.push("Remove this usage of 'eval'.", callee.span());
        }
        walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee
            && callee.name == "Function"
        {
            self.push("Remove this usage of 'Function'.", callee.span());
        }
        walk_new_expression(self, it);
    }
}

impl EvalUsageCollector<'_> {
    fn push(&mut self, message: &str, span: Span) {
        self.issues.push(Issue {
            rule_key: format!("{}:S1523", self.language.prefix()),
            message: message.to_string(),
            range: self.index.range(span),
        });
    }
}

fn check_eval_usage(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = EvalUsageCollector {
        index,
        language,
        issues: Vec::new(),
    };
    collector.visit_program(program);
    collector.issues
}

/// Central issue emitter: applies catalog scope gating, the language rule-key
/// prefix, and `LineIndex` positioning for every batch rule.
struct IssueSink<'index> {
    index: &'index LineIndex,
    language: JstsLanguage,
    issues: Vec<Issue>,
}

impl IssueSink<'_> {
    fn emit_span(&mut self, scope: RuleScope, rule: &str, message: &str, span: Span) {
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

    fn emit_pos(
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
        });
    }
}

/// Names whose binding or assignment `S2137` forbids.
const RESERVED_BINDING_NAMES: [&str; 5] = ["undefined", "NaN", "Infinity", "eval", "arguments"];

/// ECMAScript 3 future reserved words flagged by `S1527` (JavaScript-only).
const FUTURE_RESERVED_WORDS: [&str; 17] = [
    "abstract",
    "boolean",
    "byte",
    "char",
    "double",
    "final",
    "float",
    "goto",
    "int",
    "long",
    "native",
    "short",
    "synchronized",
    "throws",
    "transient",
    "volatile",
    "enum",
];

/// `console` members flagged by `S106`.
const CONSOLE_METHODS: [&str; 8] = [
    "log", "info", "warn", "error", "debug", "trace", "dir", "table",
];

/// Built-in globals whose prototypes `S6643` protects and whose surfaces
/// `S2424` treats as read-only.
const BUILTIN_GLOBALS: [&str; 16] = [
    "Array", "Object", "Function", "String", "Number", "Boolean", "Symbol", "BigInt", "Map", "Set",
    "Promise", "Date", "RegExp", "Error", "Math", "JSON",
];

/// Known-pure string methods whose bare statement call `S1154` flags.
const PURE_STRING_METHODS: [&str; 15] = [
    "toUpperCase",
    "toLowerCase",
    "trim",
    "trimStart",
    "trimEnd",
    "split",
    "concat",
    "slice",
    "substring",
    "substr",
    "charAt",
    "charCodeAt",
    "indexOf",
    "lastIndexOf",
    "includes",
];

/// Known side-effect-free array/string APIs whose bare statement call `S2201`
/// flags (callbacks are assumed pure in this subset).
const SIDE_EFFECT_FREE_APIS: [&str; 20] = [
    "concat",
    "every",
    "filter",
    "find",
    "findIndex",
    "flat",
    "flatMap",
    "includes",
    "indexOf",
    "join",
    "lastIndexOf",
    "map",
    "reduce",
    "reduceRight",
    "slice",
    "some",
    "keys",
    "values",
    "entries",
    "at",
];

/// The only values `typeof` may yield; `S4125` flags comparisons outside it.
const TYPEOF_VALUES: [&str; 8] = [
    "undefined",
    "object",
    "boolean",
    "number",
    "string",
    "symbol",
    "bigint",
    "function",
];

/// Keywords whose comment prefix suggests commented-out code for `S125`.
const CODE_START_KEYWORDS: [&str; 11] = [
    "if", "for", "while", "switch", "var", "let", "const", "function", "return", "import", "export",
];

fn is_error_type_name(name: &str) -> bool {
    name == "Error" || name.ends_with("Error")
}

fn is_bitwise_operator(operator: BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::BitwiseAnd
            | BinaryOperator::BitwiseOR
            | BinaryOperator::BitwiseXOR
            | BinaryOperator::ShiftLeft
            | BinaryOperator::ShiftRight
            | BinaryOperator::ShiftRightZeroFill
    )
}

fn is_equality_operator(operator: BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::Equality
            | BinaryOperator::Inequality
            | BinaryOperator::StrictEquality
            | BinaryOperator::StrictInequality
    )
}

/// `Expression::Identifier` name, if the expression is a plain identifier.
fn identifier_name<'a>(expression: &'a Expression<'_>) -> Option<&'a str> {
    match expression {
        Expression::Identifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

/// Name of a plain-identifier callee.
fn callee_name<'a>(call: &'a CallExpression<'_>) -> Option<&'a str> {
    identifier_name(&call.callee)
}

/// Name of a plain-identifier constructor callee.
fn constructor_name<'a>(new: &'a NewExpression<'_>) -> Option<&'a str> {
    identifier_name(&new.callee)
}

/// Property name of a static member access (`a.b`), if any.
fn static_property_name<'a>(member: &'a MemberExpression<'_>) -> Option<&'a str> {
    match member {
        MemberExpression::StaticMemberExpression(static_member) => {
            Some(&static_member.property.name)
        }
        _ => None,
    }
}

/// Root identifier of a member chain (`a` in `a.b.c`), if any.
fn member_root_name<'a>(member: &'a MemberExpression<'_>) -> Option<&'a str> {
    expression_root_name(member_object(member))
}

/// Root identifier of an expression chain, if any.
fn expression_root_name<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match expression {
        Expression::Identifier(identifier) => Some(&identifier.name),
        Expression::StaticMemberExpression(nested) => expression_root_name(&nested.object),
        Expression::ComputedMemberExpression(nested) => expression_root_name(&nested.object),
        Expression::PrivateFieldExpression(nested) => expression_root_name(&nested.object),
        _ => None,
    }
}

/// Whether the member chain starts at the given identifier.
fn member_rooted_at(member: &MemberExpression<'_>, root: &str) -> bool {
    member_root_name(member) == Some(root)
}

/// Whether the raw source text of `span` contains `needle` (used where the
/// AST cannot distinguish `import {a}` from `import {a as a}`).
fn span_text_contains(source: &str, span: Span, needle: &str) -> bool {
    let start = usize::try_from(span.start).unwrap_or(0);
    let end = usize::try_from(span.end).unwrap_or(source.len());
    source
        .get(start..end.min(source.len()))
        .is_some_and(|text| text.contains(needle))
}

/// Shannon entropy in bits per character of `value`.
fn shannon_entropy_per_char(value: &str) -> f64 {
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

fn check_comment_rules(
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    let mut sink = IssueSink {
        index,
        language,
        issues: Vec::new(),
    };
    for comment in scan_comments(source) {
        let body = source_slice(source, comment.body);
        check_flagged_tags(&mut sink, comment, body);
        check_nosonar(&mut sink, comment, body);
        check_disallowed_comment_pattern(&mut sink, source, comment, body, rules);
        check_commented_out_code(&mut sink, comment, body);
    }
    sink.issues
}

fn source_slice(source: &str, span: Span) -> &str {
    let start = usize::try_from(span.start).unwrap_or(0);
    let end = usize::try_from(span.end).unwrap_or(source.len());
    source.get(start..end).unwrap_or("")
}

/// `S1134` (FIXME) and `S1135` (TODO) task tags.
fn check_flagged_tags(sink: &mut IssueSink, comment: ScannedComment, body: &str) {
    for (tag, rule, message) in [
        (
            "FIXME",
            "S1134",
            "Complete the work corresponding to this \"FIXME\" comment.",
        ),
        (
            "TODO",
            "S1135",
            "Complete the task associated to this \"TODO\" comment.",
        ),
    ] {
        if let Some(offset) = find_tag(body, tag) {
            let start = comment.body.start + to_u32(offset);
            sink.emit_span(
                RuleScope::Both,
                rule,
                message,
                Span::new(start, start + to_u32(tag.len())),
            );
        }
    }
}

/// First whole-word occurrence of `tag` in a comment body.
fn find_tag(body: &str, tag: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut search_from = 0;
    while let Some(relative) = body[search_from..].find(tag) {
        let start = search_from + relative;
        let end = start + tag.len();
        let word_start = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let word_end = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if word_start && word_end {
            return Some(start);
        }
        search_from = end;
    }
    None
}

/// `S1291`: the `NOSONAR` suppression marker.
fn check_nosonar(sink: &mut IssueSink, comment: ScannedComment, body: &str) {
    if body.contains("NOSONAR") {
        sink.emit_span(
            RuleScope::Both,
            "S1291",
            "Remove this \"NOSONAR\" comment and fix the suppressed issue.",
            comment.token,
        );
    }
}

/// `S139`: a comment on a line that also carries code, matching the
/// configured `pattern` (default `^\s*[^\s]+$`).
fn check_disallowed_comment_pattern(
    sink: &mut IssueSink,
    source: &str,
    comment: ScannedComment,
    body: &str,
    rules: &RuleOptions,
) {
    let line_start = comment.token.start - sink.index.pos(comment.token.start).column;
    let code_before = source
        .get(
            usize::try_from(line_start).unwrap_or(0)
                ..usize::try_from(comment.token.start).unwrap_or(0),
        )
        .is_some_and(|prefix| prefix.chars().any(|c| !c.is_whitespace()));
    if !code_before || !regex_search(&rules.comment_pattern, body) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S139",
        "Rewrite or remove this comment; it matches the configured disallowed pattern.",
        comment.token,
    );
}

/// `S125`: heuristics for comments that look like commented-out code:
/// statement keyword starts, a trailing `;` with an assignment or call, or
/// balanced non-empty braces plus a `;`.
fn check_commented_out_code(sink: &mut IssueSink, comment: ScannedComment, body: &str) {
    if !looks_like_code(body) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S125",
        "Remove this commented-out code.",
        comment.token,
    );
}

fn looks_like_code(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.len() < 4
        || ["TODO", "FIXME", "NOSONAR"]
            .iter()
            .any(|tag| trimmed.contains(tag))
    {
        return false;
    }
    let first_word = trimmed
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$')
        .find(|word| !word.is_empty());
    if first_word.is_some_and(|word| CODE_START_KEYWORDS.contains(&word)) {
        return true;
    }
    if trimmed.ends_with(';') && (trimmed.contains('=') || trimmed.contains('(')) {
        return true;
    }
    trimmed.matches('{').count() == trimmed.matches('}').count()
        && trimmed.contains('{')
        && trimmed.contains(';')
}

/// Statement-level batch rules in one traversal: `S909`, `S1119`, `S1321`,
/// `S1525`, `S108`, `S1199`, `S121`, `S2681`, `S6660`, `S1066`, `S6836`,
/// `S1116`, `S3696`, `S3984`, `S1848`, `S1154`, `S2201`, `S1126`, `S3504`,
/// `S2208`, `S6859`, and `S3863`.
struct StatementCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    /// Depth of `BlockStatement`s nested directly inside `BlockStatement`s;
    /// reset at function boundaries for `S1199`.
    bare_block_depth: u32,
    last_import: Option<(String, u32)>,
}

impl<'a> Visit<'a> for StatementCollector<'a, '_> {
    fn visit_continue_statement(&mut self, it: &ContinueStatement<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S909",
            "Remove this \"continue\" statement.",
            it.span(),
        );
    }

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1119",
            "Remove this labeled statement.",
            it.label.span(),
        );
        walk_labeled_statement(self, it);
    }

    fn visit_with_statement(&mut self, it: &WithStatement<'a>) {
        self.sink.emit_span(
            RuleScope::JsOnly,
            "S1321",
            "Remove this \"with\" statement.",
            it.span(),
        );
    }

    fn visit_debugger_statement(&mut self, it: &DebuggerStatement) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1525",
            "Remove this debugger statement.",
            it.span,
        );
    }

    fn visit_empty_statement(&mut self, it: &EmptyStatement) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1116",
            "Remove this empty statement.",
            it.span,
        );
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        if self.bare_block_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1199",
                "Remove this nested block.",
                it.span(),
            );
        }
        if it.body.is_empty() {
            self.check_empty_block(it);
        }
        self.bare_block_depth += 1;
        walk_block_statement(self, it);
        self.bare_block_depth -= 1;
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        if it.body.is_empty() {
            self.check_empty_block_span(it.span());
        }
        let saved_depth = self.bare_block_depth;
        self.bare_block_depth = 0;
        walk_static_block(self, it);
        self.bare_block_depth = saved_depth;
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        let saved_depth = self.bare_block_depth;
        self.bare_block_depth = 0;
        walk_function_body(self, it);
        self.bare_block_depth = saved_depth;
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.check_control_structure_body(&it.consequent);
        if let Some(alternate) = &it.alternate {
            self.check_control_structure_body(alternate);
        }
        self.check_collapsible_if(it);
        walk_if_statement(self, it);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        if let Some(first) = it.consequent.first() {
            self.check_case_leading_declaration(first);
        }
        walk_switch_case(self, it);
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        match &it.expression {
            Expression::NewExpression(new) => {
                self.check_discarded_new(new);
            }
            Expression::CallExpression(call) => {
                self.check_discarded_pure_call(call);
            }
            _ => {}
        }
        walk_expression_statement(self, it);
    }

    fn visit_throw_statement(&mut self, it: &ThrowStatement<'a>) {
        if matches!(
            &it.argument,
            Expression::StringLiteral(_)
                | Expression::NumericLiteral(_)
                | Expression::BooleanLiteral(_)
                | Expression::NullLiteral(_)
                | Expression::TemplateLiteral(_)
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3696",
                "Throw an Error object instead of this value.",
                it.argument.span(),
            );
        }
        walk_throw_statement(self, it);
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if let Some(Expression::ConditionalExpression(conditional)) = &it.argument
            && let (Expression::BooleanLiteral(consequent), Expression::BooleanLiteral(alternate)) =
                (&conditional.consequent, &conditional.alternate)
        {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S1126",
                "Return the condition directly instead of this ternary.",
                conditional.span(),
            );
            let _ = (consequent, alternate);
        }
        walk_return_statement(self, it);
    }

    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        if it.kind == VariableDeclarationKind::Var {
            self.sink.emit_span(
                RuleScope::Both,
                "S3504",
                "Replace \"var\" with \"let\" or \"const\".",
                it.span(),
            );
        }
        walk_variable_declaration(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        self.check_namespace_import(it);
        self.check_absolute_import_path(it);
        self.check_duplicate_import(it);
        walk_import_declaration(self, it);
    }
}

impl StatementCollector<'_, '_> {
    /// `S108`: empty blocks are flagged unless their span interior still
    /// holds comments the parser dropped.
    fn check_empty_block(&mut self, block: &BlockStatement<'_>) {
        self.check_empty_block_span(block.span());
    }

    fn check_empty_block_span(&mut self, span: Span) {
        let interior = Span::new(span.start + 1, span.end.saturating_sub(1));
        let interior_text = source_slice(self.source, interior);
        if interior_text.trim().is_empty() {
            self.sink
                .emit_span(RuleScope::Both, "S108", "Remove this empty block.", span);
        }
    }

    /// `S121` (unbraced control-structure bodies) and `S2681` (the same
    /// bodies spanning several lines).
    fn check_control_structure_body(&mut self, body: &Statement<'_>) {
        if matches!(body, Statement::BlockStatement(_)) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S121",
            "Wrap this statement in curly braces.",
            body.span(),
        );
        if self.sink.index.covered_lines(body.span()).count() > 1 {
            self.sink.emit_span(
                RuleScope::Both,
                "S2681",
                "Put this unbraced statement on one line or use curly braces.",
                body.span(),
            );
        }
    }

    /// `S1066`: an `if` whose consequent block holds exactly one `if`.
    /// `S6660`: an `else` block holding exactly one `if`.
    fn check_collapsible_if(&mut self, it: &IfStatement<'_>) {
        if let Statement::BlockStatement(block) = &it.consequent
            && block.body.len() == 1
            && matches!(&block.body[0], Statement::IfStatement(_))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S1066",
                "Merge this nested \"if\" into the enclosing condition.",
                block.body[0].span(),
            );
        }
        if let Some(Statement::BlockStatement(block)) = &it.alternate
            && block.body.len() == 1
            && let Statement::IfStatement(inner) = &block.body[0]
            && inner.alternate.is_none()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6660",
                "Collapse this \"else\" block into an \"else if\".",
                block.span(),
            );
        }
    }

    /// `S6836`: lexical declarations leading a switch case.
    fn check_case_leading_declaration(&mut self, first: &Statement<'_>) {
        let lexical = match first {
            Statement::VariableDeclaration(declaration) => {
                declaration.kind != VariableDeclarationKind::Var
            }
            Statement::FunctionDeclaration(_) | Statement::ClassDeclaration(_) => true,
            _ => false,
        };
        if lexical {
            self.sink.emit_span(
                RuleScope::Both,
                "S6836",
                "Wrap this declaration in a block.",
                first.span(),
            );
        }
    }

    /// `S1848` (discarded instantiation) and `S3984` (discarded `Error`).
    fn check_discarded_new(&mut self, new: &NewExpression<'_>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1848",
            "Use this object instantiation or remove it.",
            new.span(),
        );
        if constructor_name(new).is_some_and(is_error_type_name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3984",
                "Throw this error instead of instantiating it.",
                new.callee.span(),
            );
        }
    }

    /// `S1154` and `S2201`: bare statements calling known side-effect-free
    /// APIs.
    fn check_discarded_pure_call(&mut self, call: &CallExpression<'_>) {
        let Some(member) = call.callee.as_member_expression() else {
            return;
        };
        let Some(property) = static_property_name(member) else {
            return;
        };
        if PURE_STRING_METHODS.contains(&property) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1154",
                "Remove this useless statement; the result is discarded.",
                call.span(),
            );
        } else if SIDE_EFFECT_FREE_APIS.contains(&property) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2201",
                "Remove this useless statement; the result is discarded.",
                call.span(),
            );
        }
    }

    /// `S2208`: `import * as` namespace specifiers.
    fn check_namespace_import(&mut self, it: &ImportDeclaration<'_>) {
        if let Some(specifiers) = &it.specifiers {
            for specifier in specifiers {
                if matches!(
                    specifier,
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(_)
                ) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S2208",
                        "Import only the module members you use.",
                        specifier.span(),
                    );
                }
            }
        }
    }

    /// `S6859`: absolute import paths.
    fn check_absolute_import_path(&mut self, it: &ImportDeclaration<'_>) {
        if it.source.value.starts_with('/') {
            self.sink.emit_span(
                RuleScope::Both,
                "S6859",
                "Remove the leading slash from this import path.",
                it.source.span(),
            );
        }
    }

    /// `S3863`: adjacent imports of the same module (adjacency approximated
    /// by line distance of at most one line).
    fn check_duplicate_import(&mut self, it: &ImportDeclaration<'_>) {
        let module = it.source.value.to_string();
        let start_line = self.sink.index.pos(it.span().start).line;
        if let Some((last_module, last_end_line)) = &self.last_import
            && *last_module == module
            && start_line <= last_end_line + 1
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3863",
                "Merge this import with the adjacent import of the same module.",
                it.span(),
            );
        }
        self.last_import = Some((module, self.sink.index.pos(it.span().end).line));
    }
}

fn check_statement_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = StatementCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        bare_block_depth: 0,
        last_import: None,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Boolean-context stack for the condition-sensitive rules (`S1529`,
/// `S6509`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpressionContext {
    /// Directly in an `if`/ternary test or a logical operand.
    Condition,
    /// Operand of a `!` operator.
    Negation,
}

/// `S6644`: `x ? true : false` and `x ? y : y` redundant shapes.
fn check_redundant_ternary(sink: &mut IssueSink, it: &ConditionalExpression<'_>) {
    let redundant = match (&it.consequent, &it.alternate) {
        (Expression::BooleanLiteral(consequent), Expression::BooleanLiteral(alternate)) => {
            consequent.value && !alternate.value
        }
        (Expression::Identifier(consequent), Expression::Identifier(alternate)) => {
            consequent.name == alternate.name
        }
        _ => false,
    };
    if redundant {
        sink.emit_span(
            RuleScope::Both,
            "S6644",
            "Replace this redundant ternary with the condition itself.",
            it.span(),
        );
    }
}

/// Expression-level batch rules in one traversal: `S1774`, `S3735`, `S878`,
/// `S2688`, `S6679`, `S2757`, `S1440`, `S1125`, `S1529`, `S1940`, `S6638`,
/// `S2692`, `S6557`, `S3981`, `S6676`, `S6637`, `S6509`, `S1529`, `S6958`,
/// `S6959`, `S2871`, `S3003`, `S4125`, `S2427`, `S2817`, `S3533`, `S106`,
/// `S1442`, `S6653`, `S6661`, `S6666`, `S2685`, `S6654`, `S6643`, `S2424`,
/// `S1528`, `S1533`, `S2428`, `S3834`, `S4624`, `S3786`, `S1516`, `S6535`,
/// `S6657`, `S1314`, `S6534`, `S1313`, `S4140`, and `S1110`-adjacent
/// parenthesized-expression checks (`S1110`, `S3812`).
struct ExpressionCollector<'index> {
    sink: IssueSink<'index>,
    contexts: Vec<ExpressionContext>,
    ternary_depth: u32,
    /// Nesting depth of template literals for `S4624`.
    template_depth: u32,
}

impl<'a> Visit<'a> for ExpressionCollector<'_> {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.contexts.push(ExpressionContext::Condition);
        self.visit_expression(&it.test);
        self.contexts.pop();
        self.visit_statement(&it.consequent);
        if let Some(alternate) = &it.alternate {
            self.visit_statement(alternate);
        }
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        if self.ternary_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1774",
                "Refactor this nested ternary into a statement.",
                it.span(),
            );
        }
        check_redundant_ternary(&mut self.sink, it);
        self.contexts.push(ExpressionContext::Condition);
        self.visit_expression(&it.test);
        self.contexts.pop();
        self.ternary_depth += 1;
        self.visit_expression(&it.consequent);
        self.visit_expression(&it.alternate);
        self.ternary_depth -= 1;
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        if matches!(it.operator, LogicalOperator::And | LogicalOperator::Or)
            && let (Some(left_name), Some(right_name)) =
                (identifier_name(&it.left), identifier_name(&it.right))
            && left_name == right_name
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6638",
                "Both operands are identical; simplify this expression.",
                it.span(),
            );
        }
        let operand_is_condition = !self.contexts.is_empty();
        for operand in [&it.left, &it.right] {
            if let Expression::BinaryExpression(binary) = operand
                && is_bitwise_operator(binary.operator)
                && operand_is_condition
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1529",
                    "Convert the result of this bitwise operation to a boolean explicitly.",
                    binary.span(),
                );
            }
            self.contexts.push(ExpressionContext::Condition);
            self.visit_expression(operand);
            self.contexts.pop();
        }
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        match it.operator {
            UnaryOperator::Void => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3735",
                    "Remove this use of the \"void\" operator.",
                    it.span(),
                );
            }
            UnaryOperator::LogicalNot => {
                if let Expression::BinaryExpression(binary) = &it.argument
                    && (is_equality_operator(binary.operator)
                        || matches!(
                            binary.operator,
                            BinaryOperator::LessThan
                                | BinaryOperator::LessEqualThan
                                | BinaryOperator::GreaterThan
                                | BinaryOperator::GreaterEqualThan
                        ))
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S1940",
                        "Invert the comparison operator instead of negating it.",
                        it.span(),
                    );
                }
                if matches!(
                    &it.argument,
                    Expression::UnaryExpression(inner) if inner.operator == UnaryOperator::LogicalNot
                ) && self
                    .contexts
                    .last()
                    .is_some_and(|context| *context == ExpressionContext::Condition)
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S6509",
                        "Remove this redundant double negation.",
                        it.span(),
                    );
                }
                self.contexts.push(ExpressionContext::Negation);
                self.visit_expression(&it.argument);
                self.contexts.pop();
                return;
            }
            _ => {}
        }
        walk_unary_expression(self, it);
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        check_binary_operators(&mut self.sink, it);
        check_index_of_comparisons(&mut self.sink, it);
        check_length_comparison(&mut self.sink, it);
        check_relational_strings(&mut self.sink, it);
        check_typeof_literal(&mut self.sink, it);
        walk_binary_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        check_assignment_rules(&mut self.sink, it);
        walk_assignment_expression(self, it);
    }

    fn visit_parenthesized_expression(&mut self, it: &ParenthesizedExpression<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1110",
            "Remove these redundant parentheses.",
            it.span(),
        );
        if let Expression::UnaryExpression(unary) = &it.expression
            && unary.operator == UnaryOperator::LogicalNot
            && let Expression::BinaryExpression(binary) = &unary.argument
            && matches!(
                binary.operator,
                BinaryOperator::In | BinaryOperator::Instanceof
            )
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3812",
                "The parentheses are required here; negate the operator instead.",
                unary.span(),
            );
        }
        walk_parenthesized_expression(self, it);
    }

    fn visit_sequence_expression(&mut self, it: &SequenceExpression<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S878",
            "Split this comma-separated sequence into separate statements.",
            it.span(),
        );
        walk_sequence_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        check_member_calls(&mut self.sink, it);
        check_plain_calls(&mut self.sink, it);
        if callee_name(it).is_some_and(|name| name == "Boolean")
            && it.arguments.len() == 1
            && self
                .contexts
                .last()
                .is_some_and(|context| *context == ExpressionContext::Condition)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6509",
                "Remove this redundant \"Boolean()\" cast.",
                it.span(),
            );
        }
        walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        check_constructor_calls(&mut self.sink, it);
        walk_new_expression(self, it);
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        if self.template_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S4624",
                "Extract this nested template literal.",
                it.span(),
            );
        }
        self.template_depth += 1;
        walk_template_literal(self, it);
        self.template_depth -= 1;
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        check_string_literal_raw(&mut self.sink, it);
    }

    fn visit_reg_exp_literal(&mut self, it: &RegExpLiteral<'a>) {
        if has_octal_escape(regex_pattern_text(it)) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6657",
                "Replace this octal escape sequence with a decimal escape.",
                it.span(),
            );
        }
    }

    fn visit_numeric_literal(&mut self, it: &NumericLiteral<'a>) {
        check_numeric_literal(&mut self.sink, it);
    }

    fn visit_array_expression(&mut self, it: &ArrayExpression<'a>) {
        for element in &it.elements {
            if matches!(element, ArrayExpressionElement::Elision(_)) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4140",
                    "Fill or remove the empty slots in this array literal.",
                    element.span(),
                );
            }
        }
        walk_array_expression(self, it);
    }
}

/// Shared checks over one binary expression.
fn check_binary_operators(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    if matches!(
        it.operator,
        BinaryOperator::Equality | BinaryOperator::Inequality
    ) {
        sink.emit_span(
            RuleScope::Both,
            "S1440",
            "Replace this loose equality comparison with strict equality.",
            it.span(),
        );
    }
    for operand in [&it.left, &it.right] {
        if matches!(operand, Expression::BooleanLiteral(_)) && is_equality_operator(it.operator) {
            sink.emit_span(
                RuleScope::Both,
                "S1125",
                "Remove this comparison against a boolean literal.",
                operand.span(),
            );
        }
        if identifier_name(operand) == Some("NaN") {
            sink.emit_span(
                RuleScope::Both,
                "S2688",
                "Use \"Number.isNaN()\" instead of comparing to \"NaN\" directly.",
                operand.span(),
            );
        }
    }
    // `x === NaN` family: same operands, but the equality shape suggests the
    // dedicated rule.
    if is_equality_operator(it.operator)
        && [identifier_name(&it.left), identifier_name(&it.right)]
            .into_iter()
            .any(|name| name == Some("NaN"))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6679",
            "Use \"Number.isNaN()\" to test for NaN.",
            it.span(),
        );
    }
}

fn numeric_literal_value(expression: &Expression<'_>) -> Option<f64> {
    match expression {
        Expression::NumericLiteral(literal) => Some(literal.value),
        _ => None,
    }
}

fn call_property<'r, 'a>(
    call: &'r CallExpression<'a>,
) -> Option<(&'r str, &'r MemberExpression<'a>)> {
    let member = call.callee.as_member_expression()?;
    let property = static_property_name(member)?;
    Some((property, member))
}

fn argument_expression<'r, 'a>(
    argument: &'r oxc_ast::ast::Argument<'a>,
) -> Option<&'r Expression<'a>> {
    argument.as_expression()
}

/// `S2692` (`indexOf(...) > 0`) and `S6557`
/// (`indexOf(...)[=|==|===] 0` / `lastIndexOf` equality shapes).
fn check_index_of_comparisons(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    let Expression::CallExpression(call) = &it.left else {
        return;
    };
    let Some((property, _)) = call_property(call) else {
        return;
    };
    if !matches!(property, "indexOf" | "lastIndexOf") {
        return;
    }
    let zero = numeric_literal_value(&it.right).is_some_and(|value| value == 0.0);
    if property == "indexOf" && it.operator == BinaryOperator::GreaterThan && zero {
        sink.emit_span(
            RuleScope::Both,
            "S2692",
            "Replace this comparison with \">= 0\" or \"!== -1\".",
            it.span(),
        );
    }
    if zero
        && matches!(
            it.operator,
            BinaryOperator::Equality | BinaryOperator::StrictEquality
        )
    {
        sink.emit_span(
            RuleScope::Both,
            "S6557",
            "Prefer \"startsWith()\"/\"includes()\" over this comparison.",
            it.span(),
        );
    }
}

/// `S3981`: `.length` comparisons that are always true or false.
fn check_length_comparison(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    let length_side = [&it.left, &it.right].iter().any(|operand| {
        let Some(member) = operand.as_member_expression() else {
            return false;
        };
        static_property_name(member) == Some("length")
    });
    let other = if it.left.as_member_expression().is_some() {
        &it.right
    } else {
        &it.left
    };
    let suspicious = length_side
        && (matches!(
            it.operator,
            BinaryOperator::LessThan
                | BinaryOperator::GreaterEqualThan
                | BinaryOperator::Equality
                | BinaryOperator::StrictEquality
        ) && numeric_literal_value(other).is_some_and(|value| value.eq(&-1.0) || value == 0.0));
    if suspicious {
        sink.emit_span(
            RuleScope::Both,
            "S3981",
            "Fix this always-true/false length comparison.",
            it.span(),
        );
    }
}

/// `S3003`: relational operators on two string literals.
fn check_relational_strings(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    if matches!(
        it.operator,
        BinaryOperator::LessThan
            | BinaryOperator::LessEqualThan
            | BinaryOperator::GreaterThan
            | BinaryOperator::GreaterEqualThan
    ) && matches!(&it.left, Expression::StringLiteral(_))
        && matches!(&it.right, Expression::StringLiteral(_))
    {
        sink.emit_span(
            RuleScope::Both,
            "S3003",
            "Do not compare string literals relationally.",
            it.span(),
        );
    }
}

/// `S4125`: `typeof x === 'literal'` with a value outside the typeof set.
fn check_typeof_literal(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    if !matches!(
        it.operator,
        BinaryOperator::Equality | BinaryOperator::StrictEquality
    ) {
        return;
    }
    let typeof_operand = [&it.left, &it.right].into_iter().find(|operand| {
        matches!(
            operand,
            Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::Typeof
        )
    });
    let literal_operand = [&it.left, &it.right]
        .into_iter()
        .find_map(|operand| match operand {
            Expression::StringLiteral(literal) => Some(literal.value.to_string()),
            _ => None,
        });
    if let (Some(_), Some(literal)) = (typeof_operand, literal_operand)
        && !TYPEOF_VALUES.contains(&literal.as_str())
    {
        sink.emit_span(
            RuleScope::JsOnly,
            "S4125",
            "This string is not a valid typeof result; fix the comparison.",
            it.span(),
        );
    }
}

/// `S2757` (the `x =+ 1` typo), `S6643`/`S2424` (writes into built-ins).
fn check_assignment_rules(sink: &mut IssueSink, it: &AssignmentExpression<'_>) {
    if it.operator == AssignmentOperator::Assign
        && let Expression::UnaryExpression(unary) = &it.right
        && matches!(
            unary.operator,
            UnaryOperator::UnaryPlus | UnaryOperator::UnaryNegation
        )
    {
        sink.emit_span(
            RuleScope::Both,
            "S2757",
            "Swap the \"=\" and sign characters if a compound assignment was intended.",
            it.right.span(),
        );
    }
    // Member assignment targets only; `(builtin root, prototype link)`.
    let (builtin_root, prototype_link) = match it.left.as_simple_assignment_target() {
        Some(oxc_ast::ast::SimpleAssignmentTarget::StaticMemberExpression(member)) => {
            member_builtin_conflict(&member.object)
        }
        Some(oxc_ast::ast::SimpleAssignmentTarget::ComputedMemberExpression(member)) => {
            member_builtin_conflict(&member.object)
        }
        _ => (false, false),
    };
    if builtin_root || prototype_link {
        sink.emit_span(
            RuleScope::Both,
            "S2424",
            "Do not modify built-in objects.",
            it.left.span(),
        );
    }
    if prototype_link {
        sink.emit_span(
            RuleScope::Both,
            "S6643",
            "Do not extend built-in prototypes.",
            it.left.span(),
        );
    }
}

/// Walks a member chain: is its root a built-in global (or `prototype`),
/// and does any link assign through `.prototype`?
fn member_builtin_conflict(expression: &Expression<'_>) -> (bool, bool) {
    match expression {
        Expression::Identifier(identifier) => {
            let name = identifier.name.as_ref();
            (
                BUILTIN_GLOBALS.contains(&name) || name == "prototype",
                false,
            )
        }
        Expression::StaticMemberExpression(member) => {
            let (root, prototype) = member_builtin_conflict(&member.object);
            (root, prototype || member.property.name == "prototype")
        }
        Expression::ComputedMemberExpression(member) => member_builtin_conflict(&member.object),
        _ => (false, false),
    }
}

/// Member-call rules: `S106`, `S1442`, `S6637`, `S6676`, `S6666`, `S6959`,
/// `S2871`, `S6653`, `S2685`, `S6654`, and `S6661`.
fn check_member_calls(sink: &mut IssueSink, it: &CallExpression<'_>) {
    let Some((property, member)) = call_property(it) else {
        return;
    };
    check_logging_and_binding_calls(sink, it, property, member);
    check_collection_and_object_calls(sink, it, property, member);
}

/// `S106`, `S1442`, `S6637`, and `S6676`.
fn check_logging_and_binding_calls(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    property: &str,
    member: &MemberExpression<'_>,
) {
    if member_rooted_at(member, "console") && CONSOLE_METHODS.contains(&property) {
        sink.emit_span(
            RuleScope::Both,
            "S106",
            "Remove this console logging call.",
            it.callee.span(),
        );
    }
    if property == "alert" {
        sink.emit_span(
            RuleScope::JsOnly,
            "S1442",
            "Remove this use of \"alert\".",
            it.callee.span(),
        );
    }
    if property == "bind"
        && it.arguments.len() == 1
        && argument_expression(&it.arguments[0])
            .is_some_and(|argument| matches!(argument, Expression::ThisExpression(_)))
        && bind_target_is_arrow(member_object(member))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6637",
            "Arrow functions are already bound; remove this \".bind(this)\".",
            it.callee.span(),
        );
    }
    if matches!(property, "call" | "apply") && it.arguments.len() == 1 {
        sink.emit_span(
            RuleScope::Both,
            "S6676",
            "Invoke this function directly instead of via \"call\"/\"apply\".",
            it.callee.span(),
        );
    }
}

/// `S6666`, `S6959`, `S2871`, `S6653`, `S2685`, `S6654`, and `S6661`.
fn check_collection_and_object_calls(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    property: &str,
    member: &MemberExpression<'_>,
) {
    if property == "apply"
        && it.arguments.len() == 2
        && argument_expression(&it.arguments[1])
            .is_some_and(|argument| matches!(argument, Expression::ArrayExpression(_)))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6666",
            "Use spread syntax instead of \"apply\".",
            it.arguments[1].span(),
        );
    }
    if property == "reduce" && it.arguments.len() == 1 {
        sink.emit_span(
            RuleScope::Both,
            "S6959",
            "Provide an initial accumulator value to this \"reduce\".",
            it.callee.span(),
        );
    }
    if matches!(property, "sort" | "toSorted") && it.arguments.is_empty() {
        sink.emit_span(
            RuleScope::Both,
            "S2871",
            "Provide a comparator to this sort call.",
            it.callee.span(),
        );
    }
    if property == "hasOwnProperty" {
        sink.emit_span(
            RuleScope::Both,
            "S6653",
            "Use \"Object.hasOwn()\" instead of \"hasOwnProperty()\".",
            it.callee.span(),
        );
    }
    if matches!(property, "caller" | "callee") && member_root_name(member) == Some("arguments") {
        sink.emit_span(
            RuleScope::Both,
            "S2685",
            "Do not access \"arguments.caller\"/\"arguments.callee\".",
            it.callee.span(),
        );
    }
    if property == "__proto__" {
        sink.emit_span(
            RuleScope::Both,
            "S6654",
            "Use \"Object.getPrototypeOf()\"/\"Object.setPrototypeOf()\" instead of \"__proto__\".",
            it.callee.span(),
        );
    }
    if property == "assign"
        && member_rooted_at(member, "Object")
        && it
            .arguments
            .first()
            .and_then(argument_expression)
            .is_some_and(|argument| matches!(argument, Expression::ObjectExpression(_)))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6661",
            "Use object spread syntax instead of \"Object.assign\".",
            it.arguments[0].span(),
        );
    }
}

/// Whether the `.bind(this)` receiver is an arrow function, possibly inside
/// parentheses (`(() => 1).bind(this)`).
fn bind_target_is_arrow(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::ArrowFunctionExpression(_) => true,
        Expression::ParenthesizedExpression(parenthesized) => {
            matches!(
                &parenthesized.expression,
                Expression::ArrowFunctionExpression(_)
            )
        }
        _ => false,
    }
}

fn member_object<'r, 'a>(member: &'r MemberExpression<'a>) -> &'r Expression<'a> {
    match member {
        MemberExpression::StaticMemberExpression(static_member) => &static_member.object,
        MemberExpression::ComputedMemberExpression(computed_member) => &computed_member.object,
        MemberExpression::PrivateFieldExpression(private_field) => &private_field.object,
    }
}

/// Plain-callee rules: `S1442`, `S2427`, `S3533`, `S2817`, `S6958`, and the
/// prototype-mutation calls of `S6643`.
fn check_plain_calls(sink: &mut IssueSink, it: &CallExpression<'_>) {
    if let Some(name) = callee_name(it) {
        if name == "alert" {
            sink.emit_span(
                RuleScope::JsOnly,
                "S1442",
                "Remove this use of \"alert\".",
                it.callee.span(),
            );
        }
        if name == "parseInt" && it.arguments.len() < 2 {
            sink.emit_span(
                RuleScope::Both,
                "S2427",
                "Add the radix parameter to this \"parseInt\".",
                it.callee.span(),
            );
        }
        if name == "require" {
            sink.emit_span(
                RuleScope::JsOnly,
                "S3533",
                "Use ECMAScript module imports instead of \"require\".",
                it.callee.span(),
            );
        }
        if matches!(name, "openDatabase" | "openDatabaseSync") {
            sink.emit_span(
                RuleScope::Both,
                "S2817",
                "Do not use the deprecated WebSQL database API.",
                it.callee.span(),
            );
        }
    } else if let Some((property, member)) = call_property(it)
        && matches!(property, "defineProperty" | "defineProperties")
        && BUILTIN_GLOBALS
            .iter()
            .any(|builtin| member_rooted_at(member, builtin))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6643",
            "Do not extend built-in prototypes.",
            it.callee.span(),
        );
    }
    if matches!(
        &it.callee,
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_)
    ) {
        sink.emit_span(
            RuleScope::Both,
            "S6958",
            "Do not invoke functions through literals.",
            it.callee.span(),
        );
    }
}

/// Constructor-call rules: `S1528`, `S1533`, `S2428`, and `S3834`.
fn check_constructor_calls(sink: &mut IssueSink, it: &NewExpression<'_>) {
    let Some(name) = constructor_name(it) else {
        return;
    };
    if name == "Array"
        && (it.arguments.len() >= 2
            || it.arguments.first().is_none_or(|argument| {
                argument_expression(argument)
                    .is_none_or(|expression| !matches!(expression, Expression::NumericLiteral(_)))
            }))
    {
        sink.emit_span(
            RuleScope::Both,
            "S1528",
            "Use array literal notation instead of the \"Array\" constructor.",
            it.span(),
        );
    }
    if matches!(name, "Number" | "String" | "Boolean") {
        sink.emit_span(
            RuleScope::Both,
            "S1533",
            "Use primitives instead of wrapper objects.",
            it.callee.span(),
        );
    }
    if name == "Object" {
        sink.emit_span(
            RuleScope::JsOnly,
            "S2428",
            "Use an object literal instead of \"new Object()\".",
            it.callee.span(),
        );
    }
    if matches!(name, "Symbol" | "BigInt") {
        sink.emit_span(
            RuleScope::JsOnly,
            "S3834",
            "Do not call this primitive constructor with \"new\".",
            it.callee.span(),
        );
    }
}

/// Raw-text rules on string literals: `S1516` (multi-line), `S3786`
/// (`${…}` inside a regular string), and `S6535` (unnecessary escapes).
fn check_string_literal_raw(sink: &mut IssueSink, it: &StringLiteral<'_>) {
    // `S1313`: dotted-quad IPv4 literals.
    if is_ipv4_like(it.value.as_str()) {
        sink.emit_span(
            RuleScope::Both,
            "S1313",
            "Remove this hard-coded IP address.",
            it.span,
        );
    }
    let Some(raw) = &it.raw else {
        return;
    };
    if raw.contains('\n') {
        sink.emit_span(
            RuleScope::Both,
            "S1516",
            "Use a template literal for multi-line strings.",
            it.span,
        );
    }
    if raw.contains("${") {
        sink.emit_span(
            RuleScope::Both,
            "S3786",
            "Use a template literal if \"${}\" interpolation was intended.",
            it.span,
        );
    }
    if has_unnecessary_escape(raw) {
        sink.emit_span(
            RuleScope::Both,
            "S6535",
            "Remove the unnecessary escape sequence from this string.",
            it.span,
        );
    }
}

/// A backslash followed by a character that does not need escaping.
fn has_unnecessary_escape(raw: &str) -> bool {
    let chars: Vec<char> = raw.chars().collect();
    let meaningful = [
        b'n', b't', b'r', b'b', b'f', b'v', b'x', b'u', b'\\', b'\'', b'"', b'`', b'0',
    ];
    chars.windows(2).any(|window| {
        window[0] == '\\'
            && window[1].is_ascii_alphanumeric()
            && !meaningful.contains(&(window[1] as u8))
    })
}

/// Whether `text` is exactly a dotted-quad IPv4 address (no octal-style
/// leading zeros, each octet at most 255).
fn is_ipv4_like(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
                && part.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

/// Legacy octal escapes (`\101`), including `\0`-prefixed forms.
fn has_octal_escape(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    chars
        .windows(2)
        .any(|window| window[0] == '\\' && ('1'..='7').contains(&window[1]))
}

fn regex_pattern_text<'a>(literal: &'a RegExpLiteral<'a>) -> &'a str {
    literal.regex.pattern.text.as_str()
}

/// `S1314` (legacy octal integer literals) and `S6534` (precision loss).
fn check_numeric_literal(sink: &mut IssueSink, it: &NumericLiteral<'_>) {
    let Some(raw) = &it.raw else {
        return;
    };
    let raw = raw.as_str();
    let digits = raw.trim_end_matches('n');
    if digits.len() > 1
        && digits.starts_with('0')
        && digits[1..].bytes().all(|byte| byte.is_ascii_digit())
    {
        sink.emit_span(
            RuleScope::Both,
            "S1314",
            "Use the \"0o\" prefix for octal literals.",
            it.span,
        );
    }
    if loses_precision(digits) {
        sink.emit_span(
            RuleScope::Both,
            "S6534",
            "This numeric literal exceeds safe precision; use BigInt or shorten it.",
            it.span,
        );
    }
}

fn loses_precision(digits: &str) -> bool {
    if digits.contains('.') || digits.contains('e') || digits.contains('E') {
        let significant = digits.chars().filter(char::is_ascii_digit).count();
        return significant > 17;
    }
    let cleaned = digits.trim_start_matches('0');
    i128::try_from(cleaned.len()).is_ok_and(|_| {
        cleaned
            .parse::<i128>()
            .is_ok_and(|value| value.abs() > 9_007_199_254_740_991)
    })
}

fn check_expression_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ExpressionCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        contexts: Vec::new(),
        ternary_depth: 0,
        template_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

fn property_key_name<'a>(key: &'a PropertyKey<'_>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

/// Name of an import/export name, unless it is a string literal.
fn module_export_name_name<'a>(name: &'a ModuleExportName<'_>) -> Option<&'a str> {
    match name {
        ModuleExportName::IdentifierName(identifier) => Some(&identifier.name),
        ModuleExportName::IdentifierReference(identifier) => Some(&identifier.name),
        ModuleExportName::StringLiteral(_) => None,
    }
}

/// Whether a binding name matches one of the configured words
/// (case-insensitively).
fn name_contains_any(name: &str, words: &[String]) -> bool {
    let lowered = name.to_lowercase();
    words.iter().any(|word| lowered.contains(word))
}

/// Binding, pattern, class, and interface batch rules in one traversal:
/// `S2137`, `S2138`, `S6645`, `S6650`, `S1527`, `S3799`, `S2094`, `S4023`,
/// `S4124`, `S6647`, `S1186`, `S2068`, and `S6418`.
struct BindingCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    rules: &'a RuleOptions,
    /// Depth inside call arguments; empty functions there are conventional
    /// callbacks and exempt from `S1186`.
    callback_argument_depth: u32,
    /// Depth inside `override` methods, also exempt from `S1186`.
    override_depth: u32,
    /// Depth inside constructors, whose emptiness is `S6647`'s domain.
    constructor_depth: u32,
}
impl<'a> Visit<'a> for BindingCollector<'a, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.callback_argument_depth += 1;
        walk_call_expression(self, it);
        self.callback_argument_depth -= 1;
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        self.check_binding_name(&it.id, it.span());
        self.check_declarator_init(it);
        self.check_renamed_binding(&it.id);
        self.check_empty_pattern(&it.id);
        self.check_credential_pair(binding_identifier_name(&it.id), it.init.as_ref());
        walk_variable_declarator(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        self.check_binding_name(&it.pattern, it.span());
        self.check_empty_pattern(&it.pattern);
        walk_formal_parameter(self, it);
    }

    fn visit_import_specifier(&mut self, it: &ImportSpecifier<'a>) {
        if let Some(imported) = module_export_name_name(&it.imported)
            && imported == it.local.name.as_str()
            && span_text_contains(self.source, it.span(), " as ")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6650",
                "Remove this redundant renaming.",
                it.span(),
            );
        }
    }

    fn visit_export_specifier(&mut self, it: &ExportSpecifier<'a>) {
        if let (Some(local), Some(exported)) = (
            module_export_name_name(&it.local),
            module_export_name_name(&it.exported),
        ) && local == exported
            && span_text_contains(self.source, it.span(), " as ")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6650",
                "Remove this redundant renaming.",
                it.span(),
            );
        }
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        if !it.shorthand
            && let (Some(key), Expression::Identifier(value)) =
                (property_key_name(&it.key), &it.value)
            && key == value.name.as_str()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6650",
                "Remove this redundant renaming.",
                it.span(),
            );
        }
        self.check_credential_pair(property_key_name(&it.key), Some(&it.value));
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let Some(oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(target)) =
            it.left.as_simple_assignment_target()
            && RESERVED_BINDING_NAMES.contains(&target.name.as_ref())
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2137",
                "Do not assign to this reserved global name.",
                target.span(),
            );
        }
        walk_assignment_expression(self, it);
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        if it.body.body.is_empty() {
            self.sink.emit_span(
                RuleScope::Both,
                "S2094",
                "Remove or implement this empty class.",
                it.span(),
            );
        }
        walk_class(self, it);
    }

    fn visit_ts_interface_declaration(&mut self, it: &TSInterfaceDeclaration<'a>) {
        let signatures = &it.body.body;
        if signatures.is_empty() {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4023",
                "Remove this empty interface.",
                it.span(),
            );
        }
        for signature in signatures {
            if matches!(signature, TSSignature::TSConstructSignatureDeclaration(_)) {
                self.sink.emit_span(
                    RuleScope::TsOnly,
                    "S4124",
                    "Declare construct signatures with a type alias instead.",
                    signature.span(),
                );
            }
        }
        walk_ts_interface_declaration(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if it.kind == MethodDefinitionKind::Constructor
            && let Some(body) = &it.value.body
            && body.statements.is_empty()
            && !it
                .value
                .params
                .items
                .iter()
                .any(FormalParameter::has_modifier)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6647",
                "Remove this constructor or add its logic.",
                it.span(),
            );
        }
        if it.r#override {
            self.override_depth += 1;
        }
        let saved_constructor_depth = self.constructor_depth;
        if it.kind == MethodDefinitionKind::Constructor {
            self.constructor_depth += 1;
        }
        walk_method_definition(self, it);
        self.constructor_depth = saved_constructor_depth;
        if it.r#override {
            self.override_depth -= 1;
        }
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.check_empty_function_body(it.statements.as_slice(), it.span());
        walk_function_body(self, it);
    }
}

impl BindingCollector<'_, '_> {
    /// `S2137` bindings and `S1527` future reserved words.
    fn check_binding_name(&mut self, pattern: &BindingPattern<'_>, span: Span) {
        let Some(name) = binding_identifier_name(pattern) else {
            return;
        };
        if RESERVED_BINDING_NAMES.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2137",
                "Do not bind to this reserved global name.",
                span,
            );
        }
        if FUTURE_RESERVED_WORDS.contains(&name) {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S1527",
                &format!("\"{name}\" is a future reserved word; rename this identifier."),
                span,
            );
        }
    }

    /// `S2138` and `S6645`: explicit `undefined` initializers.
    fn check_declarator_init(&mut self, it: &VariableDeclarator<'_>) {
        let initializes_to_undefined = match &it.init {
            Some(Expression::Identifier(identifier)) => identifier.name == "undefined",
            Some(Expression::UnaryExpression(unary)) => unary.operator == UnaryOperator::Void,
            _ => false,
        };
        if initializes_to_undefined {
            self.sink.emit_span(
                RuleScope::Both,
                "S2138",
                "Initialize with a meaningful value instead of \"undefined\".",
                it.init.as_ref().expect("checked above").span(),
            );
        }
        if matches!(&it.init, Some(Expression::Identifier(identifier)) if identifier.name == "undefined")
        {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S6645",
                "Remove this explicit \"undefined\" initializer.",
                it.init.as_ref().expect("checked above").span(),
            );
        }
    }

    /// `S6650`: `{ a: a }` destructuring renames.
    fn check_renamed_binding(&mut self, pattern: &BindingPattern<'_>) {
        if let BindingPattern::ObjectPattern(object_pattern) = pattern {
            for property in &object_pattern.properties {
                if !property.shorthand
                    && let (Some(key), Some(binding)) = (
                        property_key_name(&property.key),
                        binding_identifier_name(&property.value),
                    )
                    && key == binding
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S6650",
                        "Remove this redundant renaming.",
                        GetSpan::span(&property.key),
                    );
                }
            }
        }
    }

    /// `S3799`: zero-element destructuring patterns.
    fn check_empty_pattern(&mut self, pattern: &BindingPattern<'_>) {
        let is_empty = match pattern {
            BindingPattern::ObjectPattern(object_pattern) => {
                object_pattern.properties.is_empty() && object_pattern.rest.is_none()
            }
            BindingPattern::ArrayPattern(array_pattern) => array_pattern.elements.is_empty(),
            _ => false,
        };
        if is_empty {
            self.sink.emit_span(
                RuleScope::Both,
                "S3799",
                "Remove this empty destructuring pattern.",
                GetSpan::span(pattern),
            );
        }
    }

    /// `S2068` (password words) and `S6418` (high-entropy secrets next to
    /// secret-suggesting names).
    fn check_credential_pair(
        &mut self,
        context_name: Option<&str>,
        value: Option<&Expression<'_>>,
    ) {
        let Some(context_name) = context_name else {
            return;
        };
        let Some(Expression::StringLiteral(literal)) = value else {
            return;
        };
        let text = literal.value.as_str();
        if text.is_empty() {
            return;
        }
        if name_contains_any(context_name, &self.rules.password_words) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2068",
                "Remove this hard-coded credential.",
                literal.span,
            );
        }
        let name_matches_secret_word = self.rules.secret_words.iter().any(|word| {
            regex_search(word, context_name) || regex_search(word, &context_name.to_lowercase())
        });
        if name_matches_secret_word
            && text.chars().count() >= 16
            && shannon_entropy_per_char(text) > self.rules.secret_entropy_sensibility
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6418",
                "Remove this hard-coded secret.",
                literal.span,
            );
        }
    }

    /// `S1186`: empty function bodies outside callback conventions.
    fn check_empty_function_body(&mut self, statements: &[Statement<'_>], span: Span) {
        if statements.is_empty()
            && self.callback_argument_depth == 0
            && self.override_depth == 0
            && self.constructor_depth == 0
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S1186",
                "Add logic to this empty function or remove it.",
                span,
            );
        }
    }
}

/// `S138`: functions whose span covers more than `max` physical lines
/// (`end_line - start_line`, blank/comment trimming approximate per the
/// classification artifact).
struct FunctionLengthCollector<'index> {
    sink: IssueSink<'index>,
    maximum_function_lines: u32,
}

impl FunctionLengthCollector<'_> {
    fn check_length(&mut self, span: Span) {
        let start_line = self.sink.index.pos(span.start).line;
        let end_line = self.sink.index.pos(span.end).line;
        let length = end_line - start_line;
        if length > self.maximum_function_lines {
            self.sink.emit_pos(
                RuleScope::Both,
                "S138",
                &format!(
                    "This function has {} lines, which is greater than the {} authorized. \
                     Split it into smaller pieces.",
                    length, self.maximum_function_lines
                ),
                (start_line, 0),
                (start_line, 0),
            );
        }
    }
}

impl<'a> Visit<'a> for FunctionLengthCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            self.check_length(function.span());
        }
        walk_expression(self, it);
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            self.check_length(function.span());
        }
        walk_declaration(self, it);
    }

    fn visit_export_default_declaration_kind(&mut self, it: &ExportDefaultDeclarationKind<'a>) {
        if let ExportDefaultDeclarationKind::FunctionDeclaration(function) = it {
            self.check_length(function.span());
        }
        walk_export_default_declaration_kind(self, it);
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.check_length(it.span());
        walk_arrow_function_expression(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.check_length(it.span());
        walk_method_definition(self, it);
    }
}

fn binding_identifier_name<'a>(pattern: &'a BindingPattern<'_>) -> Option<&'a str> {
    match pattern {
        BindingPattern::BindingIdentifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

fn check_binding_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    let mut collector = BindingCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        rules,
        callback_argument_depth: 0,
        override_depth: 0,
        constructor_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

fn check_function_lengths(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    let mut collector = FunctionLengthCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        maximum_function_lines: rules.maximum_function_lines,
    };
    collector.visit_program(program);
    collector.sink.issues
}

#[cfg(test)]
mod tests {
    use super::{AnalyzerOptions, JstsLanguage, RuleOptions, analyze, language_for_extension};
    use std::path::PathBuf;

    fn pos(line: u32, column: u32) -> hoonarqube_ir::Pos {
        hoonarqube_ir::Pos { line, column }
    }

    fn issue(
        rule_key: &str,
        message: &str,
        start: (u32, u32),
        end: (u32, u32),
    ) -> hoonarqube_ir::Issue {
        hoonarqube_ir::Issue {
            rule_key: rule_key.to_string(),
            message: message.to_string(),
            range: hoonarqube_ir::Range {
                start: pos(start.0, start.1),
                end: pos(end.0, end.1),
            },
        }
    }

    fn js(source: &str) -> hoonarqube_ir::FileReport {
        analyze(
            PathBuf::from("test.js"),
            source,
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        )
    }

    fn ts(source: &str) -> hoonarqube_ir::FileReport {
        analyze(
            PathBuf::from("test.ts"),
            source,
            JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        )
    }

    #[test]
    fn extensions_map_to_languages() {
        assert_eq!(language_for_extension("js"), Some(JstsLanguage::JavaScript));
        assert_eq!(
            language_for_extension("jsx"),
            Some(JstsLanguage::JavaScript)
        );
        assert_eq!(
            language_for_extension("mjs"),
            Some(JstsLanguage::JavaScript)
        );
        assert_eq!(
            language_for_extension("cjs"),
            Some(JstsLanguage::JavaScript)
        );
        assert_eq!(language_for_extension("ts"), Some(JstsLanguage::TypeScript));
        assert_eq!(
            language_for_extension("tsx"),
            Some(JstsLanguage::TypeScript)
        );
        assert_eq!(
            language_for_extension("mts"),
            Some(JstsLanguage::TypeScript)
        );
        assert_eq!(
            language_for_extension("cts"),
            Some(JstsLanguage::TypeScript)
        );
        assert_eq!(language_for_extension("py"), None);
    }

    #[test]
    fn line_length_honors_option_with_exact_boundary_clean() {
        // Exactly at the limit: clean. One more character: flagged.
        let options = AnalyzerOptions {
            maximum_line_length: 13,
        };
        let at_limit = analyze(
            PathBuf::from("test.js"),
            "const ab = 1;\n",
            JstsLanguage::JavaScript,
            &options,
        );
        assert!(at_limit.issues.is_empty());

        let over_limit = analyze(
            PathBuf::from("test.js"),
            "const abc = 1;\n",
            JstsLanguage::JavaScript,
            &options,
        );
        assert_eq!(
            over_limit.issues,
            vec![issue(
                "javascript:S103",
                "This line exceeds the maximum allowed length of 13 characters.",
                (1, 0),
                (1, 14),
            )]
        );
    }

    #[test]
    fn one_statement_per_line_flags_only_second_onwards_including_nesting() {
        let source = "\
let a = 1; let b = 2;
function f() {
  let c = 3; let d = 4;
}
if (a) { g(); h(); }
while (false) { i(); j(); }
try { k(); l(); } catch { m(); n(); }
";
        let report = js(source);
        let s122: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S122"))
            .collect();
        // One issue per additional statement sharing a line: top level, the
        // function body, the `if` block, the `while` block, and two in the
        // try/catch line (`l()` and `n()`).
        assert_eq!(s122.len(), 6);
        assert!(
            s122.iter()
                .all(|issue| issue.message == "Only one statement per line is allowed.")
        );
        assert_eq!(
            s122[0].range,
            hoonarqube_ir::Range {
                start: pos(1, 11),
                end: pos(1, 21),
            }
        );
    }
    #[test]
    fn issues_are_sorted_by_position() {
        let source = "\
eval(\"a\");
let b = 1; let c = 2;
";
        let report = js(source);
        let starts: Vec<_> = report
            .issues
            .iter()
            .map(|issue| {
                (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.rule_key.clone(),
                )
            })
            .collect();
        assert_eq!(
            starts,
            vec![
                (1_u32, 0_u32, "javascript:S1523".to_string()),
                (2_u32, 11_u32, "javascript:S122".to_string()),
            ]
        );
    }

    #[test]
    fn switch_and_loop_single_statement_bodies_are_walked() {
        let source = "\
for (let i = 0; i < 1; i++) o(); p();
switch (x) { case 1: q(); r(); }
label: s(); t();
with (obj) { u(); v(); }
";
        let report = js(source);
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S122"))
                .count(),
            4
        );
    }

    #[test]
    fn eval_usage_is_flagged_at_callee_span_across_the_tree() {
        let source = "\
eval(\"x\");
const f = new Function(\"return 1\");
foo(eval(nested));
window.eval(\"not plain identifier\");
new window.Function(\"also ignored\");

";
        let report = js(source);
        assert_eq!(
            report.issues,
            vec![
                issue(
                    "javascript:S1523",
                    "Remove this usage of 'eval'.",
                    (1, 0),
                    (1, 4),
                ),
                issue(
                    "javascript:S1523",
                    "Remove this usage of 'Function'.",
                    (2, 14),
                    (2, 22),
                ),
                issue(
                    "javascript:S1523",
                    "Remove this usage of 'eval'.",
                    (3, 4),
                    (3, 8),
                ),
                issue(
                    "javascript:S1848",
                    "Use this object instantiation or remove it.",
                    (5, 0),
                    (5, 35),
                ),
            ]
        );
    }

    #[test]
    fn typescript_input_parses_and_carries_typescript_prefix() {
        let report = ts("const x: number = 1;\ninterface Y { z: string }\n");
        assert_eq!(report.language, "typescript");
        assert!(report.issues.is_empty());
    }

    #[test]
    fn jsx_input_parses_cleanly() {
        let report = analyze(
            PathBuf::from("test.jsx"),
            "const el = <div className=\"a\">hi</div>;\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert!(report.issues.is_empty());
    }

    #[test]
    fn rule_keys_follow_file_language_prefix() {
        let javascript = js("eval(\"x\");");
        assert_eq!(javascript.issues[0].rule_key, "javascript:S1523");

        let typescript = ts("eval(\"x\");");
        assert_eq!(typescript.issues[0].rule_key, "typescript:S1523");
        assert_eq!(typescript.language, "typescript");
    }

    #[test]
    fn broken_source_neither_panics_nor_emits_parse_errors() {
        let report = js("function {(:\n    ???\n");
        // No catalog-backed parse-error rule exists for js/ts; the analyzer
        // reports the file with zero issues instead of failing the run.
        assert!(report.issues.is_empty());
    }

    #[test]
    fn comment_lines_are_counted_separately_from_code() {
        let report = ts("// leading note\nconst x: number = 1;\n/* block\nstill block */\n");
        assert_eq!(report.metrics.lines, 4);
        assert_eq!(report.metrics.code_lines, 1);
        assert_eq!(report.metrics.comment_lines, 3);
    }

    #[test]
    fn comment_on_code_line_counts_as_code_only() {
        let report = js("let a = 1; // trailing\n");
        assert_eq!(report.metrics.code_lines, 1);
        assert_eq!(report.metrics.comment_lines, 0);
    }

    #[test]
    fn scanner_ignores_comment_lookalikes_in_strings_templates_regexes() {
        let source = concat!(
            "const a = \"http://not-a-comment\";\n",
            "const b = `template // text ${x + 1} done`;\n",
            "const c = /regex\\/with\\/slashes/;\n",
            "const d = a / b;\n",
        );
        let report = js(source);
        assert_eq!(report.metrics.comment_lines, 0);
        assert_eq!(report.metrics.code_lines, 4);
    }

    #[test]
    fn scanner_finds_comments_around_regex_and_division() {
        // Own-line comments survive; the regex and division on code lines
        // must not swallow or fabricate comment rows.
        let source = concat!(
            "// header\n",
            "function f() {\n",
            "  return /x/g.test(s);\n",
            "}\n",
            "// footer\n",
            "let d = a / b;\n",
        );
        let report = js(source);
        assert_eq!(report.metrics.comment_lines, 2);
        assert_eq!(report.metrics.code_lines, 4);
    }

    #[test]
    fn multiline_block_comment_between_statements_is_fully_counted() {
        let source = "let a = 1;\n/* one\ntwo\nthree */\nlet b = 2;\n";
        let report = js(source);
        assert_eq!(report.metrics.comment_lines, 3);
        assert_eq!(report.metrics.code_lines, 2);
    }

    // ---- Batch-1 rule fixtures ----

    fn findings(source: &str, language: JstsLanguage) -> Vec<(String, u32)> {
        analyze(
            PathBuf::from("test.js"),
            source,
            language,
            &AnalyzerOptions::default(),
        )
        .issues
        .into_iter()
        .map(|issue| (issue.rule_key, issue.range.start.line))
        .collect()
    }

    fn count_key(findings: &[(String, u32)], key: &str) -> usize {
        findings
            .iter()
            .filter(|(key_found, _)| key_found == key)
            .count()
    }

    fn js_keys(source: &str) -> Vec<(String, u32)> {
        findings(source, JstsLanguage::JavaScript)
    }

    #[test]
    fn text_scans_flag_tabs_trailing_whitespace_and_missing_newline() {
        let flagged = js_keys("const\t a = 1;  \nlet x;");
        assert_eq!(count_key(&flagged, "javascript:S105"), 1);
        assert_eq!(count_key(&flagged, "javascript:S1131"), 1);
        assert_eq!(count_key(&flagged, "javascript:S113"), 1);

        let clean = js_keys("const a = 1;\nlet x;\n");
        assert_eq!(count_key(&clean, "javascript:S105"), 0);
        assert_eq!(count_key(&clean, "javascript:S1131"), 0);
        assert_eq!(count_key(&clean, "javascript:S113"), 0);
    }

    #[test]
    fn loc_and_function_length_boundaries_honor_rule_options() {
        let strict = RuleOptions {
            maximum_lines_of_code: 3,
            maximum_function_lines: 2,
            ..RuleOptions::default()
        };
        let report = super::analyze_with_rules(
            PathBuf::from("test.js"),
            "a();\nb();\nc();\nd();\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &strict,
        );
        assert_eq!(count_key(&report_keys(&report), "javascript:S104"), 1);

        let long_function = "function f() {\n  a();\n  b();\n  c();\n}\n";
        let flagged = super::analyze_with_rules(
            PathBuf::from("test.js"),
            long_function,
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &strict,
        );
        assert_eq!(count_key(&report_keys(&flagged), "javascript:S138"), 1);

        let relaxed = RuleOptions {
            maximum_lines_of_code: 1000,
            maximum_function_lines: 200,
            ..RuleOptions::default()
        };
        let clean = super::analyze_with_rules(
            PathBuf::from("test.js"),
            long_function,
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &relaxed,
        );
        assert_eq!(count_key(&report_keys(&clean), "javascript:S138"), 0);
    }

    fn report_keys(report: &hoonarqube_ir::FileReport) -> Vec<(String, u32)> {
        report
            .issues
            .iter()
            .map(|issue| (issue.rule_key.clone(), issue.range.start.line))
            .collect()
    }

    #[test]
    fn file_header_requires_configured_prefix() {
        let mut rules = RuleOptions {
            header_format: "// Copyright\n".to_string(),
            ..RuleOptions::default()
        };
        let missing = super::analyze_with_rules(
            PathBuf::from("test.js"),
            "let x = 1;\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &rules,
        );
        assert_eq!(count_key(&report_keys(&missing), "javascript:S1451"), 1);

        let present = super::analyze_with_rules(
            PathBuf::from("test.js"),
            "// Copyright\nlet x = 1;\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &rules,
        );
        assert_eq!(count_key(&report_keys(&present), "javascript:S1451"), 0);

        rules.header_is_regular_expression = true;
        rules.header_format = r"^// \(c\) \d{4}".to_string();
        let regex_present = super::analyze_with_rules(
            PathBuf::from("test.js"),
            "// (c) 2026 ACME\nlet x = 1;\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &rules,
        );
        assert_eq!(
            count_key(&report_keys(&regex_present), "javascript:S1451"),
            0
        );

        let regex_missing = super::analyze_with_rules(
            PathBuf::from("test.js"),
            "// Other header\nlet x = 1;\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &rules,
        );
        assert_eq!(
            count_key(&report_keys(&regex_missing), "javascript:S1451"),
            1
        );
    }

    #[test]
    fn comment_tag_and_suppression_rules_fire_once_per_comment() {
        let flagged = js_keys("// FIXME later\n// TODO task\n// NOSONAR\n");
        assert_eq!(count_key(&flagged, "javascript:S1134"), 1);
        assert_eq!(count_key(&flagged, "javascript:S1135"), 1);
        assert_eq!(count_key(&flagged, "javascript:S1291"), 1);

        let clean = js_keys("// a note\n/* another */\n");
        assert_eq!(count_key(&clean, "javascript:S1134"), 0);
        assert_eq!(count_key(&clean, "javascript:S1135"), 0);
        assert_eq!(count_key(&clean, "javascript:S1291"), 0);
    }

    #[test]
    fn disallowed_comment_pattern_only_fires_on_code_lines() {
        let inline = js_keys("let x = 1; // hack\n");
        assert_eq!(count_key(&inline, "javascript:S139"), 1);

        let own_line = js_keys("// hack\nlet x = 1;\n");
        assert_eq!(count_key(&own_line, "javascript:S139"), 0);
    }

    #[test]
    fn commented_out_code_heuristic_flags_keyword_comments() {
        let flagged = js_keys("// return value;\n");
        assert_eq!(count_key(&flagged, "javascript:S125"), 1);

        let prose = js_keys("// this comment only explains things\n");
        assert_eq!(count_key(&prose, "javascript:S125"), 0);
    }

    #[test]
    fn statement_level_batch_rules_fire() {
        let source = "\
debugger;
with (o) { }
var v = 1;
import * as ns from 'm';
import x from '/abs';
throw 'oops';
new Error('x');
;;
";
        let flagged = js_keys(source);
        for key in [
            "S1525", "S1321", "S3504", "S2208", "S6859", "S3696", "S3984", "S1848", "S1116",
        ] {
            assert!(
                count_key(&flagged, &format!("javascript:{key}")) >= 1,
                "expected {key}"
            );
        }
    }

    #[test]
    fn control_structure_batch_rules_fire() {
        let source = "\
if (a) b();
else { if (c) d(); }
if (e) { if (f) g(); }
switch (s) { case 1: let z = 2; }
while (x) continue;
";
        let flagged = js_keys(source);
        for key in ["S121", "S6660", "S1066", "S6836", "S909"] {
            assert!(
                count_key(&flagged, &format!("javascript:{key}")) >= 1,
                "expected {key}"
            );
        }
    }

    #[test]
    fn expression_level_batch_rules_fire() {
        let source = "\
if (a == b) { void c; (d, e); }
if (x === NaN) { if (list.length < 0) { } }
const n = parseInt(s);
console.log(n);
alert(n);
values.sort();
other.reduce(cb);
if (list.indexOf(x) > 0) { }
if ('a' < 'b') { }
q = cond ? nested(1) : outer(cond ? nested(2) : 3);
r = flag ? true : false;
f = (() => 1).bind(this);
g.call(ctx);
h.apply(ctx, [args]);
Object.assign({}, opts);
const arr = new Array(1, 2);
const num = new Number(5);
legacy = require('mod');
db = openDatabase(name);
outer = `${inner `${deep}`}`;
text = \"interp ${x}\";
host = '10.0.0.1';
";
        let flagged = js_keys(source);
        for key in [
            "S1440", "S3735", "S878", "S6679", "S3981", "S2427", "S106", "S1442", "S2871", "S6959",
            "S2692", "S3003", "S1774", "S6644", "S6637", "S6676", "S6666", "S6661", "S1528",
            "S1533", "S3533", "S2817", "S4624", "S3786", "S1313",
        ] {
            assert!(
                count_key(&flagged, &format!("javascript:{key}")) >= 1,
                "expected {key}"
            );
        }
    }

    #[test]
    fn binding_and_pattern_batch_rules_fire() {
        let source = "\
const shadow = undefined;
const int = 1;
const { renamed: renamed } = pair;
const {} = empty;
const password = 'hunter2';
const apiKeyValue = 'Zx9kQ2vL8pR4tW7yB1nM6cJ3fH5dG0aE#';
NaN = 1;
";
        let flagged = js_keys(source);
        for key in [
            "S2138", "S6645", "S1527", "S6650", "S3799", "S2068", "S6418", "S2137",
        ] {
            assert!(
                count_key(&flagged, &format!("javascript:{key}")) >= 1,
                "expected {key}"
            );
        }
    }

    #[test]
    fn class_interface_and_empty_body_rules_respect_scope() {
        let ts_source = "\
class Empty {}
interface Nothing {}
interface WithCtor { new (): void; }
function bare() {}
const cb = () => {};
arr.map(function () {});
";
        let ts_findings = findings(ts_source, JstsLanguage::TypeScript);
        assert_eq!(count_key(&ts_findings, "typescript:S2094"), 1);
        assert_eq!(count_key(&ts_findings, "typescript:S4023"), 1);
        assert_eq!(count_key(&ts_findings, "typescript:S4124"), 1);
        // Callback conventions suppress `S1186`.
        assert_eq!(count_key(&ts_findings, "typescript:S1186"), 2);

        let js_findings = findings(ts_source, JstsLanguage::JavaScript);
        assert_eq!(count_key(&js_findings, "javascript:S4023"), 0);
        assert_eq!(count_key(&js_findings, "javascript:S4124"), 0);
    }

    #[test]
    fn javascript_only_rules_do_not_fire_for_typescript() {
        let source = "with (o) {}\nalert('hi');\nlegacy = require('m');\n";
        let typescript = findings(source, JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S1321"), 0);
        assert_eq!(count_key(&typescript, "typescript:S1442"), 0);
        assert_eq!(count_key(&typescript, "typescript:S3533"), 0);
    }

    #[test]
    fn parse_errors_never_surface_as_issues() {
        let broken = js_keys("function {(:\n    ???\n");
        assert!(broken.iter().all(|(key, _)| !key.ends_with(":S2260")));
    }
}
