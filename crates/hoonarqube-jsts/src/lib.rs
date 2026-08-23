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
    AssignmentOperator, BinaryExpression, BinaryOperator, BindingIdentifier, BindingPattern,
    BlockStatement, CallExpression, Class, ClassElement, ConditionalExpression, ContinueStatement,
    DebuggerStatement, Declaration, EmptyStatement, ExportDefaultDeclarationKind, ExportSpecifier,
    Expression, ExpressionStatement, FormalParameter, FunctionBody, IfStatement, ImportDeclaration,
    ImportDeclarationSpecifier, ImportSpecifier, JSXAttribute, LabeledStatement, LogicalExpression,
    LogicalOperator, MemberExpression, MethodDefinition, MethodDefinitionKind, ModuleDeclaration,
    ModuleExportName, NewExpression, NumericLiteral, ObjectProperty, ParenthesizedExpression,
    PropertyKey, RegExpLiteral, ReturnStatement, SequenceExpression, Statement, StaticBlock,
    StringLiteral, SwitchCase, SwitchStatement, TSInterfaceDeclaration, TSSignature,
    TemplateLiteral, ThrowStatement, UnaryExpression, UnaryOperator, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator, WithStatement,
};
use oxc_ast::ast_kind::AstKind;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_array_expression, walk_arrow_function_expression, walk_assignment_expression,
    walk_binary_expression, walk_binding_pattern, walk_block_statement, walk_call_expression,
    walk_class, walk_declaration, walk_export_default_declaration_kind, walk_expression,
    walk_expression_statement, walk_formal_parameter, walk_function_body, walk_if_statement,
    walk_import_declaration, walk_labeled_statement, walk_member_expression,
    walk_method_definition, walk_new_expression, walk_object_property,
    walk_parenthesized_expression, walk_return_statement, walk_sequence_expression,
    walk_static_block, walk_switch_case, walk_switch_statement, walk_template_literal,
    walk_throw_statement, walk_ts_interface_declaration, walk_unary_expression,
    walk_variable_declaration, walk_variable_declarator,
};
use oxc_parser::Parser;
use oxc_span::{ContentEq, GetSpan, SourceType, Span};

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
/// `randomnessSensibility=5.0`,
/// `secretWords="api[_.-]?key,auth,credential,secret,token"`, `S100`/`S101`/
/// `S117` naming `format` regular expressions, `S1192`
/// `threshold=3` / `ignoreStrings="application/json"`, `S1441`
/// `singleQuotes=true`, and `S6747` `whitelist=<empty>`.
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
    format_functions: String,
    format_classes: String,
    format_variables: String,
    duplicate_string_threshold: usize,
    ignored_strings: Vec<String>,
    single_quotes: bool,
    jsx_attribute_whitelist: Vec<String>,
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
            format_functions: r"^[_a-z][a-zA-Z0-9]*$".to_string(),
            format_classes: r"^[A-Z][a-zA-Z0-9]*$".to_string(),
            format_variables: r"^[_$A-Za-z][$A-Za-z0-9]*$|^[_$A-Z][_$A-Z0-9]+$".to_string(),
            duplicate_string_threshold: 3,
            ignored_strings: split_words("application/json"),
            single_quotes: true,
            jsx_attribute_whitelist: split_words(""),
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

/// Whole-file text and comment checks that run before the AST walks.
fn check_file_level_rules(
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
    rules: &RuleOptions,
    index: &LineIndex,
    body: &[Statement<'_>],
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_line_length(source, language, options));
    issues.extend(check_tab_characters(source, language));
    issues.extend(check_missing_newline_at_eof(source, language, index));
    issues.extend(check_trailing_whitespace(source, language));
    issues.extend(check_too_many_lines_of_code(body, index, language, rules));
    issues.extend(check_file_header(source, language, rules));
    issues.extend(check_comment_rules(source, index, language, rules));
    issues
}

/// Single-traversal AST batch checks: statement, expression, binding,
/// function-length, eval-usage, naming, and duplicate-structure rules.
fn check_core_ast_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
    body: &[Statement<'_>],
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_one_statement_per_line(body, index, language));
    issues.extend(check_statement_rules(program, source, index, language));
    issues.extend(check_expression_rules(program, index, language));
    issues.extend(check_binding_rules(program, source, index, language, rules));
    issues.extend(check_function_lengths(program, index, language, rules));
    issues.extend(check_eval_usage(program, index, language));
    // --- Batch2a: name/format and structural duplicate/identity rules ---
    issues.extend(check_naming_rules(program, index, language, rules));
    issues.extend(check_duplicate_rules(program, index, language));
    issues
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
    let mut issues = check_file_level_rules(source, language, options, rules, &index, body);
    // `S2260` (`ParsingError`) hook: `parsed.errors` is deliberately not
    // reported — see the module documentation for the tolerant-parse
    // decision; the partial AST below is analyzed regardless.
    let _ = &parsed.diagnostics;
    issues.extend(check_core_ast_rules(
        &parsed.program,
        source,
        &index,
        language,
        rules,
        body,
    ));
    // --- Batch2b wiring: statement-shape and control-flow walks ---
    issues.extend(check_switch_flow(&parsed.program, &index, language));
    issues.extend(check_loop_rules(&parsed.program, source, &index, language));
    issues.extend(check_flow_nesting_rules(&parsed.program, &index, language));
    issues.extend(check_embedded_effects(&parsed.program, &index, language));
    issues.extend(check_brace_style(&parsed.program, source, &index, language));
    issues.extend(check_label_usage(&parsed.program, &index, language));
    issues.extend(check_statement_sequences(&parsed.program, &index, language));
    issues.extend(check_function_contexts(&parsed.program, &index, language));
    issues.extend(check_call_argument_lines(&parsed.program, &index, language));
    issues.extend(check_self_assignments(
        &parsed.program,
        source,
        &index,
        language,
    ));
    issues.extend(check_exception_handling(
        &parsed.program,
        source,
        &index,
        language,
    ));
    issues.extend(check_function_structures(
        &parsed.program,
        source,
        &index,
        language,
    ));
    issues.extend(check_swapped_call_arguments(
        &parsed.program,
        &index,
        language,
    ));
    issues.extend(check_arrow_body_consistency(
        &parsed.program,
        &index,
        language,
    ));
    // --- Batch2d wiring: control-flow remainder groups D/E and the
    // --- ES2015+ idiom section ---
    issues.extend(check_batch2d_rules(
        &parsed.program,
        source,
        &index,
        language,
    ));
    // --- Batch3 wiring: the regex-literal family ---
    issues.extend(check_regex_family(&parsed.program, &index, language));
    // --- Batch4 wiring: React/JSX structural and accessibility families ---
    issues.extend(check_react_jsx_rules(
        &parsed.program,
        source,
        &index,
        language,
        rules,
    ));
    issues.extend(check_jsx_accessibility_rules(
        &parsed.program,
        &index,
        language,
    ));
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

// ===== Batch2b: statement-shape and control-flow walks =====
//
// Family A — switch/if-chain flow: `S126`, `S128`, `S131`, `S4524`,
// `S3616`, `S1479`, `S1301`, and `S1821`. Catalog parameters used by
// this section are kept as local constants mirroring the frozen
// catalog defaults.

/// `S1479`: switch statements carrying more cases than this are flagged
/// (frozen catalog default of the `maximum` parameter).
const MAX_SWITCH_CASES: usize = 30;

/// `S1301`: switches with at most this many tested cases are flagged as
/// convertible to `if` (frozen catalog default).
const MAX_TINY_SWITCH_CASES: usize = 2;

/// Peels parenthesized wrappers; this parser preserves parentheses, so
/// `case (a(), b):` surfaces its sequence expression behind one.
fn unparenthesized<'a, 'b>(expression: &'a Expression<'b>) -> &'a Expression<'b> {
    let mut current = expression;
    while let Expression::ParenthesizedExpression(parenthesized) = current {
        current = &parenthesized.expression;
    }
    current
}

/// Whether a case test uses a sequence expression or a logical OR
/// (`S3616`).
fn case_test_is_sequence_or_or(test: &Expression<'_>) -> bool {
    match unparenthesized(test) {
        Expression::SequenceExpression(_) => true,
        Expression::LogicalExpression(logical) => logical.operator == LogicalOperator::Or,
        _ => false,
    }
}

/// Whether a statement terminates unconditionally for `S128`: a direct
/// jump, a block whose last statement jumps, or an `if/else` where both
/// branches jump.
fn statement_ends_with_jump(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::BreakStatement(_)
        | Statement::ContinueStatement(_)
        | Statement::ReturnStatement(_)
        | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(block) => block.body.last().is_some_and(statement_ends_with_jump),
        Statement::IfStatement(if_statement) => {
            statement_ends_with_jump(&if_statement.consequent)
                && if_statement
                    .alternate
                    .as_ref()
                    .is_some_and(statement_ends_with_jump)
        }
        _ => false,
    }
}

/// Switch-statement and if-chain flow rules in one traversal: `S126`
/// (chain without final `else`), `S128` (case fall-through), `S131`
/// (missing `default`), `S4524` (default not last), `S3616` (sequence or
/// logical-OR case test), `S1479` (too many cases), `S1301` (switch
/// convertible to `if`), and `S1821` (switch nested inside a case).
struct SwitchFlowCollector<'index> {
    sink: IssueSink<'index>,
    /// Set while visiting the `alternate` of an enclosing `if`; detects
    /// chains whose last link lacks a final `else` (`S126`).
    in_else_if_chain: bool,
    /// Number of enclosing `SwitchCase` consequents (`S1821`).
    case_depth: u32,
}

impl<'a> Visit<'a> for SwitchFlowCollector<'_> {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        if self.in_else_if_chain && it.alternate.is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S126",
                "Add a final \"else\" clause to this if/else-if chain.",
                it.span(),
            );
        }
        let saved_in_chain = self.in_else_if_chain;
        self.in_else_if_chain = false;
        self.visit_statement(&it.consequent);
        self.in_else_if_chain = matches!(&it.alternate, Some(Statement::IfStatement(_)));
        if let Some(alternate) = &it.alternate {
            self.visit_statement(alternate);
        }
        self.in_else_if_chain = saved_in_chain;
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        if self.case_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1821",
                "Extract this nested switch statement from its parent case.",
                it.span(),
            );
        }
        if it.cases.iter().all(|case| case.test.is_some()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S131",
                "Add a \"default\" case to this switch statement.",
                it.span(),
            );
        }
        let last_case_index = it.cases.len().saturating_sub(1);
        for (case_index, case) in it.cases.iter().enumerate() {
            if case.test.is_none() && case_index != last_case_index {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4524",
                    "Move this default case to the end of this switch statement.",
                    case.span(),
                );
            }
        }
        if it.cases.len() > MAX_SWITCH_CASES {
            self.sink.emit_span(
                RuleScope::Both,
                "S1479",
                &format!(
                    "Reduce the number of switch cases from {} to at most {}.",
                    it.cases.len(),
                    MAX_SWITCH_CASES
                ),
                it.span(),
            );
        }
        let tested_cases = it.cases.iter().filter(|case| case.test.is_some()).count();
        if (1..=MAX_TINY_SWITCH_CASES).contains(&tested_cases) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1301",
                "Replace this switch statement with an if statement.",
                it.span(),
            );
        }
        walk_switch_statement(self, it);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        if let Some(test) = &it.test
            && case_test_is_sequence_or_or(test)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3616",
                "Remove this sequence expression or logical OR from the case test.",
                test.span(),
            );
        }
        if let Some(last) = it.consequent.last()
            && !statement_ends_with_jump(last)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S128",
                "End this case with an unconditional break, return, throw, or continue statement.",
                it.span(),
            );
        }
        self.case_depth += 1;
        walk_switch_case(self, it);
        self.case_depth -= 1;
    }
}

fn check_switch_flow(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = SwitchFlowCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        in_else_if_chain: false,
        case_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

// ----- Batch2b Family B - loop shape: `S888`, `S1264`, `S2251`, `S1994`,
// ----- `S2310`, `S135`, `S1751`, `S2189` (JS-only), `S1535`, `S4139`, and
// ----- `S4138`.

use oxc_ast::ast::{
    AssignmentTarget, BreakStatement, DoWhileStatement, ForInStatement, ForOfStatement,
    ForStatement, ForStatementInit, SimpleAssignmentTarget, UpdateExpression, UpdateOperator,
    WhileStatement,
};
use oxc_ast_visit::walk::{
    walk_do_while_statement, walk_for_in_statement, walk_for_of_statement, walk_while_statement,
};

/// Detects any `continue` below a loop body for the `S1751` exemption.
#[derive(Default)]
struct ContinueScanner {
    found: bool,
}

impl<'a> Visit<'a> for ContinueScanner {
    fn visit_continue_statement(&mut self, _it: &ContinueStatement<'a>) {
        self.found = true;
    }
}

/// Per-loop state collected while [`LoopFlowCollector`] walks one loop.
#[derive(Default)]
struct LoopFrame {
    /// Break/continue statements seen directly in this loop (`S135`).
    jumps: u32,
    /// Any break/return/throw seen anywhere below (`S2189`).
    terminators: bool,
    /// A `hasOwnProperty` reference was seen (`S1535`).
    has_own_guard: bool,
    /// Names of counters declared by this loop's init clause (`S2310`).
    counters: Vec<String>,
}

/// Loop-shape rules in one traversal.
struct LoopFlowCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    /// One frame per lexically enclosing visited loop.
    frames: Vec<LoopFrame>,
}

/// Name bound by an assignment target, if it is a plain identifier.
fn assignment_target_name<'a>(target: &'a AssignmentTarget<'a>) -> Option<&'a str> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

/// Name modified by an update expression (`++`/`--`), if plain.
fn update_target_name<'a>(update: &'a UpdateExpression<'a>) -> Option<&'a str> {
    match &update.argument {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

/// Whether the expression is the boolean literal `true`.
fn is_constant_true(expression: Option<&Expression<'_>>) -> bool {
    match expression.map(unparenthesized) {
        Some(Expression::BooleanLiteral(literal)) => literal.value,
        _ => false,
    }
}

/// Whether the expression is the boolean literal `false`.
fn is_constant_false(expression: Option<&Expression<'_>>) -> bool {
    matches!(
        expression.map(unparenthesized),
        Some(Expression::BooleanLiteral(literal)) if !literal.value
    )
}

/// Whether `span`'s raw text contains `word` delimited by non-identifier
/// characters (used where the AST shape alone cannot tell which names an
/// arbitrary update expression references).
fn span_contains_word(source: &str, span: Span, word: &str) -> bool {
    let text = source_slice(source, span);
    let bytes = text.as_bytes();
    let mut search_from = 0;
    while let Some(offset) = text[search_from..].find(word) {
        let begin = search_from + offset;
        let end = begin + word.len();
        let before_ok = begin == 0 || !is_identifier_byte(bytes[begin - 1]);
        let after_ok = end == bytes.len() || !is_identifier_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        search_from = begin + 1;
    }
    false
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

impl<'a> LoopFlowCollector<'a, '_> {
    fn push_frame(&mut self) {
        self.frames.push(LoopFrame::default());
    }

    fn pop_frame(&mut self) -> LoopFrame {
        self.frames.pop().unwrap_or_default()
    }

    /// Whether any enclosing loop declares `name` as its counter.
    fn inside_counter_scope(&self, name: &str) -> bool {
        self.frames
            .iter()
            .any(|frame| frame.counters.iter().any(|counter| counter == name))
    }

    fn note_jump(&mut self, terminator: bool) {
        if let Some(frame) = self.frames.last_mut() {
            frame.jumps += 1;
            frame.terminators |= terminator;
        }
    }

    fn flag_many_jumps(&mut self, jumps: u32, span: Span) {
        if jumps > 1 {
            self.sink.emit_span(
                RuleScope::Both,
                "S135",
                "Reduce the number of break and continue statements in this loop to at most one.",
                span,
            );
        }
    }

    /// Loop-exit checks shared by counted loops (`for`, `while`, `do`).
    fn finish_loop(&mut self, span: Span, endless: bool) {
        let frame = self.pop_frame();
        self.flag_many_jumps(frame.jumps, span);
        if endless && !frame.terminators {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S2189",
                "Refactor this loop; it currently loops forever.",
                span,
            );
        }
    }

    /// Name of the counter declared by the loop's init clause (`let i = 0`).
    fn counter_name(it: &ForStatement<'a>) -> Option<String> {
        match it.init.as_ref()? {
            ForStatementInit::VariableDeclaration(declaration) => {
                let declarator = declaration.declarations.first()?;
                binding_identifier_name(&declarator.id).map(str::to_string)
            }
            _ => None,
        }
    }

    /// Operator relating the counter to a bound in the loop test.
    fn test_bound_operator(test: Option<&Expression<'_>>, counter: &str) -> Option<BinaryOperator> {
        let Expression::BinaryExpression(binary) = unparenthesized(test?) else {
            return None;
        };
        let involves_counter = identifier_name(&binary.left) == Some(counter)
            || identifier_name(&binary.right) == Some(counter);
        involves_counter.then_some(binary.operator)
    }

    /// `S2251`: the update moves the counter away from the tested bound.
    fn check_counter_direction(
        &mut self,
        it: &ForStatement<'a>,
        counter: &str,
        operator: BinaryOperator,
    ) {
        let Some(Expression::UpdateExpression(update)) = it.update.as_ref().map(unparenthesized)
        else {
            return;
        };
        if update_target_name(update) != Some(counter) {
            return;
        }
        let conflicts = if update.operator == UpdateOperator::Increment {
            operator == BinaryOperator::GreaterThan
        } else {
            operator == BinaryOperator::LessThan
        };
        if conflicts {
            self.sink.emit_span(
                RuleScope::Both,
                "S2251",
                "The loop counter moves away from the bound tested by this loop condition.",
                update.span(),
            );
        }
    }

    /// `S1994`: the update clause never mentions the declared counter.
    fn check_counter_updated(&mut self, it: &ForStatement<'a>, counter: &str) {
        if let Some(update) = &it.update
            && !span_contains_word(self.source, update.span(), counter)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S1994",
                "Modify the loop counter in the update clause or remove the clause.",
                update.span(),
            );
        }
    }

    /// `S1751` constant-false form.
    fn check_constant_test(&mut self, test: Option<&Expression<'_>>, span: Span) {
        if is_constant_false(test) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1751",
                "This loop runs at most once; replace it with a conditional statement.",
                span,
            );
        }
    }

    /// `S1751` terminal-break form: a block body whose last statement is a
    /// bare break, provided no continue anywhere in the body can loop back
    /// to another iteration.
    fn check_single_iteration_body(&mut self, body: &Statement<'a>) {
        let Statement::BlockStatement(block) = body else {
            return;
        };
        if !matches!(block.body.last(), Some(Statement::BreakStatement(_))) {
            return;
        }
        let mut scanner = ContinueScanner::default();
        scanner.visit_statement(body);
        if scanner.found {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S1751",
            "This loop runs at most once; replace it with a conditional statement.",
            body.span(),
        );
    }
}

impl<'a> Visit<'a> for LoopFlowCollector<'a, '_> {
    fn visit_break_statement(&mut self, _it: &BreakStatement) {
        self.note_jump(true);
    }

    fn visit_continue_statement(&mut self, _it: &ContinueStatement) {
        self.note_jump(false);
    }

    fn visit_return_statement(&mut self, _it: &ReturnStatement) {
        if let Some(frame) = self.frames.last_mut() {
            frame.terminators = true;
        }
    }

    fn visit_throw_statement(&mut self, _it: &ThrowStatement) {
        if let Some(frame) = self.frames.last_mut() {
            frame.terminators = true;
        }
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let guard = callee_name(it).is_some_and(|name| name == "hasOwnProperty")
            || call_property(it).is_some_and(|(property, _)| property == "hasOwnProperty");
        if guard && let Some(frame) = self.frames.last_mut() {
            frame.has_own_guard = true;
        }
        walk_call_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let Some(name) = assignment_target_name(&it.left)
            && self.inside_counter_scope(name)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2310",
                "Remove this assignment of the loop counter inside the loop body.",
                it.span(),
            );
        }
        walk_assignment_expression(self, it);
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        if let Some(name) = update_target_name(it)
            && self.inside_counter_scope(name)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2310",
                "Remove this modification of the loop counter inside the loop body.",
                it.span(),
            );
        }
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(test) = &it.test
            && let Expression::BinaryExpression(binary) = unparenthesized(test)
            && matches!(
                binary.operator,
                BinaryOperator::Equality | BinaryOperator::Inequality
            )
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S888",
                "Use a strict comparison in this loop condition.",
                test.span(),
            );
        }
        if it.init.is_none() && it.update.is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S1264",
                "This for loop lacks init and update clauses; use a while loop instead.",
                it.span(),
            );
        }
        let counter = Self::counter_name(it);
        if let Some(counter_name) = counter.as_deref() {
            if let Some(operator) = Self::test_bound_operator(it.test.as_ref(), counter_name) {
                self.check_counter_direction(it, counter_name, operator);
            }
            self.check_counter_updated(it, counter_name);
        }
        let endless = it.test.is_none();
        self.push_frame();
        if let Some(counter_name) = &counter
            && let Some(frame) = self.frames.last_mut()
        {
            frame.counters.push(counter_name.clone());
        }
        self.visit_statement(&it.body);
        self.finish_loop(it.span(), endless);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.check_constant_test(Some(&it.test), it.span());
        self.check_single_iteration_body(&it.body);
        let endless = is_constant_true(Some(&it.test));
        self.push_frame();
        walk_while_statement(self, it);
        self.finish_loop(it.span(), endless);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.check_constant_test(Some(&it.test), it.span());
        self.check_single_iteration_body(&it.body);
        let endless = is_constant_true(Some(&it.test));
        self.push_frame();
        walk_do_while_statement(self, it);
        self.finish_loop(it.span(), endless);
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        match unparenthesized(&it.right) {
            Expression::ArrayExpression(_) => self.sink.emit_span(
                RuleScope::Both,
                "S4139",
                "Do not use for-in to iterate over an array.",
                it.right.span(),
            ),
            Expression::StringLiteral(_) => self.sink.emit_span(
                RuleScope::Both,
                "S4139",
                "Do not use for-in to iterate over a string.",
                it.right.span(),
            ),
            _ => {}
        }
        self.push_frame();
        walk_for_in_statement(self, it);
        let frame = self.pop_frame();
        if !frame.has_own_guard {
            self.sink.emit_span(
                RuleScope::Both,
                "S1535",
                "Guard this for-in loop with a hasOwnProperty check.",
                it.span(),
            );
        }
        self.flag_many_jumps(frame.jumps, it.span());
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        match unparenthesized(&it.right) {
            Expression::NumericLiteral(_) => self.sink.emit_span(
                RuleScope::Both,
                "S4138",
                "Do not use for-of to iterate over a number.",
                it.right.span(),
            ),
            Expression::ObjectExpression(_) => self.sink.emit_span(
                RuleScope::Both,
                "S4138",
                "Do not use for-of to iterate over an object literal.",
                it.right.span(),
            ),
            _ => {}
        }
        self.push_frame();
        walk_for_of_statement(self, it);
        let frame = self.pop_frame();
        self.flag_many_jumps(frame.jumps, it.span());
    }
}

fn check_loop_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = LoopFlowCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        frames: Vec::new(),
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

// ===== Batch2a: name/format convention rules (S100 S101 S117 S109 S1192 S1441 S2430) =====

/// `S100` (function names), `S101` (class and interface names), `S117`
/// (variable, parameter, and property-key names), and `S2430` (lowercase
/// constructor callees). The first three compare against the catalog
/// `format` regular expressions.
struct NameFormatCollector<'a, 'index> {
    sink: IssueSink<'index>,
    rules: &'a RuleOptions,
}

impl<'a> Visit<'a> for NameFormatCollector<'a, '_> {
    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        match it {
            Declaration::FunctionDeclaration(function) => {
                self.check_function_name(function.id.as_ref());
            }
            Declaration::ClassDeclaration(class) => {
                self.check_type_name("class", class.id.as_ref());
            }
            Declaration::TSInterfaceDeclaration(interface) => {
                self.check_type_name("interface", Some(&interface.id));
            }
            _ => {}
        }
        walk_declaration(self, it);
    }

    fn visit_export_default_declaration_kind(&mut self, it: &ExportDefaultDeclarationKind<'a>) {
        match it {
            ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                self.check_function_name(function.id.as_ref());
            }
            ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                self.check_type_name("class", class.id.as_ref());
            }
            _ => {}
        }
        walk_export_default_declaration_kind(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        match it {
            Expression::FunctionExpression(function) => {
                self.check_function_name(function.id.as_ref());
            }
            Expression::ClassExpression(class) => {
                self.check_type_name("class", class.id.as_ref());
            }
            _ => {}
        }
        walk_expression(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if !matches!(it.kind, MethodDefinitionKind::Constructor)
            && let Some(name) = property_key_name(&it.key)
        {
            self.check_name(
                "S100",
                "function",
                name,
                it.key.span(),
                &self.rules.format_functions,
            );
        }
        walk_method_definition(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(name) = binding_identifier_name(&it.id) {
            self.check_name(
                "S117",
                "variable",
                name,
                it.id.span(),
                &self.rules.format_variables,
            );
        }
        walk_variable_declarator(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        if let Some(name) = binding_identifier_name(&it.pattern) {
            self.check_name(
                "S117",
                "parameter",
                name,
                it.pattern.span(),
                &self.rules.format_variables,
            );
        }
        walk_formal_parameter(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        if !it.computed
            && let Some(name) = property_key_name(&it.key)
        {
            self.check_name(
                "S117",
                "property",
                name,
                it.key.span(),
                &self.rules.format_variables,
            );
        }
        walk_object_property(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if let Some(name) = constructor_name(it)
            && name.starts_with(|first: char| first.is_ascii_lowercase())
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2430",
                "Rename this constructor to start with an uppercase letter.",
                it.callee.span(),
            );
        }
        walk_new_expression(self, it);
    }

    fn visit_jsx_attribute(&mut self, _it: &JSXAttribute<'a>) {
        // JSX attribute names/values are exempt from naming checks.
    }
}

impl NameFormatCollector<'_, '_> {
    fn check_function_name(&mut self, id: Option<&BindingIdentifier<'_>>) {
        let Some(id) = id else {
            return;
        };
        self.check_name(
            "S100",
            "function",
            &id.name,
            id.span,
            &self.rules.format_functions,
        );
    }

    fn check_type_name(&mut self, kind: &str, id: Option<&BindingIdentifier<'_>>) {
        let Some(id) = id else {
            return;
        };
        self.check_name("S101", kind, &id.name, id.span, &self.rules.format_classes);
    }

    fn check_name(&mut self, rule: &str, kind: &str, name: &str, span: Span, format: &str) {
        if !regex_search(format, name) {
            self.sink.emit_span(
                RuleScope::Both,
                rule,
                &format!("Rename this {kind} to match the regular expression '{format}'."),
                span,
            );
        }
    }
}

/// `S109`: numeric literals outside the catalog-allowed contexts — const
/// initializers, computed array indexes, and `-1..=2` parameter defaults.
struct MagicNumberCollector<'index> {
    sink: IssueSink<'index>,
    const_initializer_depth: u32,
    index_depth: u32,
    default_depth: u32,
    negation_depth: u32,
}

impl<'a> Visit<'a> for MagicNumberCollector<'_> {
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        let in_const = matches!(it.kind, VariableDeclarationKind::Const);
        self.const_initializer_depth += u32::from(in_const);
        walk_variable_declaration(self, it);
        self.const_initializer_depth -= u32::from(in_const);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if let MemberExpression::ComputedMemberExpression(member) = it {
            walk_expression(self, &member.object);
            self.index_depth += 1;
            walk_expression(self, &member.expression);
            self.index_depth -= 1;
        } else {
            walk_member_expression(self, it);
        }
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        walk_binding_pattern(self, &it.pattern);
        if let Some(initializer) = &it.initializer {
            self.default_depth += 1;
            walk_expression(self, initializer);
            self.default_depth -= 1;
        }
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        let negated = matches!(it.operator, UnaryOperator::UnaryNegation);
        self.negation_depth += u32::from(negated);
        walk_unary_expression(self, it);
        self.negation_depth -= u32::from(negated);
    }

    fn visit_numeric_literal(&mut self, it: &NumericLiteral<'a>) {
        let value = if self.negation_depth % 2 == 1 {
            -it.value
        } else {
            it.value
        };
        let allowed = self.const_initializer_depth > 0
            || self.index_depth > 0
            || (self.default_depth > 0 && (-2.0..=2.0).contains(&value));
        if !allowed {
            self.sink.emit_span(
                RuleScope::Both,
                "S109",
                "This numeric literal should be replaced by a named constant.",
                it.span,
            );
        }
    }

    fn visit_jsx_attribute(&mut self, _it: &JSXAttribute<'a>) {
        // Numeric JSX attribute values are exempt from magic-number checks.
    }
}

/// `S1441` (quote style per `singleQuotes`) and `S1192` (duplicated string
/// literals, aggregated after the traversal).
struct StringStyleCollector<'index> {
    sink: IssueSink<'index>,
    single_quotes: bool,
    duplicate_threshold: usize,
    ignored_strings: Vec<String>,
    string_occurrences: Vec<(String, Span)>,
}

impl<'a> Visit<'a> for StringStyleCollector<'_> {
    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        self.check_quote_style(it);
        self.record_occurrence(it);
    }

    fn visit_jsx_attribute(&mut self, _it: &JSXAttribute<'a>) {
        // JSX attribute strings are exempt from quote-style and
        // duplication checks.
    }
}

impl StringStyleCollector<'_> {
    fn check_quote_style(&mut self, literal: &StringLiteral<'_>) {
        let Some(raw) = literal.raw.as_ref().map(oxc_ast::ast::Str::as_str) else {
            return;
        };
        let Some(delimiter) = raw.chars().next() else {
            return;
        };
        let disallowed = if self.single_quotes { '"' } else { '\'' };
        if delimiter != disallowed || escapes_delimiter(raw, delimiter) {
            return;
        }
        let preferred = if self.single_quotes {
            "single"
        } else {
            "double"
        };
        self.sink.emit_span(
            RuleScope::Both,
            "S1441",
            &format!("Use {preferred} quotes for this string literal."),
            literal.span,
        );
    }

    fn record_occurrence(&mut self, literal: &StringLiteral<'_>) {
        let value = literal.value.as_str();
        if value.chars().count() < 2 || self.ignored_strings.iter().any(|word| word == value) {
            return;
        }
        self.string_occurrences
            .push((value.to_string(), literal.span));
    }

    /// One `S1192` issue per over-duplicated value, anchored at the first
    /// occurrence.
    fn report_duplicates(&mut self) {
        let mut groups: Vec<(String, Vec<Span>)> = Vec::new();
        for (value, span) in &self.string_occurrences {
            match groups.iter_mut().find(|(known, _)| known == value) {
                Some((_, spans)) => spans.push(*span),
                None => groups.push((value.clone(), vec![*span])),
            }
        }
        for (value, spans) in groups {
            if spans.len() >= self.duplicate_threshold {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1192",
                    &format!(
                        "Define a constant instead of duplicating this literal \
                         \"{value}\" {} times.",
                        spans.len()
                    ),
                    spans[0],
                );
            }
        }
    }
}

/// Whether `raw` contains a backslash escaping `delimiter`, which makes a
/// quote-style switch unsafe (`S1441` tolerance).
fn escapes_delimiter(raw: &str, delimiter: char) -> bool {
    let mut chars = raw.chars();
    while let Some(current) = chars.next() {
        if current == '\\' && chars.next() == Some(delimiter) {
            return true;
        }
    }
    false
}

fn check_naming_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    let mut names = NameFormatCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        rules,
    };
    names.visit_program(program);
    let mut magic = MagicNumberCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        const_initializer_depth: 0,
        index_depth: 0,
        default_depth: 0,
        negation_depth: 0,
    };
    magic.visit_program(program);
    let mut strings = StringStyleCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        single_quotes: rules.single_quotes,
        duplicate_threshold: rules.duplicate_string_threshold,
        ignored_strings: rules.ignored_strings.clone(),
        string_occurrences: Vec::new(),
    };
    strings.visit_program(program);
    strings.report_duplicates();
    let mut issues = names.sink.issues;
    issues.extend(magic.sink.issues);
    issues.extend(strings.sink.issues);
    issues
}

// ===== Batch2a: structural duplicate/identity checks (S1764 S1871 S3923 S1862 S4144 S3516) =====

/// `S1764` (identical binary operands), `S1871`/`S3923`/`S1862` (duplicated
/// branches and conditions), and `S3516` (invariant literal returns),
/// collected in one traversal; `S4144` (identical function bodies) is
/// resolved afterwards through span-free subtree equality (`ContentEq`).
struct DuplicateCollector<'a, 'index> {
    sink: IssueSink<'index>,
    if_statements: Vec<&'a IfStatement<'a>>,
    function_bodies: Vec<&'a FunctionBody<'a>>,
    return_groups: Vec<Vec<&'a ReturnStatement<'a>>>,
    current_return_group: Option<usize>,
    group_stack: Vec<Option<usize>>,
}

impl<'a> Visit<'a> for DuplicateCollector<'a, '_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        match kind {
            AstKind::IfStatement(statement) => self.if_statements.push(statement),
            AstKind::BinaryExpression(expression) => {
                if expression.left.content_eq(&expression.right) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S1764",
                        "Identical sub-expressions on both sides of this operator.",
                        expression.span,
                    );
                }
            }
            AstKind::ConditionalExpression(expression) => {
                if expression.consequent.content_eq(&expression.alternate) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3923",
                        "Either remove this branch or refactor the code to avoid duplication.",
                        expression.span,
                    );
                }
            }
            AstKind::SwitchStatement(statement) => self.check_switch_cases(statement),
            AstKind::FunctionBody(body) => {
                let group = self.return_groups.len();
                self.return_groups.push(Vec::new());
                self.function_bodies.push(body);
                self.group_stack.push(self.current_return_group);
                self.current_return_group = Some(group);
            }
            AstKind::ReturnStatement(statement) => {
                if let Some(group) = self.current_return_group {
                    self.return_groups[group].push(statement);
                }
            }
            _ => {}
        }
    }

    fn leave_node(&mut self, kind: AstKind<'a>) {
        if matches!(kind, AstKind::FunctionBody(_)) {
            self.current_return_group = self.group_stack.pop().flatten();
        }
    }
}

impl<'a> DuplicateCollector<'a, '_> {
    fn check_switch_cases(&mut self, it: &SwitchStatement<'a>) {
        let cases = &it.cases;
        if cases.len() < 2 {
            return;
        }
        // `S1862`: a case test duplicating an earlier one.
        for (position, case) in cases.iter().enumerate().skip(1) {
            let Some(test) = &case.test else {
                continue;
            };
            let duplicated = cases[..position].iter().any(|earlier| {
                earlier
                    .test
                    .as_ref()
                    .is_some_and(|previous| test.content_eq(previous))
            });
            if duplicated {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1862",
                    "This case duplicates an earlier case; merge the clauses.",
                    test.span(),
                );
            }
        }
        // `S1871`: consecutive cases with identical bodies (fallthrough
        // placeholders without statements do not count).
        for pair in cases.windows(2) {
            if let Some(first) = pair[1].consequent.first()
                && statements_equal(&pair[0].consequent, &pair[1].consequent)
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1871",
                    "This branch's code is identical to the previous branch's.",
                    first.span(),
                );
            }
        }
        // `S3923`: every case carrying the same non-empty body.
        let all_populated = cases.iter().all(|case| !case.consequent.is_empty());
        let all_identical = cases.first().is_some_and(|first| {
            cases
                .iter()
                .all(|case| statements_equal(&first.consequent, &case.consequent))
        });
        if all_populated && all_identical {
            self.sink.emit_span(
                RuleScope::Both,
                "S3923",
                "Either remove this branch or refactor the code to avoid duplication.",
                it.span,
            );
        }
    }

    /// Resolves the deferred if-chain rules once every `IfStatement` has
    /// been collected; chains are processed from their heads only so no
    /// link is reported twice.
    fn check_if_chains(&mut self) {
        let statements = std::mem::take(&mut self.if_statements);
        let chained_starts: BTreeSet<u32> = statements
            .iter()
            .filter_map(|statement| match statement.alternate.as_ref() {
                Some(Statement::IfStatement(next)) => Some(next.span.start),
                _ => None,
            })
            .collect();
        for head in statements {
            if !chained_starts.contains(&head.span.start) {
                self.check_single_chain(head);
            }
        }
    }
    fn check_single_chain(&mut self, head: &'a IfStatement<'a>) {
        // `S1871`: any link whose own branches are structurally equal.
        let mut current = head;
        loop {
            if let Some(alternate) = current.alternate.as_ref()
                && current.consequent.content_eq(alternate)
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1871",
                    "This branch's code is identical to the previous branch's.",
                    alternate.span(),
                );
            }
            match current.alternate.as_ref() {
                Some(Statement::IfStatement(next)) => current = next,
                _ => break,
            }
        }
        let mut tests: Vec<&Expression<'a>> = vec![&head.test];
        let mut branches: Vec<&Statement<'a>> = vec![&head.consequent];
        current = head;
        while let Some(alternate) = current.alternate.as_ref() {
            match alternate {
                Statement::IfStatement(next) => {
                    tests.push(&next.test);
                    branches.push(&next.consequent);
                    current = next;
                }
                other => {
                    branches.push(other);
                    break;
                }
            }
        }
        // `S1862`: repeated conditions within the same chain.
        for (position, test) in tests.iter().enumerate().skip(1) {
            if tests[..position]
                .iter()
                .any(|earlier| test.content_eq(earlier))
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1862",
                    "This condition duplicates an earlier condition in the same chain; \
                     merge the branches.",
                    test.span(),
                );
            }
        }
        // `S3923`: every branch carrying the same non-empty code.
        let all_identical = branches.windows(2).all(|pair| pair[0].content_eq(pair[1]));
        let all_populated = branches.iter().all(|branch| !is_empty_block(branch));
        if branches.len() >= 2 && all_identical && all_populated {
            self.sink.emit_span(
                RuleScope::Both,
                "S3923",
                "Either remove this branch or refactor the code to avoid duplication.",
                head.span,
            );
        }
    }

    /// `S4144`: function bodies identical to an earlier body in the same
    /// file; single-line bodies count as trivial and are skipped.
    fn check_similar_functions(&mut self) {
        let bodies = std::mem::take(&mut self.function_bodies);
        for (position, body) in bodies.iter().enumerate() {
            if !self.spans_multiple_lines(body.span) {
                continue;
            }
            let matches_earlier = bodies[..position]
                .iter()
                .any(|other| self.spans_multiple_lines(other.span) && other.content_eq(body));
            if matches_earlier {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4144",
                    "This function body is identical to another function's body; \
                     factor it out into a shared function.",
                    body.span,
                );
            }
        }
    }

    /// `S3516`: functions whose returns all yield the same literal.
    fn check_invariant_returns(&mut self) {
        let groups = std::mem::take(&mut self.return_groups);
        for returns in groups {
            let Some(second) = returns.get(1) else {
                continue;
            };
            let all_literals = returns.iter().all(|statement| {
                statement
                    .argument
                    .as_ref()
                    .is_some_and(is_literal_expression)
            });
            if !all_literals {
                continue;
            }
            let Some(baseline) = returns[0].argument.as_ref() else {
                continue;
            };
            let invariant = returns[1..].iter().all(|statement| {
                statement
                    .argument
                    .as_ref()
                    .is_some_and(|argument| argument.content_eq(baseline))
            });
            if invariant {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3516",
                    "All return statements of this function return the same value; \
                     simplify them.",
                    second.span(),
                );
            }
        }
    }

    fn spans_multiple_lines(&self, span: Span) -> bool {
        let start = self.sink.index.pos(span.start).line;
        let end = self.sink.index.pos(span.end).line;
        start != end
    }
}

fn check_duplicate_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = DuplicateCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        if_statements: Vec::new(),
        function_bodies: Vec::new(),
        return_groups: Vec::new(),
        current_return_group: None,
        group_stack: Vec::new(),
    };
    collector.visit_program(program);
    collector.check_if_chains();
    collector.check_similar_functions();
    collector.check_invariant_returns();
    collector.sink.issues
}

/// Elementwise span-free equality of two statement lists.
fn statements_equal(left: &[Statement<'_>], right: &[Statement<'_>]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left_item, right_item)| left_item.content_eq(right_item))
}

fn is_empty_block(statement: &Statement<'_>) -> bool {
    matches!(statement, Statement::BlockStatement(block) if block.body.is_empty())
}

fn is_literal_expression(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::BigIntLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::RegExpLiteral(_)
            | Expression::StringLiteral(_)
    )
}

// ===== Batch2c group A: statement-shape and control-flow walks =====
//
// `S107` (too many parameters), `S134` (control-flow nesting), `S881`
// (standalone update expressions), `S905` (pointless expression statements),
// `S1105` (1tbs opening-brace placement), `S1121` (embedded assignments),
// and `S1143` (jumps out of `finally` blocks).

use oxc_ast::ast::{CatchClause, ClassBody, FormalParameters, TryStatement};
use oxc_ast_visit::walk::{walk_catch_clause, walk_class_body};

/// `S107`: functions carrying more parameters than this are flagged (frozen
/// catalog default of `maximumFunctionParameters`).
const MAX_FUNCTION_PARAMETERS: usize = 7;

/// `S134`: control-flow statements nested deeper than this are flagged
/// (frozen catalog default of `maximumNestingLevel`).
const MAX_CONTROL_FLOW_NESTING: u32 = 3;

/// `S107`, `S134`, and `S1143` in one traversal. Tracks control-flow nesting
/// depth and `finally` membership, both reset at every function boundary.
struct ControlFlowNestingCollector<'index> {
    sink: IssueSink<'index>,
    /// Number of control-flow constructs enclosing the current node (`S134`).
    flow_depth: u32,
    /// > 0 while walking inside a `finally` clause (`S1143`).
    finally_depth: u32,
}

impl ControlFlowNestingCollector<'_> {
    fn check_parameter_count(&mut self, params: &FormalParameters<'_>) {
        let count = params.items.len() + usize::from(params.rest.is_some());
        if count > MAX_FUNCTION_PARAMETERS {
            self.sink.emit_span(
                RuleScope::Both,
                "S107",
                &format!(
                    "This function has {count} parameters, which is greater \
                     than the {MAX_FUNCTION_PARAMETERS} authorized."
                ),
                params.span(),
            );
        }
    }

    /// Zeroes the per-function state; returns the saved values for
    /// [`Self::leave_function`].
    fn enter_function(&mut self) -> (u32, u32) {
        let saved = (self.flow_depth, self.finally_depth);
        self.flow_depth = 0;
        self.finally_depth = 0;
        saved
    }

    fn leave_function(&mut self, saved: (u32, u32)) {
        self.flow_depth = saved.0;
        self.finally_depth = saved.1;
    }

    /// `S134`: flags a construct entered while already `MAX` deep, i.e. one
    /// whose own nesting level exceeds `MAX_CONTROL_FLOW_NESTING`.
    fn check_nesting(&mut self, span: Span) {
        if self.flow_depth >= MAX_CONTROL_FLOW_NESTING {
            self.sink.emit_span(
                RuleScope::Both,
                "S134",
                &format!(
                    "Refactor this code to not nest more than \
                     {MAX_CONTROL_FLOW_NESTING} control flow statements."
                ),
                span,
            );
        }
    }

    fn check_finally_jump(&mut self, span: Span) {
        if self.finally_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1143",
                "Remove this jump statement from this finally block.",
                span,
            );
        }
    }

    /// Counts parameters and resets nesting around one whole function-like
    /// subtree.
    fn function_scope(
        &mut self,
        params: Option<&FormalParameters<'_>>,
        walk_children: impl FnOnce(&mut Self),
    ) {
        if let Some(params) = params {
            self.check_parameter_count(params);
        }
        let saved = self.enter_function();
        walk_children(self);
        self.leave_function(saved);
    }
}

impl<'a> Visit<'a> for ControlFlowNestingCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            self.function_scope(Some(&function.params), |collector| {
                walk_expression(collector, it);
            });
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.function_scope(Some(&it.params), |collector| {
            walk_arrow_function_expression(collector, it);
        });
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.function_scope(Some(&it.value.params), |collector| {
            walk_method_definition(collector, it);
        });
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.function_scope(None, |collector| {
            walk_static_block(collector, it);
        });
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            self.function_scope(Some(&function.params), |collector| {
                walk_declaration(collector, it);
            });
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_export_default_declaration_kind(&mut self, it: &ExportDefaultDeclarationKind<'a>) {
        if let ExportDefaultDeclarationKind::FunctionDeclaration(function) = it {
            self.function_scope(Some(&function.params), |collector| {
                walk_export_default_declaration_kind(collector, it);
            });
        } else {
            walk_export_default_declaration_kind(self, it);
        }
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_if_statement(collector, it));
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.nested_flow(it.span(), |collector| {
            if let Some(init) = &it.init {
                collector.visit_for_statement_init(init);
            }
            if let Some(test) = &it.test {
                collector.visit_expression(test);
            }
            if let Some(update) = &it.update {
                collector.visit_expression(update);
            }
            collector.visit_statement(&it.body);
        });
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_for_in_statement(collector, it));
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_for_of_statement(collector, it));
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_while_statement(collector, it));
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.nested_flow(it.span(), |collector| {
            walk_do_while_statement(collector, it);
        });
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_switch_statement(collector, it));
    }

    fn visit_catch_clause(&mut self, it: &CatchClause<'_>) {
        self.nested_flow(it.span(), |collector| walk_catch_clause(collector, it));
    }

    /// `S1143` handling: the `try` header itself nests like other
    /// constructs, while the optional `finally` additionally enables jump
    /// detection for its subtree.
    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        self.check_nesting(it.span());
        self.flow_depth += 1;
        self.visit_block_statement(&it.block);
        if let Some(handler) = &it.handler {
            self.visit_catch_clause(handler);
        }
        self.flow_depth -= 1;
        if let Some(finalizer) = &it.finalizer {
            self.finally_depth += 1;
            self.visit_block_statement(finalizer);
            self.finally_depth -= 1;
        }
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        self.check_finally_jump(it.span());
        walk_return_statement(self, it);
    }

    fn visit_throw_statement(&mut self, it: &ThrowStatement<'a>) {
        self.check_finally_jump(it.span());
        walk_throw_statement(self, it);
    }

    fn visit_break_statement(&mut self, it: &BreakStatement<'a>) {
        self.check_finally_jump(it.span());
    }

    fn visit_continue_statement(&mut self, it: &ContinueStatement<'a>) {
        self.check_finally_jump(it.span());
    }
}

impl ControlFlowNestingCollector<'_> {
    fn nested_flow(&mut self, span: Span, walk_children: impl FnOnce(&mut Self)) {
        self.check_nesting(span);
        self.flow_depth += 1;
        walk_children(self);
        self.flow_depth -= 1;
    }
}

fn check_flow_nesting_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ControlFlowNestingCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        flow_depth: 0,
        finally_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S881` (standalone `++`/`--`), `S1121` (standalone assignments), and
/// `S905` (pointless expression statements) in one traversal.
///
/// Updates and assignments are only tolerated as the direct root expression
/// of an `ExpressionStatement` or in a `for` header init/update slot; the
/// `expr_depth` counter distinguishes those roots from deeper embedding.
struct EmbeddedEffectCollector<'index> {
    sink: IssueSink<'index>,
    /// Distance of the current expression below its statement root: `1` for
    /// the root itself, increasing per nesting level, `0` outside
    /// statement-root contexts (initializers, conditions, arguments, ...).
    expr_depth: u32,
}

impl<'a> Visit<'a> for EmbeddedEffectCollector<'_> {
    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        if is_pointless_expression(&it.expression) {
            self.sink.emit_span(
                RuleScope::Both,
                "S905",
                "Remove this expression; it has no effect.",
                it.expression.span(),
            );
        }
        let saved = self.expr_depth;
        self.expr_depth = 1;
        walk_expression_statement(self, it);
        self.expr_depth = saved;
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(init) = &it.init {
            // Only the expression form of the init slot is an embedded
            // statement root; `for (let i = ...)` declarations walk with
            // their own (non-root) initializer context.
            if init.as_expression().is_some() {
                let saved = self.expr_depth;
                self.expr_depth = 1;
                self.visit_for_statement_init(init);
                self.expr_depth = saved;
            } else {
                self.visit_for_statement_init(init);
            }
        }
        if let Some(test) = &it.test {
            self.visit_expression(test);
        }
        if let Some(update) = &it.update {
            let saved = self.expr_depth;
            self.expr_depth = 1;
            self.visit_expression(update);
            self.expr_depth = saved;
        }
        self.visit_statement(&it.body);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        match it {
            Expression::UpdateExpression(update) => {
                if self.expr_depth != 1 {
                    let operator = match update.operator {
                        UpdateOperator::Increment => "++",
                        UpdateOperator::Decrement => "--",
                    };
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S881",
                        &format!("Remove this use of the operator '{operator}'."),
                        update.span(),
                    );
                }
            }
            Expression::AssignmentExpression(assign) if self.expr_depth != 1 => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1121",
                    "Extract this assignment out of this expression.",
                    assign.span(),
                );
            }
            _ => {}
        }
        if self.expr_depth > 0 {
            self.expr_depth += 1;
            walk_expression(self, it);
            self.expr_depth -= 1;
        } else {
            walk_expression(self, it);
        }
    }
}

/// Whether an expression statement provably has no effect: literals,
/// identifiers, templates without substitutions, and pure operators over
/// such operands. Calls, assignments, `delete`, tagged templates, and any
/// unrecognized shape are treated as effectful.
fn is_pointless_expression(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::Identifier(_)
        | Expression::ThisExpression(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::ParenthesizedExpression(parens) => is_pointless_expression(&parens.expression),
        Expression::UnaryExpression(unary) => {
            unary.operator != UnaryOperator::Delete && is_pointless_expression(&unary.argument)
        }
        Expression::BinaryExpression(binary) => {
            is_pointless_expression(&binary.left) && is_pointless_expression(&binary.right)
        }
        Expression::LogicalExpression(logical) => {
            is_pointless_expression(&logical.left) && is_pointless_expression(&logical.right)
        }
        Expression::SequenceExpression(sequence) => sequence
            .expressions
            .iter()
            .all(|expression| is_pointless_expression(expression)),
        _ => false,
    }
}

fn check_embedded_effects(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = EmbeddedEffectCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        expr_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Byte offset of the last character before `offset` that is neither
/// whitespace nor part of a comment; `None` when only trivia precedes.
/// `//` comment lines and `/* … */` comments are skipped in full so the scan
/// lands on the token before the trivia run.
fn previous_non_trivia_offset(source: &str, offset: u32) -> Option<u32> {
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
fn line_start(bytes: &[u8], newline_index: usize) -> usize {
    let mut j = newline_index;
    while j > 0 && bytes[j - 1] != b'\n' {
        j -= 1;
    }
    j
}

/// Whether the line ending at `newline_index` carries nothing but a `//`
/// comment (leading whitespace allowed).
fn line_is_comment_only(bytes: &[u8], newline_index: usize) -> bool {
    let start = line_start(bytes, newline_index);
    let mut k = start;
    while k < newline_index && (bytes[k] == b' ' || bytes[k] == b'\t') {
        k += 1;
    }
    k + 1 < bytes.len() && bytes[k] == b'/' && bytes[k + 1] == b'/'
}

/// First non-trivia byte offset at or after `start`, skipping whitespace and
/// comments; `None` at end of input.
fn next_non_trivia_offset(source: &str, start: usize) -> Option<usize> {
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

/// `S1105` (1tbs opening-brace placement) over block bodies, function
/// bodies, class bodies, and switch headers.
struct BraceStyleCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
}

impl BraceStyleCollector<'_, '_> {
    /// Flags `brace_offset` (the `{`) when the nearest preceding token ends
    /// on an earlier line.
    fn check_opening_brace(&mut self, brace_offset: u32) {
        let Some(previous) = previous_non_trivia_offset(self.source, brace_offset) else {
            return;
        };
        let brace_line = self.sink.index.pos(brace_offset).line;
        let previous_line = self.sink.index.pos(previous).line;
        if previous_line != brace_line {
            self.sink.emit_span(
                RuleScope::Both,
                "S1105",
                "Move the opening curly brace to the end of the previous line.",
                Span::new(brace_offset, brace_offset.saturating_add(1)),
            );
        }
    }

    /// The switch header's `{`: the first non-trivia byte after the
    /// discriminant, skipping the header's closing parenthesis group(s)
    /// (`switch (x)`, `switch ((x))`) — nothing else may sit between them.
    fn switch_opening_brace_offset(&self, it: &SwitchStatement<'_>) -> Option<u32> {
        let bytes = self.source.as_bytes();
        let mut i = usize::try_from(it.discriminant.span().end)
            .ok()?
            .min(bytes.len());
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b')') {
            i += 1;
        }
        let offset = next_non_trivia_offset(self.source, i)?;
        (bytes.get(offset) == Some(&b'{')).then_some(to_u32(offset))
    }
}
impl<'a> Visit<'a> for BraceStyleCollector<'a, '_> {
    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.check_opening_brace(it.span.start);
        walk_block_statement(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.check_opening_brace(it.span.start);
        walk_function_body(self, it);
    }

    fn visit_class_body(&mut self, it: &ClassBody<'a>) {
        self.check_opening_brace(it.span.start);
        walk_class_body(self, it);
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        if let Some(offset) = self.switch_opening_brace_offset(it) {
            self.check_opening_brace(offset);
        }
        walk_switch_statement(self, it);
    }
}

fn check_brace_style(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = BraceStyleCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
    };
    collector.visit_program(program);
    collector.sink.issues
}

// ===== Batch2c group B: labels, statement sequences, function context =====
//
// `S1219` (labels on switch clauses), `S1439` (labels on non-loops),
// `S1472` (call arguments split across lines), `S1488`
// (declare-then-return/throw), `S1515` (functions created in loops),
// `S1530` (function declarations in nested blocks), `S1656`
// (self-assignments), `S1763` (unreachable statements), `S1788` (default
// parameter before a regular one), and `S2004` (function nesting depth).

use oxc_ast::ast::ForStatementLeft;
use oxc_ast_visit::walk::walk_program;

/// `S2004`: functions nested deeper than this many levels are flagged
/// (frozen catalog default of `max`).
const MAX_FUNCTION_NESTING: u32 = 4;

/// Whether the labeled statement body is a loop or a switch (`S1439`
/// tolerance set).
fn label_target_is_loop_or_switch(statement: &Statement<'_>) -> bool {
    matches!(
        statement,
        Statement::WhileStatement(_)
            | Statement::DoWhileStatement(_)
            | Statement::ForStatement(_)
            | Statement::ForInStatement(_)
            | Statement::ForOfStatement(_)
            | Statement::SwitchStatement(_)
    )
}

/// `S1219` and `S1439` in one traversal.
struct LabelUsageCollector<'index> {
    sink: IssueSink<'index>,
    /// > 0 while walking inside a switch clause (`S1219`).
    switch_case_depth: u32,
}

impl<'a> Visit<'a> for LabelUsageCollector<'_> {
    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        self.switch_case_depth += 1;
        walk_switch_case(self, it);
        self.switch_case_depth -= 1;
    }

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        if self.switch_case_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1219",
                "Remove this unnecessary label.",
                it.label.span(),
            );
        }
        if !label_target_is_loop_or_switch(&it.body) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1439",
                "Only loops and switch statements should be labeled.",
                it.label.span(),
            );
        }
        walk_labeled_statement(self, it);
    }
}

fn check_label_usage(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = LabelUsageCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        switch_case_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Scans one statement list for `S1763` (the first statement after an
/// unconditional jump is unreachable) and `S1488` (a sole variable declarator
/// immediately returned or thrown under its own name).
fn scan_statement_sequence(sink: &mut IssueSink<'_>, statements: &[Statement<'_>]) {
    let mut jumped = false;
    for statement in statements {
        if jumped {
            sink.emit_span(
                RuleScope::Both,
                "S1763",
                "Remove this unreachable code.",
                statement.span(),
            );
            break;
        }
        jumped = statement_ends_with_jump(statement);
    }

    for pair in statements.windows(2) {
        let Some(Declaration::VariableDeclaration(variables)) = pair[0].as_declaration() else {
            continue;
        };
        if variables.declarations.len() != 1 || variables.declarations[0].init.is_none() {
            continue;
        }
        let declarator = &variables.declarations[0];
        let Some(name) = binding_identifier_name(&declarator.id) else {
            continue;
        };
        let message = match &pair[1] {
            Statement::ReturnStatement(returned) => {
                let returned_name = returned.argument.as_ref().and_then(identifier_name);
                (returned_name == Some(name)).then(|| {
                    format!(
                        "Immediately return this expression instead of assigning it to '{name}'."
                    )
                })
            }
            Statement::ThrowStatement(thrown) => (identifier_name(&thrown.argument) == Some(name))
                .then(|| {
                    format!(
                        "Immediately throw this expression instead of assigning it to '{name}'."
                    )
                }),
            _ => None,
        };
        if let Some(message) = message {
            sink.emit_span(RuleScope::Both, "S1488", &message, declarator.span());
        }
    }
}

/// `S1488` and `S1763` over program bodies, block bodies, and function
/// bodies.
struct StatementSequenceCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for StatementSequenceCollector<'_> {
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        scan_statement_sequence(&mut self.sink, &it.body);
        walk_program(self, it);
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        scan_statement_sequence(&mut self.sink, &it.body);
        walk_block_statement(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        scan_statement_sequence(&mut self.sink, &it.statements);
        walk_function_body(self, it);
    }
}

fn check_statement_sequences(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = StatementSequenceCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Whether the parameter carries a default value (`= expr`) or a
/// destructuring default at its top level.
fn param_has_default(item: &FormalParameter<'_>) -> bool {
    item.initializer.is_some() || matches!(item.pattern, BindingPattern::AssignmentPattern(_))
}

/// `S1515` (functions created inside loop bodies), `S1530` (function
/// declarations placed in nested blocks), `S1788` (default parameter before
/// a regular one), and `S2004` (function nesting beyond
/// [`MAX_FUNCTION_NESTING`] levels) in one traversal.
struct FunctionContextCollector<'index> {
    sink: IssueSink<'index>,
    /// Depth of `BlockStatement`s below the nearest function or program
    /// root (`S1530`); reset per function.
    block_depth: u32,
    /// > 0 while walking inside a loop *body* (`S1515`); reset per function.
    loop_body_depth: u32,
    /// Number of enclosing functions (`S2004`).
    function_depth: u32,
}

impl FunctionContextCollector<'_> {
    fn check_parameter_order(&mut self, params: &FormalParameters<'_>) {
        let mut defaulted = false;
        for item in &params.items {
            if param_has_default(item) {
                defaulted = true;
            } else if defaulted {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1788",
                    "Move this default parameter after the other parameters.",
                    item.span(),
                );
            }
        }
    }

    /// Walks the shared `for-in`/`for-of` header left side: either a target
    /// declaration or an assignment/expression target.
    fn visit_for_header_left(&mut self, left: &ForStatementLeft<'_>) {
        match left {
            ForStatementLeft::VariableDeclaration(declaration) => {
                self.visit_variable_declaration(declaration);
            }
            other => {
                if let Some(target) = other.as_assignment_target() {
                    self.visit_assignment_target(target);
                }
            }
        }
    }

    /// Shared entry for every function-like node: flags creation context
    /// (`S1515`, `S2004`), checks parameter order (`S1788`), then resets
    /// block/loop state for the subtree.
    fn enter_function(
        &mut self,
        span: Span,
        params: Option<&FormalParameters<'_>>,
        walk_children: impl FnOnce(&mut Self),
    ) {
        if self.function_depth >= MAX_FUNCTION_NESTING {
            self.sink.emit_span(
                RuleScope::Both,
                "S2004",
                &format!(
                    "Refactor this code to not nest functions more than \
                     {MAX_FUNCTION_NESTING} levels deep."
                ),
                span,
            );
        }
        if self.loop_body_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1515",
                "Functions should not be created within loops.",
                span,
            );
        }
        if let Some(params) = params {
            self.check_parameter_order(params);
        }

        let saved_block = self.block_depth;
        let saved_loop = self.loop_body_depth;
        let saved_function = self.function_depth;
        self.block_depth = 0;
        self.loop_body_depth = 0;
        self.function_depth += 1;
        walk_children(self);
        self.function_depth = saved_function;
        self.block_depth = saved_block;
        self.loop_body_depth = saved_loop;
    }
}

impl<'a> Visit<'a> for FunctionContextCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            self.enter_function(function.span(), Some(&function.params), |collector| {
                walk_expression(collector, it);
            });
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.enter_function(it.span(), Some(&it.params), |collector| {
            walk_arrow_function_expression(collector, it);
        });
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.enter_function(it.span(), Some(&it.value.params), |collector| {
            walk_method_definition(collector, it);
        });
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.enter_function(it.span(), None, |collector| {
            walk_static_block(collector, it);
        });
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            // Flag before entering: the *enclosing* block decides `S1530`.
            if self.block_depth > 0 {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1530",
                    "Function declarations should not be placed in blocks.",
                    function.span(),
                );
            }
            self.enter_function(function.span(), Some(&function.params), |collector| {
                walk_declaration(collector, it);
            });
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.block_depth += 1;
        walk_block_statement(self, it);
        self.block_depth -= 1;
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(init) = &it.init {
            self.visit_for_statement_init(init);
        }
        if let Some(test) = &it.test {
            self.visit_expression(test);
        }
        if let Some(update) = &it.update {
            self.visit_expression(update);
        }
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.visit_for_header_left(&it.left);
        self.visit_expression(&it.right);
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.visit_for_header_left(&it.left);
        self.visit_expression(&it.right);
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.visit_expression(&it.test);
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
        self.visit_expression(&it.test);
    }
}

fn check_function_contexts(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = FunctionContextCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        block_depth: 0,
        loop_body_depth: 0,
        function_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1472`: calls whose first argument starts on a later line than the call.
struct CallArgumentCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for CallArgumentCollector<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Some(first) = it.arguments.first().and_then(argument_expression) {
            let call_line = self.sink.index.pos(it.span.start).line;
            let argument_line = self.sink.index.pos(first.span().start).line;
            if call_line != argument_line {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1472",
                    "Move the arguments of this call onto the same line as the call.",
                    first.span(),
                );
            }
        }
        walk_call_expression(self, it);
    }
}

fn check_call_argument_lines(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = CallArgumentCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1656`: assignments whose both sides are identical.
struct SelfAssignmentCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
}

impl<'a> Visit<'a> for SelfAssignmentCollector<'a, '_> {
    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if it.operator == AssignmentOperator::Assign {
            let names_match = assignment_target_name(&it.left)
                .is_some_and(|target| identifier_name(&it.right) == Some(target));
            let text_matches = source_slice(self.source, it.left.span())
                == source_slice(self.source, it.right.span());
            if names_match || text_matches {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1656",
                    "Remove this self-assignment.",
                    it.span(),
                );
            }
        }
        walk_assignment_expression(self, it);
    }
}

fn check_self_assignments(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = SelfAssignmentCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
    };
    collector.visit_program(program);
    collector.sink.issues
}

// ===== Batch2c group C: exceptions, structure, and call shapes =====
//
// `S2234` (swapped call arguments by name match), `S2376` (getter without
// setter), `S2432` (setter returning a value, JS-only), `S2486` (empty catch),
// `S2737` (catch that only rethrows), `S3001` (`delete` on a plain
// identifier), `S3524` (mixed arrow body styles), `S3525` (prototype method
// assignment), `S3531` (generator without yield), and `S3626` (redundant
// trailing jump).

use std::collections::BTreeMap;

use oxc_ast::ast::{
    ArrowFunctionBody, Function, ObjectExpression, ObjectPropertyKind, PropertyKind,
};
use oxc_ast_visit::walk::walk_object_expression;

/// Whether any scanned comment lies inside `span` (overlap counts).
fn span_contains_comment(comments: &[ScannedComment], span: Span) -> bool {
    comments
        .iter()
        .any(|comment| comment.token.start < span.end && span.start < comment.token.end)
}

/// Finds `return <value>` statements outside nested functions; used to skip
/// function subtrees while scanning setter bodies.
#[derive(Default)]
struct ReturnValueScanner {
    found: bool,
}

impl<'a> Visit<'a> for ReturnValueScanner {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if it.argument.is_some() {
            self.found = true;
        }
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }
}

/// Finds `yield` expressions outside nested functions; used for `S3531`.
#[derive(Default)]
struct YieldScanner {
    found: bool,
}

impl<'a> Visit<'a> for YieldScanner {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if matches!(it, Expression::YieldExpression(_)) {
            self.found = true;
        }
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, _it: &MethodDefinition<'a>) {}

    fn visit_static_block(&mut self, _it: &StaticBlock<'a>) {}
}

/// `S2486`, `S2737`, and `S2432` in one traversal.
struct ExceptionHandlingCollector<'index> {
    sink: IssueSink<'index>,
    comments: Vec<ScannedComment>,
}

impl<'a> Visit<'a> for ExceptionHandlingCollector<'a> {
    fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
        // `S2737`: exactly one statement rethrowing the caught binding.
        if it.body.body.len() == 1
            && let Statement::ThrowStatement(thrown) = &it.body.body[0]
        {
            let caught = it
                .param
                .as_ref()
                .and_then(|param| binding_identifier_name(&param.pattern));
            if caught.is_some() && identifier_name(&thrown.argument) == caught {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S2737",
                    "This catch clause does nothing but rethrow the caught exception.",
                    thrown.span(),
                );
            }
        }
        // `S2486`: an empty catch is flagged unless it carries a comment
        // explaining why the exception is ignored.
        if it.body.body.is_empty() {
            let inner = Span::new(it.body.span.start + 1, it.body.span.end.saturating_sub(1));
            if !span_contains_comment(&self.comments, inner) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S2486",
                    "Handle this exception or remove this empty catch clause.",
                    it.body.span(),
                );
            }
        }
        walk_catch_clause(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        // `S2432`: setters returning a value.
        if it.kind == MethodDefinitionKind::Set {
            let mut scanner = ReturnValueScanner::default();
            if let Some(body) = &it.value.body {
                scanner.visit_function_body(body);
            }
            if scanner.found {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S2432",
                    "Setters should not return values.",
                    it.key.span(),
                );
            }
        }
        walk_method_definition(self, it);
    }
}

fn check_exception_handling(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ExceptionHandlingCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        comments: scan_comments(source),
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Whether any class element is a getter whose name has no matching setter;
/// flags each unmatched getter (`S2376`, `getWithoutSet=false` mode).
fn check_class_getter_pairing(sink: &mut IssueSink<'_>, elements: &[ClassElement<'_>]) {
    let getter_names: Vec<(Option<&str>, Span)> = elements
        .iter()
        .filter_map(|element| match element {
            ClassElement::MethodDefinition(method) if method.kind == MethodDefinitionKind::Get => {
                Some((property_key_name(&method.key), method.key.span()))
            }
            _ => None,
        })
        .collect();
    let setter_names: Vec<Option<&str>> = elements
        .iter()
        .filter_map(|element| match element {
            ClassElement::MethodDefinition(method) if method.kind == MethodDefinitionKind::Set => {
                Some(property_key_name(&method.key))
            }
            _ => None,
        })
        .collect();
    for (name, span) in getter_names {
        if !setter_names.contains(&name) {
            sink.emit_span(
                RuleScope::Both,
                "S2376",
                "Add a setter matching this getter.",
                span,
            );
        }
    }
}

/// `S3001`, `S3525`, `S3531`, `S3626`, and `S2376` in one traversal.
struct FunctionStructureCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    /// Set while visiting a block that sits directly in a statement list
    /// (`S3626` bare-block case).
    next_block_is_bare: bool,
}

impl<'a> FunctionStructureCollector<'a, '_> {
    /// Enters a function-like node: checks its generator body (`S3531`) and
    /// resets bare-block tracking for the subtree.
    fn enter_function(&mut self, function: &Function<'_>, walk_children: impl FnOnce(&mut Self)) {
        if function.generator {
            let mut scanner = YieldScanner::default();
            if let Some(body) = &function.body {
                scanner.visit_function_body(body);
            }
            if !scanner.found {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3531",
                    "Add a \"yield\" statement to this generator.",
                    function.span(),
                );
            }
        }
        let saved_bare = self.next_block_is_bare;
        self.next_block_is_bare = false;
        walk_children(self);
        self.next_block_is_bare = saved_bare;
    }

    /// Flags the last statement of a statement list when it is an
    /// unconditional jump (`S3626`).
    fn flag_trailing_jump(&mut self, statements: &[Statement<'_>]) {
        let Some(last) = statements.last() else {
            return;
        };
        if matches!(
            last,
            Statement::BreakStatement(_)
                | Statement::ContinueStatement(_)
                | Statement::ReturnStatement(_)
                | Statement::ThrowStatement(_)
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3626",
                "Remove this redundant jump statement.",
                last.span(),
            );
        }
    }

    /// Walks a loop body: trailing-jump check plus non-bare traversal of its
    /// block statements.
    fn visit_loop_body(&mut self, body: &Statement<'a>) {
        if let Statement::BlockStatement(block) = body {
            self.flag_trailing_jump(&block.body);
            for statement in &block.body {
                self.next_block_is_bare = true;
                self.visit_statement(statement);
            }
        } else {
            self.next_block_is_bare = false;
            self.visit_statement(body);
        }
    }
}

impl<'a> Visit<'a> for FunctionStructureCollector<'a, '_> {
    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        // `S3001`: `delete x` on a plain identifier.
        if it.operator == UnaryOperator::Delete && identifier_name(&it.argument).is_some() {
            self.sink.emit_span(
                RuleScope::Both,
                "S3001",
                "Remove this delete of a plain identifier.",
                it.argument.span(),
            );
        }
        walk_unary_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        // `S3525`: `X.prototype.member = function ...`.
        if it.operator == AssignmentOperator::Assign
            && span_text_contains(self.source, it.left.span(), ".prototype.")
            && matches!(
                it.right,
                Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
            )
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3525",
                "Assign methods directly instead of adding them to a prototype.",
                it.left.span(),
            );
        }
        walk_assignment_expression(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            self.enter_function(function, |collector| {
                walk_expression(collector, it);
            });
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        // Arrows cannot be generators; only reset bare-block tracking.
        let saved_bare = self.next_block_is_bare;
        self.next_block_is_bare = false;
        walk_arrow_function_expression(self, it);
        self.next_block_is_bare = saved_bare;
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        let saved_bare = self.next_block_is_bare;
        self.next_block_is_bare = false;
        walk_static_block(self, it);
        self.next_block_is_bare = saved_bare;
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            self.enter_function(function, |collector| {
                walk_declaration(collector, it);
            });
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.enter_function(&it.value, |collector| {
            walk_method_definition(collector, it);
        });
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        check_class_getter_pairing(&mut self.sink, &it.body.body);
        walk_class(self, it);
    }

    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        // `S2376` over object-literal accessors.
        let getters: Vec<(Option<&str>, Span)> = it
            .properties
            .iter()
            .filter_map(|property| match property {
                ObjectPropertyKind::ObjectProperty(inner) if inner.kind == PropertyKind::Get => {
                    Some((property_key_name(&inner.key), inner.key.span()))
                }
                _ => None,
            })
            .collect();
        let setters: Vec<Option<&str>> = it
            .properties
            .iter()
            .filter_map(|property| match property {
                ObjectPropertyKind::ObjectProperty(inner) if inner.kind == PropertyKind::Set => {
                    Some(property_key_name(&inner.key))
                }
                _ => None,
            })
            .collect();
        for (name, span) in getters {
            if !setters.contains(&name) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S2376",
                    "Add a setter matching this getter.",
                    span,
                );
            }
        }
        walk_object_expression(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        for statement in &it.statements {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
    }
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        for statement in &it.body {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        if self.next_block_is_bare {
            self.flag_trailing_jump(&it.body);
        }
        for statement in &it.body {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
    }

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        self.next_block_is_bare = false;
        walk_labeled_statement(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.visit_expression(&it.test);
        self.next_block_is_bare = false;
        self.visit_statement(&it.consequent);
        if let Some(alternate) = &it.alternate {
            self.next_block_is_bare = false;
            self.visit_statement(alternate);
        }
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(init) = &it.init {
            self.visit_for_statement_init(init);
        }
        if let Some(test) = &it.test {
            self.visit_expression(test);
        }
        if let Some(update) = &it.update {
            self.visit_expression(update);
        }
        self.visit_loop_body(&it.body);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.visit_expression(&it.test);
        self.visit_loop_body(&it.body);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.visit_loop_body(&it.body);
        self.visit_expression(&it.test);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        // Case bodies end conventionally with `break`; not an `S3626` case.
        for statement in &it.consequent {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        self.flag_trailing_jump(&it.block.body);
        for statement in &it.block.body {
            self.next_block_is_bare = true;
            self.visit_statement(statement);
        }
        if let Some(handler) = &it.handler {
            self.flag_trailing_jump(&handler.body.body);
            for statement in &handler.body.body {
                self.next_block_is_bare = true;
                self.visit_statement(statement);
            }
        }
        if let Some(finalizer) = &it.finalizer {
            self.flag_trailing_jump(&finalizer.body);
            for statement in &finalizer.body {
                self.next_block_is_bare = true;
                self.visit_statement(statement);
            }
        }
    }
}

fn check_function_structures(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = FunctionStructureCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        next_block_is_bare: false,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Parameter names of named function declarations, for the `S2234` name
/// heuristic.
#[derive(Default)]
struct FunctionParamMapCollector {
    params_by_name: BTreeMap<String, Vec<String>>,
}

impl<'a> Visit<'a> for FunctionParamMapCollector {
    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it
            && let Some(id) = &function.id
        {
            let names: Vec<String> = function
                .params
                .items
                .iter()
                .filter_map(|item| binding_identifier_name(&item.pattern))
                .map(str::to_string)
                .collect();
            self.params_by_name.insert(id.name.to_string(), names);
        }
        walk_declaration(self, it);
    }
}

/// `S2234`: calls of same-file functions where one adjacent swap increases
/// the number of argument names matching parameter names.
struct CallArgumentOrderCollector<'index> {
    sink: IssueSink<'index>,
    params_by_name: BTreeMap<String, Vec<String>>,
}

impl<'a> Visit<'a> for CallArgumentOrderCollector<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let mut checked_callee = false;
        if let Some(callee) = callee_name(it)
            && let Some(parameters) = self.params_by_name.get(callee)
        {
            checked_callee = true;
            let argument_names: Vec<Option<&str>> = it
                .arguments
                .iter()
                .map(|argument| argument_expression(argument).and_then(identifier_name))
                .collect();
            let count = argument_names.len();
            if count >= 2 && count == parameters.len() && argument_names.iter().all(Option::is_some)
            {
                let matched = |order: &[usize]| -> usize {
                    order
                        .iter()
                        .enumerate()
                        .filter(|(position, argument)| {
                            argument_names[**argument] == Some(parameters[*position].as_str())
                        })
                        .count()
                };
                let identity: Vec<usize> = (0..count).collect();
                let baseline = matched(&identity);
                let improved = (0..count - 1).any(|position| {
                    let mut swapped = identity.clone();
                    swapped.swap(position, position + 1);
                    matched(&swapped) > baseline
                });
                if improved {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S2234",
                        "Check this argument order; the arguments look swapped.",
                        it.span(),
                    );
                }
            }
        }
        if !checked_callee {
            walk_call_expression(self, it);
        }
    }
}

fn check_swapped_call_arguments(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut map_collector = FunctionParamMapCollector::default();
    map_collector.visit_program(program);
    let mut collector = CallArgumentOrderCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        params_by_name: map_collector.params_by_name,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S3524`: arrow functions mixing concise-expression and block bodies
/// within one file; each arrow of the minority style is flagged (ties favor
/// block bodies).
struct ArrowStyleCollector<'index> {
    sink: IssueSink<'index>,
    arrows: Vec<(Span, bool)>,
}

impl<'a> Visit<'a> for ArrowStyleCollector<'_> {
    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        let uses_block_body = matches!(it.body, ArrowFunctionBody::FunctionBody(_));
        self.arrows.push((it.span(), uses_block_body));
        walk_arrow_function_expression(self, it);
    }
}

fn check_arrow_body_consistency(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ArrowStyleCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        arrows: Vec::new(),
    };
    collector.visit_program(program);
    let block_bodies = collector.arrows.iter().filter(|(_, block)| *block).count();
    let expression_bodies = collector.arrows.len() - block_bodies;
    // Flag whichever style is the minority; on ties flag expression bodies.
    let minority_is_block = block_bodies < expression_bodies;
    let tie = block_bodies == expression_bodies;
    let flagged_arrows: Vec<Span> = collector
        .arrows
        .iter()
        .filter(|(span, uses_block_body)| {
            let _ = span;
            *uses_block_body == minority_is_block || (tie && !*uses_block_body)
        })
        .map(|(span, _)| *span)
        .collect();
    for span in flagged_arrows {
        collector.sink.emit_span(
            RuleScope::Both,
            "S3524",
            "Use a consistent arrow function body style in this file.",
            span,
        );
    }
    collector.sink.issues
}

// ===== Batch2d group D: control-flow remainder =====
//
// Function-centric measures first: `S3776` (cognitive complexity),
// `S1541` (cyclomatic complexity), `S3801` (mixed return styles), and
// `S3796` (array-callback returns, JavaScript-only) all evaluate one
// function unit at a time, excluding nested function units.

/// `S3776`: functions exceeding this cognitive complexity are flagged
/// (frozen catalog default of the `threshold` parameter).
const MAX_COGNITIVE_COMPLEXITY: u32 = 15;

/// `S1541`: functions exceeding this cyclomatic complexity are flagged
/// (frozen catalog default of `maximumFunctionComplexityThreshold`).
const MAX_CYCLOMATIC_COMPLEXITY: u32 = 10;

/// `S3796`: array methods whose callbacks are expected to return values.
/// `forEach` is deliberately absent — its callbacks legitimately produce
/// nothing, so they never carry a missing-return defect.
const ARRAY_CALLBACK_METHODS: [&str; 10] = [
    "every",
    "filter",
    "find",
    "findIndex",
    "flatMap",
    "map",
    "reduce",
    "reduceRight",
    "some",
    "sort",
];

use oxc_ast_visit::walk::{
    walk_break_statement, walk_conditional_expression, walk_continue_statement, walk_for_statement,
    walk_logical_expression,
};

/// Collects `return` statements outside nested functions, split into
/// value-carrying and bare returns (`S3796`, `S3801`, `S6635`).
#[derive(Default)]
struct ReturnMixScanner {
    valued_spans: Vec<Span>,
    bare_spans: Vec<Span>,
}

impl<'a> Visit<'a> for ReturnMixScanner {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if it.argument.is_some() {
            self.valued_spans.push(it.span());
        } else {
            self.bare_spans.push(it.span());
        }
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, _it: &MethodDefinition<'a>) {}

    fn visit_static_block(&mut self, _it: &StaticBlock<'a>) {}
}

/// Whether one function body carries no value-returning statement outside
/// nested functions (`S3796`).
fn lacks_valued_return(body: &FunctionBody<'_>) -> bool {
    let mut scanner = ReturnMixScanner::default();
    scanner.visit_function_body(body);
    scanner.valued_spans.is_empty()
}

/// Computes the cognitive (`S3776`) and cyclomatic (`S1541`) complexity of
/// one function unit. Nesting weights follow the Sonar model: control-flow
/// structures add `1 + nesting`, `else if` chains stay flat, logical
/// operators count once per consecutive sequence of the same operator, and
/// nested function units are excluded entirely.
#[derive(Default)]
struct ComplexityWalker {
    cognitive: u32,
    cyclomatic: u32,
    nesting: u32,
    /// Operator of the logical chain currently walked; entering a chain (or
    /// switching operators mid-chain) adds one increment.
    logic_chain: Option<LogicalOperator>,
}

impl<'a> Visit<'a> for ComplexityWalker {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.process_if(it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.enter_nested(|walker| walk_for_statement(walker, it));
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.enter_nested(|walker| walk_for_in_statement(walker, it));
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.enter_nested(|walker| walk_for_of_statement(walker, it));
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.enter_nested(|walker| walk_while_statement(walker, it));
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.enter_nested(|walker| walk_do_while_statement(walker, it));
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        self.cognitive += 1 + self.nesting;
        let tested_cases =
            u32::try_from(it.cases.iter().filter(|case| case.test.is_some()).count())
                .unwrap_or(u32::MAX);
        self.cyclomatic += tested_cases;
        self.enter_nested(|walker| walk_switch_statement(walker, it));
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        for statement in &it.block.body {
            self.visit_statement(statement);
        }
        if let Some(handler) = &it.handler {
            self.cognitive += 1 + self.nesting;
            self.cyclomatic += 1;
            let saved = self.nesting;
            self.nesting += 1;
            self.visit_catch_clause(handler);
            self.nesting = saved;
        }
        if let Some(finalizer) = &it.finalizer {
            for statement in &finalizer.body {
                self.visit_statement(statement);
            }
        }
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        self.cognitive += 1 + self.nesting;
        self.cyclomatic += 1;
        self.visit_expression(&it.test);
        let saved = self.nesting;
        self.nesting += 1;
        walk_conditional_expression(self, it);
        self.nesting = saved;
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        if self.logic_chain != Some(it.operator) {
            self.cognitive += 1;
            self.cyclomatic += 1;
        }
        let saved_chain = self.logic_chain;
        self.logic_chain = Some(it.operator);
        walk_logical_expression(self, it);
        self.logic_chain = saved_chain;
    }

    fn visit_break_statement(&mut self, it: &BreakStatement<'a>) {
        if it.label.is_some() {
            self.cognitive += 1;
        }
        walk_break_statement(self, it);
    }

    fn visit_continue_statement(&mut self, it: &ContinueStatement<'a>) {
        if it.label.is_some() {
            self.cognitive += 1;
        }
        walk_continue_statement(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, _it: &MethodDefinition<'a>) {}

    fn visit_static_block(&mut self, _it: &StaticBlock<'a>) {}
}

impl ComplexityWalker {
    /// One `if` increment; `else if` links are processed flat so a chained
    /// conditional adds no extra nesting weight.
    fn process_if(&mut self, it: &IfStatement<'_>) {
        self.cognitive += 1 + self.nesting;
        self.cyclomatic += 1;
        self.visit_expression(&it.test);
        let saved = self.nesting;
        self.nesting += 1;
        self.visit_statement(&it.consequent);
        self.nesting = saved;
        if let Some(Statement::IfStatement(inner)) = &it.alternate {
            self.process_if(inner);
        } else if let Some(alternate) = &it.alternate {
            self.nesting += 1;
            self.visit_statement(alternate);
            self.nesting = saved;
        }
    }

    /// Walks one loop-like construct: `1 + nesting` increments with all
    /// contents nested one level deeper.
    fn enter_nested(&mut self, walk_children: impl FnOnce(&mut Self)) {
        self.cognitive += 1 + self.nesting;
        self.cyclomatic += 1;
        let saved = self.nesting;
        self.nesting += 1;
        walk_children(self);
        self.nesting = saved;
    }
}

/// `S3776`, `S1541`, `S3801`, and `S3796` in one traversal. Every function
/// unit is measured on entry; nested units are measured separately when the
/// descent reaches them.
struct FunctionMetricsCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for FunctionMetricsCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            let exempt = function.generator;
            self.analyze_function(function, function.span(), exempt, |collector| {
                walk_expression(collector, it);
            });
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            let exempt = function.generator;
            self.analyze_function(function, function.span(), exempt, |collector| {
                walk_declaration(collector, it);
            });
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        let exempt = it.kind != MethodDefinitionKind::Method || it.value.generator;
        self.analyze_function(&it.value, it.value.span(), exempt, |collector| {
            walk_method_definition(collector, it);
        });
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        if let Some(body) = it.body.as_function_body() {
            self.report_unit(body, it.span(), false);
        } else {
            self.report_expression_unit(it.body.to_expression(), it.span());
        }
        walk_arrow_function_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // `S3796`: array-method callbacks without any value-returning
        // statement (JavaScript-only).
        if let Some((property, _member)) = call_property(it)
            && ARRAY_CALLBACK_METHODS.contains(&property)
            && let Some(callback) = it.arguments.first().and_then(argument_expression)
        {
            let missing = match callback {
                Expression::FunctionExpression(function) => function
                    .body
                    .as_ref()
                    .is_some_and(|body| lacks_valued_return(body)),
                Expression::ArrowFunctionExpression(arrow) => arrow
                    .body
                    .as_function_body()
                    .is_some_and(lacks_valued_return),
                _ => false,
            };
            if missing {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S3796",
                    "Add the missing \"return\" statement to this function.",
                    callback.span(),
                );
            }
        }
        walk_call_expression(self, it);
    }
}

impl FunctionMetricsCollector<'_> {
    /// Measures one function-like unit, then descends into its subtree.
    fn analyze_function(
        &mut self,
        function: &Function<'_>,
        anchor: Span,
        exempt_mixed_returns: bool,
        walk_children: impl FnOnce(&mut Self),
    ) {
        if let Some(body) = &function.body {
            self.report_unit(body, anchor, exempt_mixed_returns);
        }
        walk_children(self);
    }

    /// Emits the threshold findings for one measured unit.
    fn report_complexity(&mut self, walker: &ComplexityWalker, anchor: Span) {
        if walker.cognitive > MAX_COGNITIVE_COMPLEXITY {
            self.sink.emit_span(
                RuleScope::Both,
                "S3776",
                &format!(
                    "Refactor this function to reduce its Cognitive Complexity from {} to the {} allowed.",
                    walker.cognitive, MAX_COGNITIVE_COMPLEXITY
                ),
                anchor,
            );
        }
        if walker.cyclomatic > MAX_CYCLOMATIC_COMPLEXITY {
            self.sink.emit_span(
                RuleScope::Both,
                "S1541",
                &format!(
                    "The Cyclomatic Complexity of this function is {} which is greater than {} authorized.",
                    walker.cyclomatic, MAX_CYCLOMATIC_COMPLEXITY
                ),
                anchor,
            );
        }
    }

    /// Measures a statement-list unit; `mixed` carries precomputed return
    /// information when the caller wants `S3801` checked.
    fn report_unit(&mut self, body: &FunctionBody<'_>, anchor: Span, exempt_mixed_returns: bool) {
        // Cyclomatic complexity starts at 1 (the single entry path).
        let mut walker = ComplexityWalker {
            cyclomatic: 1,
            ..ComplexityWalker::default()
        };
        for statement in &body.statements {
            walker.visit_statement(statement);
        }
        self.report_complexity(&walker, anchor);
        if !exempt_mixed_returns {
            self.check_mixed_returns(body, anchor);
        }
    }

    /// Measures an expression-bodied arrow (no `S3801`: it always yields).
    fn report_expression_unit(&mut self, expression: &Expression<'_>, anchor: Span) {
        let mut walker = ComplexityWalker {
            cyclomatic: 1,
            ..ComplexityWalker::default()
        };
        walker.visit_expression(expression);
        self.report_complexity(&walker, anchor);
    }

    /// `S3801`: a function mixing valued and bare returns flags each bare
    /// return; a function returning values but also falling off the end is
    /// flagged at the function itself.
    fn check_mixed_returns(&mut self, body: &FunctionBody<'_>, anchor: Span) {
        let mut scanner = ReturnMixScanner::default();
        scanner.visit_function_body(body);
        let falls_off_end = !body
            .statements
            .last()
            .is_some_and(|last| statement_ends_with_jump(last));
        if !scanner.valued_spans.is_empty() && !scanner.bare_spans.is_empty() {
            for span in &scanner.bare_spans {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3801",
                    "Remove this return statement or make it return a value.",
                    *span,
                );
            }
        } else if !scanner.valued_spans.is_empty() && falls_off_end {
            self.sink.emit_span(
                RuleScope::Both,
                "S3801",
                "Make this function consistently return a value.",
                anchor,
            );
        }
    }
}

fn check_function_metrics(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = FunctionMetricsCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

// ----- Group D part B: constructors, accessors, keyword placement, and
// ----- promise/array flow: `S3854`, `S6635`, `S4275`, `S3972`, `S3973`,
// ----- `S4619`, `S4634`, `S6671`, and `S4822`.

use oxc_ast_visit::walk::walk_try_statement;

/// Finds `super(...)` calls anywhere in a subtree.
#[derive(Default)]
struct SuperCallScanner {
    spans: Vec<Span>,
}

impl<'a> Visit<'a> for SuperCallScanner {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::CallExpression(call) = it
            && matches!(call.callee, Expression::Super(_))
        {
            self.spans.push(call.span());
        }
        walk_expression(self, it);
    }
}

/// Detects any `this` reference in a subtree.
#[derive(Default)]
struct ThisUseScanner {
    found: bool,
}

impl<'a> Visit<'a> for ThisUseScanner {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if matches!(it, Expression::ThisExpression(_)) {
            self.found = true;
        }
        walk_expression(self, it);
    }
}

/// Tracks reads and writes of one expected accessor field (`S4275`).
struct FieldAccessScanner<'n> {
    field: &'n str,
    read: bool,
    written: bool,
}

impl<'a> Visit<'a> for FieldAccessScanner<'_> {
    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if matches!(member_object(it), Expression::ThisExpression(_))
            && static_property_name(it) == Some(self.field)
        {
            self.read = true;
        }
        walk_member_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let Some(SimpleAssignmentTarget::StaticMemberExpression(member)) =
            it.left.as_simple_assignment_target()
            && matches!(member.object, Expression::ThisExpression(_))
            && matches!(member.object, Expression::ThisExpression(_))
            && member.property.name == self.field
        {
            self.written = true;
        }
        walk_assignment_expression(self, it);
    }
}

/// Constructor and accessor rules over class bodies (`S3854`, `S6635`,
/// `S4275`) plus object-literal accessors (`S4275`).
struct ClassAccessorCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for ClassAccessorCollector<'_> {
    fn visit_class(&mut self, it: &Class<'a>) {
        let heritage = it.heritage.is_some();
        for element in &it.body.body {
            if let ClassElement::MethodDefinition(method) = element {
                match method.kind {
                    MethodDefinitionKind::Constructor => {
                        self.check_constructor(method, heritage);
                    }
                    MethodDefinitionKind::Get | MethodDefinitionKind::Set => {
                        self.check_accessor(
                            property_key_name(&method.key),
                            method.key.span(),
                            method.kind == MethodDefinitionKind::Set,
                            method.value.body.as_deref(),
                        );
                    }
                    MethodDefinitionKind::Method => {}
                }
            }
        }
        walk_class(self, it);
    }

    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        for property in &it.properties {
            if let ObjectPropertyKind::ObjectProperty(inner) = property
                && inner.kind != PropertyKind::Init
                && let Expression::FunctionExpression(function) = &inner.value
                && let Some(body) = function.body.as_deref()
            {
                self.check_accessor(
                    property_key_name(&inner.key),
                    inner.key.span(),
                    inner.kind == PropertyKind::Set,
                    Some(body),
                );
            }
        }
        walk_object_expression(self, it);
    }
}

impl ClassAccessorCollector<'_> {
    /// `S3854`: missing, duplicated, conditional, or late `super()` calls;
    /// also `S6635`: constructors returning values.
    fn check_constructor(&mut self, method: &MethodDefinition<'_>, heritage: bool) {
        let Some(body) = &method.value.body else {
            return;
        };
        // `S6635` applies with or without a base class.
        let mut returns = ReturnMixScanner::default();
        returns.visit_function_body(body);
        for span in &returns.valued_spans {
            self.sink.emit_span(
                RuleScope::Both,
                "S6635",
                "Remove this return value; constructors should not return anything.",
                *span,
            );
        }
        if !heritage {
            return;
        }

        // Split the calls into direct top-level statements and nested
        // (conditional) ones; only the top-level ones can be "first".
        let mut top_level_spans: Vec<Span> = Vec::new();
        let mut nested_spans: Vec<Span> = Vec::new();
        for statement in &body.statements {
            if is_super_call_statement(statement) {
                if let Statement::ExpressionStatement(expr) = statement
                    && let Expression::CallExpression(call) = unparenthesized(&expr.expression)
                {
                    top_level_spans.push(call.span());
                }
            } else {
                let mut scanner = SuperCallScanner::default();
                scanner.visit_statement(statement);
                nested_spans.extend(scanner.spans);
            }
        }

        if top_level_spans.is_empty() && nested_spans.is_empty() {
            self.sink.emit_span(
                RuleScope::Both,
                "S3854",
                "Add a \"super()\" call in this constructor.",
                method.key.span(),
            );
            return;
        }
        for span in &nested_spans {
            self.sink.emit_span(
                RuleScope::Both,
                "S3854",
                "Move this call of super() to the first statement of this constructor.",
                *span,
            );
        }
        for span in top_level_spans.iter().skip(1) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3854",
                "Remove this duplicated call to super().",
                *span,
            );
        }
        // `this` must not be touched before the first `super()` call.
        if let Some(first) = top_level_spans.first() {
            for statement in &body.statements {
                if is_super_call_statement(statement) {
                    break;
                }
                let mut scanner = ThisUseScanner::default();
                scanner.visit_statement(statement);
                if scanner.found {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3854",
                        "Call super() before accessing \"this\".",
                        statement.span(),
                    );
                    break;
                }
            }
            let _ = first;
        }
    }

    /// `S4275`: accessors should touch the field their name declares.
    fn check_accessor(
        &mut self,
        name: Option<&str>,
        key_span: Span,
        is_setter: bool,
        body: Option<&FunctionBody<'_>>,
    ) {
        let (Some(name), Some(body)) = (name, body) else {
            return;
        };
        let mut scanner = FieldAccessScanner {
            field: name,
            read: false,
            written: false,
        };
        scanner.visit_function_body(body);
        let satisfied = if is_setter {
            scanner.written
        } else {
            scanner.read
        };
        if !satisfied {
            let message = if is_setter {
                format!("Verify that this setter assigns the \"{name}\" field.")
            } else {
                format!("Verify that this getter accesses the \"{name}\" field.")
            };
            self.sink
                .emit_span(RuleScope::Both, "S4275", &message, key_span);
        }
    }
}

fn is_super_call_statement(statement: &Statement<'_>) -> bool {
    matches!(statement, Statement::ExpressionStatement(expr)
        if matches!(unparenthesized(&expr.expression), Expression::CallExpression(call)
            if matches!(call.callee, Expression::Super(_))))
}

fn check_class_accessors(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ClassAccessorCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S3972` (`else`/`catch`/`finally` sharing the closing brace's line) and
/// `S3973` (unbraced single-statement bodies indented deeper than their
/// head statement).
struct KeywordPlacementCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    index: &'index LineIndex,
}

impl<'a> Visit<'a> for KeywordPlacementCollector<'a, '_> {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        if let Some(alternate) = &it.alternate {
            self.check_keyword_line(it.consequent.span(), alternate.span(), "else");
            self.check_unbraced_indent(it.span(), alternate);
        }
        self.check_unbraced_indent(it.span(), &it.consequent);
        walk_if_statement(self, it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_for_statement(self, it);
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_for_in_statement(self, it);
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_for_of_statement(self, it);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_while_statement(self, it);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.check_unbraced_indent(it.span(), &it.body);
        walk_do_while_statement(self, it);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        if let Some(handler) = &it.handler {
            self.check_keyword_line(it.block.span(), handler.span(), "catch");
        }
        let after_catch = it.handler.as_ref().map_or(it.block.span(), |h| h.span());
        if let Some(finalizer) = &it.finalizer {
            self.check_keyword_line(after_catch, finalizer.span(), "finally");
        }
        walk_try_statement(self, it);
    }
}

impl KeywordPlacementCollector<'_, '_> {
    /// `S3972`: the keyword joining two blocks (`else`, `catch`, `finally`)
    /// must start on its own line after the preceding closing brace; a
    /// keyword sharing the brace's line is flagged.
    fn check_keyword_line(&mut self, previous: Span, following: Span, keyword: &str) {
        let gap = &self.source[previous.end as usize..following.start as usize];
        if !gap.contains('\n') {
            let anchor = gap
                .find(keyword)
                .map_or(following.start, |at| previous.end + to_u32(at));
            self.sink.emit_span(
                RuleScope::Both,
                "S3972",
                "Move this keyword onto its own line after the closing brace.",
                Span::new(anchor, anchor + to_u32(keyword.len())),
            );
        }
    }

    /// `S3973`: an unbraced body starting on a later line must be indented
    /// strictly deeper than its head statement.
    fn check_unbraced_indent(&mut self, head: Span, body: &Statement<'_>) {
        if matches!(
            body,
            Statement::BlockStatement(_) | Statement::EmptyStatement(_)
        ) {
            return;
        }
        let head_start = self.index.pos(head.start);
        let body_start = self.index.pos(body.span().start);
        if body_start.line > head_start.line && body_start.column <= head_start.column {
            self.sink.emit_span(
                RuleScope::Both,
                "S3973",
                "Indent this statement deeper than its parent statement.",
                body.span(),
            );
        }
    }
}

fn check_keyword_placement(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = KeywordPlacementCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        index,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Names bound directly to an array literal anywhere in the file, for the
/// `S4619` heuristic (`const xs = []; ... x in xs`).
fn collect_array_binding_names(program: &oxc_ast::ast::Program<'_>) -> BTreeSet<String> {
    #[derive(Default)]
    struct Collector {
        names: BTreeSet<String>,
    }
    impl<'a> Visit<'a> for Collector {
        fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
            if matches!(&it.init, Some(Expression::ArrayExpression(_)))
                && let Some(name) = binding_identifier_name(&it.id)
            {
                self.names.insert(name.to_string());
            }
        }
    }
    let mut collector = Collector::default();
    collector.visit_program(program);
    collector.names
}

/// `S4619` (`in` on arrays), `S4634` (immediately-settling promise
/// executors), `S6671` (rejecting literals), and `S4822` (await-less
/// promise calls inside `try` blocks).
struct PromiseFlowCollector<'index> {
    sink: IssueSink<'index>,
    array_bindings: BTreeSet<String>,
}

impl<'a> Visit<'a> for PromiseFlowCollector<'_> {
    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        if it.operator == BinaryOperator::In {
            let flagged = match unparenthesized(&it.right) {
                Expression::ArrayExpression(_) => true,
                Expression::Identifier(identifier) => {
                    self.array_bindings.contains(identifier.name.as_str())
                }
                _ => false,
            };
            if flagged {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4619",
                    "Use \"includes\" or \"indexOf\" instead of the \"in\" operator on this array.",
                    it.span(),
                );
            }
        }
        walk_binary_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if identifier_name(&it.callee) == Some("Promise")
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && promise_executor_settles_immediately(argument)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4634",
                "Refactor this promise executor; it resolves or rejects immediately.",
                it.span(),
            );
        }
        walk_new_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // `S6671`: rejecting with a plain literal value.
        let rejects = identifier_name(&it.callee) == Some("reject")
            || it.callee.as_member_expression().is_some_and(|member| {
                static_property_name(member) == Some("reject")
                    && member_rooted_at(member, "Promise")
            });
        if rejects
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && is_plain_literal(argument)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6671",
                "Reject this promise with an \"Error\" object instead of a literal value.",
                it.span(),
            );
        }
        walk_call_expression(self, it);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        // `S4822`: await-less promise-producing calls escape the catch.
        for statement in &it.block.body {
            let Some(expression) = statement_as_expression(statement) else {
                continue;
            };
            if matches!(expression, Expression::AwaitExpression(_)) {
                continue;
            }
            if let Expression::CallExpression(call) = unparenthesized(expression) {
                let promise_api = identifier_name(&call.callee) == Some("fetch")
                    || call
                        .callee
                        .as_member_expression()
                        .is_some_and(|member| static_property_name(member) == Some("then"));
                if promise_api {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S4822",
                        "Await this promise; otherwise its failure bypasses the \"catch\".",
                        statement.span(),
                    );
                }
            }
        }
        walk_try_statement(self, it);
    }
}

fn statement_as_expression<'a>(statement: &'a Statement<'a>) -> Option<&'a Expression<'a>> {
    match statement {
        Statement::ExpressionStatement(expr) => Some(&expr.expression),
        _ => None,
    }
}

/// Whether every top-level statement of the executor immediately calls its
/// own resolve/reject parameter.
fn settles_immediately(body: &FunctionBody<'_>, param: &str) -> bool {
    !body.statements.is_empty()
        && body.statements.iter().all(|statement| {
            statement_as_expression(statement).is_some_and(|expression| {
                matches!(unparenthesized(expression), Expression::CallExpression(call)
                    if identifier_name(&call.callee) == Some(param))
            })
        })
}

/// Whether a `new Promise` executor argument settles the promise without
/// doing any asynchronous work: every block statement is an immediate call
/// of its own resolve/reject parameter, or (for expression-bodied arrows)
/// the whole body is that call.
fn promise_executor_settles_immediately(argument: &Expression<'_>) -> bool {
    match argument {
        Expression::FunctionExpression(function) => {
            let Some(body) = function.body.as_deref() else {
                return false;
            };
            let Some(param) = function
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern))
            else {
                return false;
            };
            settles_immediately(body, param)
        }
        Expression::ArrowFunctionExpression(arrow) => {
            let Some(param) = arrow
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern))
            else {
                return false;
            };
            match arrow.body.as_function_body() {
                Some(body) => settles_immediately(body, param),
                None => matches!(arrow.body.to_expression(), Expression::CallExpression(call)
                    if identifier_name(&call.callee) == Some(param)),
            }
        }
        _ => false,
    }
}
use oxc_ast::ast::ExportDeclaration;
use oxc_ast::ast::RegExpFlags;
use oxc_ast_visit::walk::{walk_export_declaration, walk_formal_parameters};
// ===== Batch2d group E: duplication and condition complexity =====
// `S1534` (duplicated object/class keys), `S1536` (duplicated function
// parameters, JavaScript-only), `S6861` (mutable exports), and `S1067`
// (overly complex boolean conditions).

/// `S1067`: conditions carrying more boolean operators than this are
/// flagged (frozen catalog default of the `max` parameter).
const MAX_CONDITION_OPERATORS: usize = 3;

/// Counts `&&`, `||`, and `!` operators in one condition, excluding
/// conditions of nested function units.
#[derive(Default)]
struct ConditionOperatorScanner {
    count: usize,
}

impl<'a> Visit<'a> for ConditionOperatorScanner {
    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        self.count += 1;
        walk_logical_expression(self, it);
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        if it.operator == UnaryOperator::LogicalNot {
            self.count += 1;
        }
        walk_unary_expression(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }
}

/// `S1534`, `S1536`, `S6861`, and `S1067` in one traversal.
struct DuplicationCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for DuplicationCollector<'a> {
    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        // `S1534`: duplicated data-property keys (accessor pairs are legal).
        let mut seen: Vec<&str> = Vec::new();
        for property in &it.properties {
            let ObjectPropertyKind::ObjectProperty(inner) = property else {
                continue;
            };
            if inner.kind != PropertyKind::Init
                || inner.kind == PropertyKind::Init && inner.shorthand
            {
                // Shorthand properties cannot collide with their own binding.
                continue;
            }
            let Some(name) = duplicated_key_name(&inner.key) else {
                continue;
            };
            if seen.contains(&name) {
                self.emit_duplicate_key(&format!("\"{name}\""), inner.key.span());
            } else {
                seen.push(name);
            }
        }
        walk_object_expression(self, it);
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        // `S1534`: duplicated class members; getters and setters pair up, so
        // each accessor kind is tracked separately.
        let mut plain: Vec<&str> = Vec::new();
        let mut getters: Vec<&str> = Vec::new();
        let mut setters: Vec<&str> = Vec::new();
        for element in &it.body.body {
            match element {
                ClassElement::MethodDefinition(method) => {
                    let Some(name) = property_key_name(&method.key) else {
                        continue;
                    };
                    match method.kind {
                        MethodDefinitionKind::Get => {
                            self.flag_duplicate(&mut getters, name, method.key.span());
                        }
                        MethodDefinitionKind::Set => {
                            self.flag_duplicate(&mut setters, name, method.key.span());
                        }
                        _ => self.flag_duplicate(&mut plain, name, method.key.span()),
                    }
                }
                ClassElement::PropertyDefinition(definition) => {
                    if let Some(name) = property_key_name(&definition.key) {
                        self.flag_duplicate(&mut plain, name, definition.key.span());
                    }
                }
                _ => {}
            }
        }
        walk_class(self, it);
    }

    fn visit_formal_parameters(&mut self, it: &FormalParameters<'a>) {
        // `S1536`: duplicate parameter names (JavaScript-only).
        let mut seen: Vec<&str> = Vec::new();
        for item in &it.items {
            let Some(name) = binding_identifier_name(&item.pattern) else {
                continue;
            };
            if seen.contains(&name) {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S1536",
                    &format!("Rename this parameter; \"{name}\" is already used."),
                    item.pattern.span(),
                );
            } else {
                seen.push(name);
            }
        }
        walk_formal_parameters(self, it);
    }

    fn visit_export_declaration(&mut self, it: &ExportDeclaration<'a>) {
        // `S6861`: mutable bindings must not be exported.
        if let Declaration::VariableDeclaration(variable) = &it.declaration
            && variable.kind != VariableDeclarationKind::Const
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6861",
                "Do not export mutable bindings.",
                it.span(),
            );
        }
        walk_export_declaration(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.check_condition_operators(&it.test);
        walk_if_statement(self, it);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.check_condition_operators(&it.test);
        walk_while_statement(self, it);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.check_condition_operators(&it.test);
        walk_do_while_statement(self, it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(test) = &it.test {
            self.check_condition_operators(test);
        }
        walk_for_statement(self, it);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        self.check_condition_operators(&it.test);
        walk_conditional_expression(self, it);
    }
}

impl DuplicationCollector<'_> {
    fn flag_duplicate<'name>(&mut self, seen: &mut Vec<&'name str>, name: &'name str, span: Span) {
        if seen.contains(&name) {
            self.emit_duplicate_key(&format!("\"{name}\""), span);
        } else {
            seen.push(name);
        }
    }

    fn emit_duplicate_key(&mut self, name: &str, span: Span) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1534",
            &format!("Rename or remove this duplicated {name} key."),
            span,
        );
    }

    /// `S1067`: conditions with more operators than the catalog maximum.
    fn check_condition_operators(&mut self, test: &Expression<'_>) {
        let mut scanner = ConditionOperatorScanner::default();
        scanner.visit_expression(test);
        if scanner.count > MAX_CONDITION_OPERATORS {
            self.sink.emit_span(
                RuleScope::Both,
                "S1067",
                &format!(
                    "This condition uses {} boolean operators; simplify it to at most {}.",
                    scanner.count, MAX_CONDITION_OPERATORS
                ),
                test.span(),
            );
        }
    }
}

/// Normalized key name for duplicate detection: static identifiers plus
/// their quoted-string spellings (`{a: 1, "a": 2}` collide).
fn duplicated_key_name<'a>(key: &'a PropertyKey<'a>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) => Some(&identifier.name),
        PropertyKey::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

fn check_duplications(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = DuplicationCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

fn is_plain_literal(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::TemplateLiteral(_)
    )
}

fn check_promise_flows(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = PromiseFlowCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        array_bindings: collect_array_binding_names(program),
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// All Batch2d checks in one place: the control-flow remainder groups D/E
/// (`S3776`, `S3796`, `S3801`, `S3854`, `S3972`, `S3973`, `S4275`,
/// `S4619`, `S4634`, `S4822`, `S6635`, `S6671`, `S6861`, `S1067`,
/// `S1534`, `S1536`, `S1541`) and the ES2015+ idiom section (`S3358`,
/// `S3498`, `S3499`, `S3512`, `S3513`, `S3514`, `S3523`, `S4158`,
/// `S6582`, `S6594`).
fn check_batch2d_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = check_function_metrics(program, index, language);
    issues.extend(check_class_accessors(program, index, language));
    issues.extend(check_keyword_placement(program, source, index, language));
    issues.extend(check_promise_flows(program, index, language));
    issues.extend(check_duplications(program, index, language));
    issues.extend(check_es_idioms(program, index, language));
    issues
}
// ===== Batch2d ES2015+ idiom / rewrite suggestions =====
//
// `S3358` (nested ternaries), `S3498`/`S3499` (shorthand properties),
// `S3512` (string-literal concatenation), `S3513` (`arguments`),
// `S3514` (temp-variable swaps), `S3523` (`new Function`,
// JavaScript-only), `S4158` (empty-array literal operations), `S6582`
// (null guards vs. optional chaining), and `S6594` (`.match` with a
// global regex).

/// Whether an expression is entirely string literals joined by `+`
/// (`S3512`).
fn is_pure_string_concat(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
            is_pure_string_concat(&binary.left) && is_pure_string_concat(&binary.right)
        }
        Expression::StringLiteral(_) => true,
        _ => false,
    }
}

/// Identifier compared against `null`/`undefined` by one side of an `&&`
/// guard (`S6582`).
fn null_guard_target<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    let Expression::BinaryExpression(binary) = unparenthesized(expression) else {
        return None;
    };
    if !is_equality_operator(binary.operator) {
        return None;
    }
    let is_nullish = |expression: &Expression<'_>| {
        matches!(expression, Expression::NullLiteral(_))
            || identifier_name(expression) == Some("undefined")
    };
    match (&binary.left, &binary.right) {
        (Expression::Identifier(identifier), other)
        | (other, Expression::Identifier(identifier))
            if is_nullish(other) =>
        {
            Some(&identifier.name)
        }
        _ => None,
    }
}

/// Detects member accesses rooted at one identifier (`S6582` right-hand
/// usage probe).
#[derive(Default)]
struct RootedMemberScanner<'n> {
    root: &'n str,
    found: bool,
}

impl<'a> Visit<'a> for RootedMemberScanner<'_> {
    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if member_root_name(it) == Some(self.root) {
            self.found = true;
        }
        walk_member_expression(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }
}

/// `S3358`, `S3498`, `S3499`, `S3512`, `S3513`, `S3514`, `S3523`,
/// `S4158`, `S6582`, and `S6594` in one traversal.
struct EsIdiomCollector<'index> {
    sink: IssueSink<'index>,
    /// Pure string-concatenation subroots; minimal spans resolved after the
    /// traversal (`S3512`).
    concat_roots: Vec<Span>,
    /// One frame per enclosing function unit recording whether it shadows
    /// the name `arguments` (`S3513`).
    arguments_shadowed: Vec<bool>,
}

impl<'a> Visit<'a> for EsIdiomCollector<'a> {
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        self.scan_swap_triples(&it.body);
        walk_program(self, it);
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.scan_swap_triples(&it.body);
        walk_block_statement(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.scan_swap_triples(&it.statements);
        walk_function_body(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            let shadowed = function_params_shadow_arguments(&function.params);
            self.arguments_shadowed.push(shadowed);
            walk_expression(self, it);
            self.arguments_shadowed.pop();
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            let shadowed = function_params_shadow_arguments(&function.params);
            self.arguments_shadowed.push(shadowed);
            walk_declaration(self, it);
            self.arguments_shadowed.pop();
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        let shadowed = function_params_shadow_arguments(&it.value.params);
        self.arguments_shadowed.push(shadowed);
        walk_method_definition(self, it);
        self.arguments_shadowed.pop();
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.arguments_shadowed.push(false);
        walk_static_block(self, it);
        self.arguments_shadowed.pop();
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        let shadowed = function_params_shadow_arguments(&it.params);
        self.arguments_shadowed.push(shadowed);
        walk_arrow_function_expression(self, it);
        self.arguments_shadowed.pop();
    }

    fn visit_identifier_reference(&mut self, it: &oxc_ast::ast::IdentifierReference<'a>) {
        // `S3513`: direct `arguments` reads where no parameter shadows it.
        if it.name == "arguments" && !self.arguments_shadowed.iter().any(|&shadowed| shadowed) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3513",
                "Use rest parameters instead of \"arguments\".",
                it.span(),
            );
        }
    }

    fn visit_object_expression(&mut self, it: &ObjectExpression<'a>) {
        let mut non_shorthand_seen = false;
        for property in &it.properties {
            let ObjectPropertyKind::ObjectProperty(inner) = property else {
                continue;
            };
            if inner.kind != PropertyKind::Init {
                continue;
            }
            if inner.shorthand {
                // `S3499`: shorthand properties come first.
                if non_shorthand_seen {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3499",
                        "Write this shorthand property before the non-shorthand properties.",
                        inner.span(),
                    );
                }
            } else {
                non_shorthand_seen = true;
                // `S3498`: `{ a: a }` should use the shorthand form.
                if let (Some(key), Some(value)) =
                    (property_key_name(&inner.key), identifier_name(&inner.value))
                    && key == value
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3498",
                        "Use the shorthand syntax for this property.",
                        inner.span(),
                    );
                }
            }
        }
        walk_object_expression(self, it);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'a>) {
        // `S3358`: ternaries nested in consequent or alternate positions.
        for branch in [&it.consequent, &it.alternate] {
            if let Expression::ConditionalExpression(nested) = unparenthesized(branch) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3358",
                    "Refactor this nested ternary expression.",
                    nested.span(),
                );
            }
        }
        walk_conditional_expression(self, it);
    }

    fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
        // `S3512`: record pure string-concat roots; containment filtering
        // happens after the traversal.
        if it.operator == BinaryOperator::Addition
            && is_pure_string_concat(&it.left)
            && is_pure_string_concat(&it.right)
        {
            self.concat_roots.push(it.span());
        }
        walk_binary_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        // `S3523`: the `Function` constructor (JavaScript-only); overlaps
        // the `S1523` finding on purpose — separate catalog rule keys.
        if constructor_name(it) == Some("Function") {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3523",
                "Remove this use of the \"Function\" constructor.",
                it.callee.span(),
            );
        }
        walk_new_expression(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        // `S4158`: operations on empty array literals always do nothing.
        if matches!(
            unparenthesized(member_object(it)),
            Expression::ArrayExpression(array) if array.elements.is_empty()
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4158",
                "Review this operation; it always targets an empty array.",
                it.span(),
            );
        }
        walk_member_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // `S6594`: `.match(/…/g)` prefers `.matchAll` or `.exec`.
        if let Some((property, _member)) = call_property(it)
            && property == "match"
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && let Expression::RegExpLiteral(literal) = argument
            && literal.regex.flags.contains(RegExpFlags::G)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6594",
                "Prefer \".matchAll\" or \".exec\" over \".match\" for this global regex.",
                it.span(),
            );
        }
        walk_call_expression(self, it);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        // `S6582`: `x !== null && x.member` rewrites to optional chaining.
        if it.operator == LogicalOperator::And
            && let Some(root) = null_guard_target(&it.left)
        {
            let mut scanner = RootedMemberScanner { root, found: false };
            scanner.visit_expression(&it.right);
            if scanner.found {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6582",
                    "Use optional chaining (\"?.\") instead of this null check.",
                    it.span(),
                );
            }
        }
        walk_logical_expression(self, it);
    }
}

impl EsIdiomCollector<'_> {
    /// `S3514`: consecutive `t = a; … ; a = t` statements hide a swap that
    /// destructuring expresses directly.
    fn scan_swap_triples(&mut self, statements: &[Statement<'_>]) {
        for window in statements.windows(3) {
            // First saves `saved` into `temp`, either through an assignment
            // or a single declarator; the third restores it.
            let Some((temp, saved)) = swap_seed(&window[0]) else {
                continue;
            };
            let Some(third) = swap_assignment(&window[2]) else {
                continue;
            };
            if identifier_name(&third.right) != Some(temp) {
                continue;
            }
            let Some(counterpart) = assignment_target_name(&third.left) else {
                continue;
            };
            let Some(middle) = swap_assignment(&window[1]) else {
                continue;
            };
            let links_saved_to_counterpart = (assignment_target_name(&middle.left) == Some(saved)
                && identifier_name(&middle.right) == Some(counterpart))
                || (assignment_target_name(&middle.left) == Some(counterpart)
                    && identifier_name(&middle.right) == Some(saved));
            if counterpart != temp && links_saved_to_counterpart {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3514",
                    "Swap these variables with destructuring instead of this temporary.",
                    window[0].span(),
                );
            }
        }
    }
}

/// The plain `=` assignment expression of an expression statement, if any
/// (`S3514`).
fn swap_assignment<'a>(statement: &'a Statement<'a>) -> Option<&'a AssignmentExpression<'a>> {
    match statement {
        Statement::ExpressionStatement(expression_statement) => {
            match unparenthesized(&expression_statement.expression) {
                Expression::AssignmentExpression(assignment)
                    if assignment.operator == AssignmentOperator::Assign =>
                {
                    Some(assignment)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn function_params_shadow_arguments(params: &FormalParameters<'_>) -> bool {
    params
        .items
        .iter()
        .any(|item| binding_identifier_name(&item.pattern) == Some("arguments"))
}

/// The `temp = saved` seed of a swap triple: either a plain assignment
/// statement or a single-declarator declaration (`let t = a;`) with plain
/// identifier sides (`S3514`).
fn swap_seed<'a>(statement: &'a Statement<'a>) -> Option<(&'a str, &'a str)> {
    match statement {
        Statement::ExpressionStatement(expression_statement) => {
            match unparenthesized(&expression_statement.expression) {
                Expression::AssignmentExpression(assignment)
                    if assignment.operator == AssignmentOperator::Assign =>
                {
                    Some((
                        assignment_target_name(&assignment.left)?,
                        identifier_name(&assignment.right)?,
                    ))
                }
                _ => None,
            }
        }
        Statement::VariableDeclaration(declaration) => {
            let [declarator] = declaration.declarations.as_slice() else {
                return None;
            };
            let name = binding_identifier_name(&declarator.id)?;
            Some((name, identifier_name(declarator.init.as_ref()?)?))
        }
        _ => None,
    }
}
fn check_es_idioms(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = EsIdiomCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        concat_roots: Vec::new(),
        arguments_shadowed: Vec::new(),
    };
    collector.visit_program(program);
    let roots: Vec<Span> = collector
        .concat_roots
        .iter()
        .copied()
        .filter(|span| {
            // Left-nested chains share their start offset with the root,
            // so containment is checked inclusively on both edges.
            !collector.concat_roots.iter().any(|other| {
                (other.start, other.end) != (span.start, span.end)
                    && other.start <= span.start
                    && span.end <= other.end
            })
        })
        .collect();
    for span in roots {
        collector.sink.emit_span(
            RuleScope::Both,
            "S3512",
            "Replace this string concatenation with a template literal.",
            span,
        );
    }
    collector.sink.issues
}

// ===== Batch3: regex-literal family =====
//
// Twenty rules share one mini regex-pattern walker over the literal syntax —
// `RegExpLiteral` pattern text and constant string arguments to the `RegExp`
// constructor; nothing is evaluated at runtime: `S5856`, `S6325`, `S2639`,
// `S6323`, `S6331`, `S5869`, `S6397`, `S6353`, `S6326`, `S6324`, `S6328`,
// `S5842`, `S6019`, `S6035`, `S5850`, `S5867`, `S5868`, `S5843`, `S5852`,
// and `S6351`.

/// `S5843`: patterns scoring above this complexity budget are flagged
/// (subset approximation of the frozen catalog `threshold=20`).
const REGEX_COMPLEXITY_THRESHOLD: u32 = 20;

/// Character-class shorthand escapes (`\d`, `\w`, `\s` and negations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShorthandClass {
    Digit,
    Word,
    Space,
}

/// Zero-width assertions understood by the pattern parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorKind {
    Start,
    End,
    WordBoundary,
    NotWordBoundary,
}

/// Group headers the mini parser understands; anything else (`(?P`, …) is a
/// definite syntax error for `S5856`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GroupKind {
    Capturing,
    Named(String),
    NonCapturing,
    Lookahead { negated: bool },
    Lookbehind { negated: bool },
}

impl GroupKind {
    fn is_lookaround(&self) -> bool {
        matches!(self, Self::Lookahead { .. } | Self::Lookbehind { .. })
    }
}

/// One item inside a `[...]` character class.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClassItem {
    Char {
        ch: char,
        pos: usize,
    },
    Range {
        low: char,
        high: char,
        start: usize,
    },
    Shorthand {
        negated: bool,
        kind: ShorthandClass,
        pos: usize,
    },
    Property {
        negated: bool,
        pos: usize,
    },
}

/// One node of the mini regex-pattern tree. Positions are byte offsets into
/// the pattern text so findings can be anchored at the offending construct.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternNode {
    Literal {
        ch: char,
        pos: usize,
    },
    Dot,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
        start: usize,
        end: usize,
    },
    ClassEscape {
        negated: bool,
        kind: ShorthandClass,
        pos: usize,
    },
    PropertyEscape {
        negated: bool,
        pos: usize,
    },
    Anchor {
        kind: AnchorKind,
        pos: usize,
    },
    Group {
        kind: GroupKind,
        alternatives: Vec<Vec<PatternNode>>,
        start: usize,
        end: usize,
    },
    BackReference {
        pos: usize,
    },
    Quantified {
        node: Box<PatternNode>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
        pos: usize,
        /// Verbatim source text of the quantifier (`{1}` vs `{1,1}`).
        verbose: String,
    },
}

/// Parse result of [`parse_regex_pattern`].
struct ParsedRegex {
    alternatives: Vec<Vec<PatternNode>>,
    /// Byte offsets of empty alternation branches with at least one
    /// non-empty sibling (`S6323`); wholly empty groups belong to `S6331`.
    empty_branch_positions: Vec<usize>,
    capture_count: usize,
    capture_names: Vec<String>,
}

/// Parses the literal-syntax subset of ECMAScript regex patterns. Returns
/// `Err` only for definite syntax errors — unbalanced parentheses,
/// unterminated character classes, quantifiers with nothing to repeat,
/// unknown `(?…)` headers, reversed class ranges, and malformed `\u`/`\x`
/// forms in unicode mode. Anything merely unfamiliar parses conservatively
/// so the walker never invents findings (tolerant, never panics).
fn parse_regex_pattern(pattern: &str, unicode_mode: bool) -> Result<ParsedRegex, ()> {
    let mut parser = PatternParser {
        source: pattern,
        chars: pattern.char_indices().collect(),
        pos: 0,
        captures: Vec::new(),
        unicode_mode,
        empty_branch_positions: Vec::new(),
    };
    let alternatives = parser.parse_alternatives(None)?;
    Ok(ParsedRegex {
        capture_count: parser.captures.len(),
        capture_names: parser.captures.iter().flatten().cloned().collect(),
        alternatives,
        empty_branch_positions: parser.empty_branch_positions,
    })
}

struct PatternParser<'p> {
    /// The raw pattern text, for verbatim quantifier slices.
    source: &'p str,
    chars: Vec<(usize, char)>,
    pos: usize,
    captures: Vec<Option<String>>,
    unicode_mode: bool,
    empty_branch_positions: Vec<usize>,
}

impl PatternParser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).map(|&(_, ch)| ch)
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += 1;
        Some(ch)
    }

    fn current_offset(&self) -> usize {
        self.chars
            .get(self.pos)
            .map_or_else(|| self.end_offset(), |&(off, _)| off)
    }

    fn end_offset(&self) -> usize {
        self.chars
            .last()
            .map_or(0, |&(off, ch)| off + ch.len_utf8())
    }

    /// Alternation body of the whole pattern (`terminator: None`) or of one
    /// group (`terminator: Some(')')`, consumed here).
    fn parse_alternatives(
        &mut self,
        terminator: Option<char>,
    ) -> Result<Vec<Vec<PatternNode>>, ()> {
        let mut alternatives = Vec::new();
        let mut local_empties = Vec::new();
        loop {
            let branch_start = self.current_offset();
            let nodes = self.parse_sequence(terminator)?;
            if nodes.is_empty() {
                local_empties.push(branch_start);
            }
            alternatives.push(nodes);
            if self.peek() == Some('|') {
                self.pos += 1;
            } else {
                break;
            }
        }
        // A single empty branch is either an empty pattern (clean) or a
        // wholly empty group (`S6331`); neither belongs to `S6323`.
        if !(alternatives.len() == 1 && alternatives[0].is_empty()) {
            self.empty_branch_positions.extend(local_empties);
        }
        match terminator {
            None => {
                if self.pos != self.chars.len() {
                    return Err(()); // stray `)`
                }
            }
            Some(expected) => {
                if self.peek() != Some(expected) {
                    return Err(()); // unclosed group
                }
                self.pos += 1;
            }
        }
        Ok(alternatives)
    }

    fn parse_sequence(&mut self, terminator: Option<char>) -> Result<Vec<PatternNode>, ()> {
        let mut nodes: Vec<PatternNode> = Vec::new();
        loop {
            match self.peek() {
                None | Some('|') => break,
                Some(')') => {
                    if terminator == Some(')') {
                        break;
                    }
                    return Err(()); // unbalanced `)`
                }
                // A quantifier here has nothing to repeat: sequence start,
                // after `|`, after `(`, or stacked onto another quantifier.
                Some('*' | '+' | '?') => return Err(()),
                _ => {}
            }
            let atom = self.parse_atom()?;
            let quantifier_pos = self.current_offset();
            if let Some((min, max)) = self.try_parse_quantifier()? {
                let mut greedy = true;
                if self.peek() == Some('?') {
                    self.pos += 1;
                    greedy = false;
                }
                let verbose = self.source[quantifier_pos..self.current_offset()].to_string();
                nodes.push(PatternNode::Quantified {
                    node: Box::new(atom),
                    min,
                    max,
                    greedy,
                    pos: quantifier_pos,
                    verbose,
                });
            } else {
                nodes.push(atom);
            }
        }
        Ok(nodes)
    }

    /// `Ok(None)` when the upcoming text is not a quantifier (malformed
    /// braces stay literal characters, per Annex B); `Err` for a definite
    /// `{m,n}` reversal in unicode mode.
    fn try_parse_quantifier(&mut self) -> Result<Option<(u32, Option<u32>)>, ()> {
        match self.peek() {
            Some('*') => {
                self.pos += 1;
                Ok(Some((0, None)))
            }
            Some('+') => {
                self.pos += 1;
                Ok(Some((1, None)))
            }
            Some('?') => {
                self.pos += 1;
                Ok(Some((0, Some(1))))
            }
            Some('{') => self.try_parse_brace_quantifier(),
            _ => Ok(None),
        }
    }

    fn try_parse_brace_quantifier(&mut self) -> Result<Option<(u32, Option<u32>)>, ()> {
        let save = self.pos;
        self.pos += 1; // `{`
        let Some(min) = self.parse_decimal() else {
            self.pos = save;
            return Ok(None);
        };
        let max = match self.peek() {
            Some('}') => {
                self.pos += 1;
                Some(min)
            }
            Some(',') => {
                self.pos += 1;
                let max = self.parse_decimal();
                if self.peek() != Some('}') {
                    self.pos = save;
                    return Ok(None);
                }
                self.pos += 1;
                max
            }
            _ => {
                self.pos = save;
                return Ok(None);
            }
        };
        if let Some(max) = max
            && max < min
        {
            if self.unicode_mode {
                return Err(());
            }
            self.pos = save;
            return Ok(None);
        }
        Ok(Some((min, max)))
    }

    fn parse_decimal(&mut self) -> Option<u32> {
        let mut value: Option<u32> = None;
        while let Some(digit) = self.peek().and_then(|next| next.to_digit(10)) {
            value = Some(value.unwrap_or(0).saturating_mul(10).saturating_add(digit));
            self.pos += 1;
        }
        value
    }

    fn parse_atom(&mut self) -> Result<PatternNode, ()> {
        let Some(&(pos, ch)) = self.chars.get(self.pos) else {
            return Err(());
        };
        self.pos += 1;
        match ch {
            '.' => Ok(PatternNode::Dot),
            '^' => Ok(PatternNode::Anchor {
                kind: AnchorKind::Start,
                pos,
            }),
            '$' => Ok(PatternNode::Anchor {
                kind: AnchorKind::End,
                pos,
            }),
            '[' => self.parse_class(pos),
            '(' => self.parse_group(pos),
            '\\' => self.parse_escape(pos),
            _ => Ok(PatternNode::Literal { ch, pos }),
        }
    }

    fn parse_group(&mut self, start: usize) -> Result<PatternNode, ()> {
        let kind = if self.peek() == Some('?') {
            self.pos += 1;
            match self.peek() {
                Some(':') => {
                    self.pos += 1;
                    GroupKind::NonCapturing
                }
                Some('=') => {
                    self.pos += 1;
                    GroupKind::Lookahead { negated: false }
                }
                Some('!') => {
                    self.pos += 1;
                    GroupKind::Lookahead { negated: true }
                }
                Some('<') => {
                    self.pos += 1;
                    match self.peek() {
                        Some('=') => {
                            self.pos += 1;
                            GroupKind::Lookbehind { negated: false }
                        }
                        Some('!') => {
                            self.pos += 1;
                            GroupKind::Lookbehind { negated: true }
                        }
                        _ => {
                            let name = self.parse_group_name()?;
                            self.captures.push(Some(name.clone()));
                            GroupKind::Named(name)
                        }
                    }
                }
                _ => return Err(()), // unknown `(?…)` header
            }
        } else {
            self.captures.push(None);
            GroupKind::Capturing
        };
        let alternatives = self.parse_alternatives(Some(')'))?;
        Ok(PatternNode::Group {
            kind,
            alternatives,
            start,
            end: self.end_offset(),
        })
    }

    fn parse_group_name(&mut self) -> Result<String, ()> {
        let mut name = String::new();
        loop {
            match self.bump() {
                None | Some('(' | '|') => return Err(()),
                Some('>') => break,
                Some(ch) => name.push(ch),
            }
        }
        if name.is_empty() {
            return Err(());
        }
        Ok(name)
    }

    fn parse_escape(&mut self, backslash_pos: usize) -> Result<PatternNode, ()> {
        let Some(&(char_pos, ch)) = self.chars.get(self.pos) else {
            return Err(()); // trailing backslash
        };
        self.pos += 1;
        match ch {
            'd' | 'D' | 'w' | 'W' | 's' | 'S' => {
                let (negated, kind) = match ch {
                    'D' => (true, ShorthandClass::Digit),
                    'W' => (true, ShorthandClass::Word),
                    'S' => (true, ShorthandClass::Space),
                    'd' => (false, ShorthandClass::Digit),
                    'w' => (false, ShorthandClass::Word),
                    _ => (false, ShorthandClass::Space),
                };
                Ok(PatternNode::ClassEscape {
                    negated,
                    kind,
                    pos: backslash_pos,
                })
            }
            'p' | 'P' => match self.peek() {
                Some('{') => {
                    self.skip_property_body()?;
                    Ok(PatternNode::PropertyEscape {
                        negated: ch == 'P',
                        pos: backslash_pos,
                    })
                }
                None => Err(()),
                Some(_) if self.unicode_mode => Err(()),
                Some(_) => Ok(PatternNode::Literal { ch, pos: char_pos }),
            },
            'b' => Ok(PatternNode::Anchor {
                kind: AnchorKind::WordBoundary,
                pos: backslash_pos,
            }),
            'B' => Ok(PatternNode::Anchor {
                kind: AnchorKind::NotWordBoundary,
                pos: backslash_pos,
            }),
            '1'..='9' => {
                while self.peek().is_some_and(|next| next.is_ascii_digit()) {
                    self.pos += 1;
                }
                Ok(PatternNode::BackReference { pos: backslash_pos })
            }
            'k' if self.peek() == Some('<') => {
                self.pos += 1;
                self.parse_group_name()?;
                Ok(PatternNode::BackReference { pos: backslash_pos })
            }
            'n' => Ok(PatternNode::Literal {
                ch: '\n',
                pos: char_pos,
            }),
            't' => Ok(PatternNode::Literal {
                ch: '\t',
                pos: char_pos,
            }),
            'r' => Ok(PatternNode::Literal {
                ch: '\r',
                pos: char_pos,
            }),
            'f' => Ok(PatternNode::Literal {
                ch: '\u{000C}',
                pos: char_pos,
            }),
            'v' => Ok(PatternNode::Literal {
                ch: '\u{000B}',
                pos: char_pos,
            }),
            '0' => Ok(PatternNode::Literal {
                ch: '\0',
                pos: char_pos,
            }),
            'u' if self.unicode_mode => Ok(PatternNode::Literal {
                ch: self.parse_unicode_escape()?,
                pos: char_pos,
            }),
            'x' if self.unicode_mode => Ok(PatternNode::Literal {
                ch: self.parse_hex_escape(2)?,
                pos: char_pos,
            }),
            'c' if self.unicode_mode => match self.peek() {
                Some(letter) if letter.is_ascii_alphabetic() => {
                    self.pos += 1;
                    Ok(PatternNode::Literal {
                        ch: (letter.to_ascii_uppercase() as u8 ^ 0x40) as char,
                        pos: char_pos,
                    })
                }
                _ => Err(()),
            },
            _ => Ok(PatternNode::Literal { ch, pos: char_pos }),
        }
    }

    /// `\u{HexDigits}` or `\uHHHH` in unicode mode; `u` already consumed.
    fn parse_unicode_escape(&mut self) -> Result<char, ()> {
        if self.peek() == Some('{') {
            self.pos += 1;
            let mut value: u32 = 0;
            let mut digits = 0;
            while let Some(next) = self.peek()
                && next != '}'
            {
                let Some(nibble) = next.to_digit(16) else {
                    return Err(());
                };
                value = value.saturating_mul(16).saturating_add(nibble);
                digits += 1;
                self.pos += 1;
            }
            if digits == 0 || digits > 6 || self.bump() != Some('}') {
                return Err(());
            }
            char::from_u32(value).ok_or(())
        } else {
            self.parse_hex_escape(4)
        }
    }

    /// Exactly `count` hex digits in unicode mode; `x`/`u` already consumed.
    fn parse_hex_escape(&mut self, count: usize) -> Result<char, ()> {
        let mut value: u32 = 0;
        for _ in 0..count {
            let nibble = self.peek().and_then(|next| next.to_digit(16)).ok_or(())?;
            value = value.saturating_mul(16).saturating_add(nibble);
            self.pos += 1;
        }
        char::from_u32(value).ok_or(())
    }

    fn skip_property_body(&mut self) -> Result<(), ()> {
        self.pos += 1; // `{`
        loop {
            match self.bump() {
                None | Some('(' | '|') => return Err(()),
                Some('}') => return Ok(()),
                Some(_) => {}
            }
        }
    }

    fn parse_class(&mut self, start: usize) -> Result<PatternNode, ()> {
        let negated = if self.peek() == Some('^') {
            self.pos += 1;
            true
        } else {
            false
        };
        let mut items = Vec::new();
        loop {
            let Some(&(item_pos, ch)) = self.chars.get(self.pos) else {
                return Err(()); // unterminated class
            };
            if ch == ']' {
                self.pos += 1;
                break;
            }
            let item = self.parse_class_item(item_pos, ch)?;
            if let ClassItem::Char {
                ch: low,
                pos: low_pos,
            } = item
                && let Some(range) = self.try_parse_class_range(low, low_pos)?
            {
                items.push(range);
            } else {
                items.push(item);
            }
        }
        Ok(PatternNode::Class {
            negated,
            items,
            start,
            end: self.end_offset(),
        })
    }

    /// Extends a lone class char into `low-high` when a dash and a further
    /// single char follow; otherwise rewinds so `-` stays literal.
    fn try_parse_class_range(
        &mut self,
        low: char,
        low_pos: usize,
    ) -> Result<Option<ClassItem>, ()> {
        if self.peek() != Some('-') {
            return Ok(None);
        }
        let save = self.pos;
        self.pos += 1; // `-`
        let Some(&(high_pos, high_ch)) = self.chars.get(self.pos) else {
            self.pos = save;
            return Ok(None);
        };
        if high_ch == ']' {
            self.pos = save;
            return Ok(None);
        }
        let ClassItem::Char { ch: high, .. } = self.parse_class_item(high_pos, high_ch)? else {
            // `a-\d`: Annex B keeps the dash literal; rewind and let the
            // shorthand be parsed as its own item.
            self.pos = save;
            return Ok(None);
        };
        if high < low {
            return Err(()); // reversed range
        }
        Ok(Some(ClassItem::Range {
            low,
            high,
            start: low_pos,
        }))
    }

    fn parse_class_item(&mut self, pos: usize, ch: char) -> Result<ClassItem, ()> {
        if ch != '\\' {
            self.pos += 1;
            return Ok(ClassItem::Char { ch, pos });
        }
        self.pos += 1; // backslash
        let Some(&(char_pos, esc)) = self.chars.get(self.pos) else {
            return Err(()); // trailing backslash
        };
        self.pos += 1;
        Ok(match esc {
            'd' => ClassItem::Shorthand {
                negated: false,
                kind: ShorthandClass::Digit,
                pos,
            },
            'D' => ClassItem::Shorthand {
                negated: true,
                kind: ShorthandClass::Digit,
                pos,
            },
            'w' => ClassItem::Shorthand {
                negated: false,
                kind: ShorthandClass::Word,
                pos,
            },
            'W' => ClassItem::Shorthand {
                negated: true,
                kind: ShorthandClass::Word,
                pos,
            },
            's' => ClassItem::Shorthand {
                negated: false,
                kind: ShorthandClass::Space,
                pos,
            },
            'S' => ClassItem::Shorthand {
                negated: true,
                kind: ShorthandClass::Space,
                pos,
            },
            'p' | 'P' => match self.peek() {
                Some('{') => {
                    self.skip_property_body()?;
                    ClassItem::Property {
                        negated: esc == 'P',
                        pos,
                    }
                }
                None => return Err(()),
                Some(_) if self.unicode_mode => return Err(()),
                Some(_) => ClassItem::Char {
                    ch: esc,
                    pos: char_pos,
                },
            },
            'b' => ClassItem::Char {
                ch: '\u{0008}',
                pos: char_pos,
            },
            'n' => ClassItem::Char {
                ch: '\n',
                pos: char_pos,
            },
            't' => ClassItem::Char {
                ch: '\t',
                pos: char_pos,
            },
            'r' => ClassItem::Char {
                ch: '\r',
                pos: char_pos,
            },
            'f' => ClassItem::Char {
                ch: '\u{000C}',
                pos: char_pos,
            },
            'v' => ClassItem::Char {
                ch: '\u{000B}',
                pos: char_pos,
            },
            '0' => ClassItem::Char {
                ch: '\0',
                pos: char_pos,
            },
            'u' if self.unicode_mode => ClassItem::Char {
                ch: self.parse_unicode_escape()?,
                pos: char_pos,
            },
            'x' if self.unicode_mode => ClassItem::Char {
                ch: self.parse_hex_escape(2)?,
                pos: char_pos,
            },
            _ => ClassItem::Char {
                ch: esc,
                pos: char_pos,
            },
        })
    }
}

/// Whether a sequence can match the empty string.
fn sequence_can_match_empty(sequence: &[PatternNode]) -> bool {
    sequence.iter().all(node_can_match_empty)
}

/// Whether one node can match the empty string; lookarounds and anchors are
/// zero-width, groups when any alternative is empty-capable.
fn node_can_match_empty(node: &PatternNode) -> bool {
    match node {
        PatternNode::Anchor { .. } => true,
        PatternNode::Group {
            kind, alternatives, ..
        } => {
            kind.is_lookaround()
                || alternatives
                    .iter()
                    .any(|alternative| sequence_can_match_empty(alternative))
        }
        PatternNode::Quantified { min, node, .. } => *min == 0 || node_can_match_empty(node),
        _ => false,
    }
}

/// Pre-order traversal of the pattern tree behind `sequence`.
fn walk_pattern_nodes(sequence: &[PatternNode], visit: &mut dyn FnMut(&PatternNode)) {
    for node in sequence {
        visit(node);
        match node {
            PatternNode::Group { alternatives, .. } => {
                for alternative in alternatives {
                    walk_pattern_nodes(alternative, visit);
                }
            }
            PatternNode::Quantified { node: inner, .. } => {
                walk_pattern_nodes(std::slice::from_ref(inner.as_ref()), visit);
            }
            _ => {}
        }
    }
}

/// Documented subset approximation of the `S5843` complexity score:
/// literals/dots/anchors cost 1, shorthands 2, backreferences 2, property
/// escapes 3, classes `2 + items`, groups 2 (lookarounds 4) plus their
/// body, quantifiers 2 plus their target, and each additional alternation
/// branch costs 1.
fn pattern_complexity(alternatives: &[Vec<PatternNode>]) -> u32 {
    let extra_branches = alternatives.len().saturating_sub(1);
    alternatives
        .iter()
        .map(|alternative| alternative.iter().map(node_complexity).sum::<u32>())
        .sum::<u32>()
        .saturating_add(to_u32(extra_branches))
}

fn node_complexity(node: &PatternNode) -> u32 {
    match node {
        PatternNode::Literal { .. } | PatternNode::Dot | PatternNode::Anchor { .. } => 1,
        PatternNode::BackReference { .. } | PatternNode::ClassEscape { .. } => 2,
        PatternNode::PropertyEscape { .. } => 3,
        PatternNode::Class { items, .. } => 2u32.saturating_add(to_u32(items.len())),
        PatternNode::Group {
            kind, alternatives, ..
        } => {
            let base: u32 = if kind.is_lookaround() { 4 } else { 2 };
            base.saturating_add(pattern_complexity(alternatives))
        }
        PatternNode::Quantified { node, .. } => 2u32.saturating_add(node_complexity(node)),
    }
}

// ----- Regex-site plumbing -----

/// One constant regex found in the AST: a regex literal or a `RegExp`
/// constructor call whose arguments are all literals. Pattern rules run the
/// shared mini walker over the pattern text; nothing is executed.
struct RegexSite {
    /// Fallback span for findings whose exact pattern offset is unknown
    /// (constructor-form offsets hide behind string escapes).
    span: Span,
    /// Source byte offset of `pattern[0]`; reliable only when
    /// [`RegexSite::exact`] holds.
    pattern_base: u32,
    /// Whether `pattern_base` maps pattern byte offsets exactly onto source.
    exact: bool,
    pattern: String,
    flags: String,
}

impl RegexSite {
    fn sub_span(&self, start: usize, end: usize) -> Span {
        if self.exact {
            Span::new(
                self.pattern_base.saturating_add(to_u32(start)),
                self.pattern_base.saturating_add(to_u32(end)),
            )
        } else {
            self.span
        }
    }

    fn whole_pattern_span(&self) -> Span {
        self.sub_span(0, self.pattern.len())
    }

    fn has_flag(&self, flag: char) -> bool {
        self.flags.contains(flag)
    }
}

/// Builds a site from a regex literal; its pattern text sits verbatim
/// between the slashes, so sub-spans are exact.
fn regex_site_from_literal(literal: &RegExpLiteral<'_>) -> RegexSite {
    RegexSite {
        span: literal.span,
        pattern_base: literal.span.start.saturating_add(1),
        exact: true,
        pattern: literal.regex.pattern.text.as_str().to_string(),
        flags: regex_flags_text(literal.regex.flags),
    }
}

/// Literal-form flags in canonical order; the constructor form keeps its
/// raw flags string instead.
fn regex_flags_text(flags: RegExpFlags) -> String {
    const ORDERED: [(RegExpFlags, char); 8] = [
        (RegExpFlags::G, 'g'),
        (RegExpFlags::I, 'i'),
        (RegExpFlags::M, 'm'),
        (RegExpFlags::S, 's'),
        (RegExpFlags::U, 'u'),
        (RegExpFlags::Y, 'y'),
        (RegExpFlags::D, 'd'),
        (RegExpFlags::V, 'v'),
    ];
    ORDERED
        .iter()
        .filter(|&(flag, _)| flags.contains(*flag))
        .map(|&(_, ch)| ch)
        .collect()
}

/// String value of a constant literal argument: a string literal or a
/// substitution-free template literal.
fn literal_string_value(argument: &oxc_ast::ast::Argument<'_>) -> Option<String> {
    match argument.as_expression()? {
        Expression::StringLiteral(string) => Some(string.value.as_str().to_string()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => template
            .quasis
            .first()
            .and_then(|element| element.value.cooked.as_ref())
            .map(|atom| atom.as_str().to_string()),
        _ => None,
    }
}

/// Builds a site from `new RegExp(pattern, flags?)` / `RegExp(pattern,
/// flags?)` when every argument is a constant literal. Offsets inside
/// escaped strings are unreliable, so findings anchor at the argument span.
fn constructor_regex_site(arguments: &[oxc_ast::ast::Argument<'_>]) -> Option<RegexSite> {
    let values: Vec<Option<String>> = arguments.iter().map(literal_string_value).collect();
    let pattern = values.first()?.clone()?;
    let flags = values.get(1).cloned().flatten().unwrap_or_default();
    Some(RegexSite {
        span: arguments.first()?.span(),
        pattern_base: 0,
        exact: false,
        pattern,
        flags,
    })
}

/// The regex literal behind an optional call argument, if it is one.
fn regex_literal_argument<'a>(
    argument: Option<&'a oxc_ast::ast::Argument<'a>>,
) -> Option<&'a oxc_ast::ast::RegExpLiteral<'a>> {
    match argument?.as_expression()? {
        Expression::RegExpLiteral(literal) => Some(literal),
        _ => None,
    }
}

// ----- Shared-walker rule drivers -----

/// Runs every pattern-text rule over one constant regex site. The raw-text
/// scans also run on patterns the mini parser rejects; everything
/// structure-based needs a successful parse.
fn check_constant_regex_site(sink: &mut IssueSink, site: &RegexSite) {
    check_control_characters(sink, site);
    check_unicode_constructs_without_u_flag(sink, site);
    let unicode_mode = site.has_flag('u') || site.has_flag('v');
    let Ok(parsed) = parse_regex_pattern(&site.pattern, unicode_mode) else {
        // Upstream embeds the validator's detail text; the subset reports
        // statically because the mini parser carries no error messages.
        sink.emit_span(
            RuleScope::Both,
            "S5856",
            "Invalid regular expression.",
            site.whole_pattern_span(),
        );
        return;
    };
    check_empty_character_class(sink, site, &parsed);
    check_empty_alternatives(sink, site, &parsed);
    check_empty_groups(sink, site, &parsed);
    check_duplicate_class_members(sink, site, &parsed);
    check_single_member_class(sink, site, &parsed);
    check_concise_shapes(sink, site, &parsed);
    check_space_runs(sink, site, &parsed);
    check_empty_string_repetition(sink, site, &parsed);
    check_pointless_reluctant_quantifier(sink, site, &parsed);
    check_single_char_alternation(sink, site, &parsed);
    check_anchor_precedence(sink, site, &parsed);
    check_misleading_class_characters(sink, site, &parsed);
    check_regex_complexity(sink, site, &parsed);
    check_exponential_backtracking(sink, site, &parsed);
}

/// `S2639`: `[]` never matches anything and `[^]` matches everything —
/// both are defects.
fn check_empty_character_class(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Class {
                items, start, end, ..
            } = node
                && items.is_empty()
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S2639",
                    "Rework this empty character class that doesn't match anything.",
                    site.sub_span(*start, *end),
                );
            }
        });
    }
}

/// `S6323`: an alternation branch that can never participate (`|`, `(a|)`).
fn check_empty_alternatives(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for pos in &parsed.empty_branch_positions {
        sink.emit_span(
            RuleScope::Both,
            "S6323",
            "Remove this empty alternative.",
            site.sub_span(*pos, *pos),
        );
    }
}

/// `S6331`: a wholly empty group `()` / `(?:)`.
fn check_empty_groups(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Group {
                kind,
                alternatives,
                start,
                end,
            } = node
                && !kind.is_lookaround()
                && alternatives.len() == 1
                && alternatives[0].is_empty()
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S6331",
                    "Remove this empty group.",
                    site.sub_span(*start, *end),
                );
            }
        });
    }
}

/// `S5869`: repeated characters inside `[...]`. Case-insensitive folding is
/// out of subset scope.
fn check_duplicate_class_members(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            let PatternNode::Class { items, .. } = node else {
                return;
            };
            let mut seen: Vec<char> = Vec::new();
            for item in items {
                if let ClassItem::Char { ch, pos } = item {
                    if seen.contains(ch) {
                        sink.emit_span(
                            RuleScope::Both,
                            "S5869",
                            "Remove duplicates in this character class.",
                            site.sub_span(*pos, pos + ch.len_utf8()),
                        );
                    } else {
                        seen.push(*ch);
                    }
                }
            }
        });
    }
}

/// `S6397`: `[a]` asserts no more than `a`.
fn check_single_member_class(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Class {
                items, start, end, ..
            } = node
                && items.len() == 1
                && matches!(items[0], ClassItem::Char { .. })
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S6397",
                    "Replace this character class by the character itself.",
                    site.sub_span(*start, *end),
                );
            }
        });
    }
}

/// `S6353`: `{1}` / `{1,1}` quantifiers and duplicate-only classes with a
/// concise rewrite.
fn check_concise_shapes(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| match node {
            PatternNode::Quantified {
                min,
                max,
                verbose,
                pos,
                ..
            } if *min == 1 && *max == Some(1) => {
                sink.emit_span(
                    RuleScope::Both,
                    "S6353",
                    &format!("Remove redundant quantifier {verbose}."),
                    site.sub_span(*pos, *pos),
                );
            }
            PatternNode::Class {
                items, start, end, ..
            } => {
                emit_concise_class_rewrite(sink, site, items, *start, *end);
            }
            _ => {}
        });
    }
}

/// Concise-form rewrite for classes made solely of duplicated single chars
/// (`[aa]` → `[a]`), following the upstream message shape.
fn emit_concise_class_rewrite(
    sink: &mut IssueSink,
    site: &RegexSite,
    items: &[ClassItem],
    start: usize,
    end: usize,
) {
    let mut unique: Vec<char> = Vec::new();
    for item in items {
        let ClassItem::Char { ch, .. } = item else {
            return; // mixed shapes have no single concise form in subset scope
        };
        if !unique.contains(ch) {
            unique.push(*ch);
        }
    }
    if unique.len() == items.len() {
        return; // no duplicates, nothing to rewrite
    }
    let expected: String = unique.iter().collect();
    let actual = &site.pattern[start..end];
    sink.emit_span(
        RuleScope::Both,
        "S6353",
        &format!("Use concise character class syntax '[{expected}]' instead of '{actual}'."),
        site.sub_span(start, end),
    );
}

/// `S6326`: runs of two or more spaces outside character classes.
fn check_space_runs(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        for_every_sequence(alternative, &mut |sequence| {
            emit_space_runs_in_sequence(sink, site, sequence);
        });
    }
}

fn emit_space_runs_in_sequence(sink: &mut IssueSink, site: &RegexSite, sequence: &[PatternNode]) {
    let mut run: Option<(usize, u32)> = None; // (start offset, length)
    for node in sequence {
        match node {
            PatternNode::Literal { ch: ' ', pos } => {
                run = Some(match run {
                    Some((start, len)) => (start, len + 1),
                    None => (*pos, 1),
                });
            }
            _ => flush_space_run(sink, site, run.take()),
        }
    }
    flush_space_run(sink, site, run.take());
}

fn flush_space_run(sink: &mut IssueSink, site: &RegexSite, run: Option<(usize, u32)>) {
    let Some((start, len)) = run.filter(|&(_, length)| length >= 2) else {
        return;
    };
    let end = start + usize::try_from(len).unwrap_or(usize::MAX);
    sink.emit_span(
        RuleScope::Both,
        "S6326",
        &format!("If multiple spaces are required here, use number quantifier ({{{len}}})."),
        site.sub_span(start, end),
    );
}

/// `S5842`: a consuming quantifier over an empty-matchable group loops
/// forever (`(a*)+`). Subset: `min >= 1` over non-lookaround groups.
fn check_empty_string_repetition(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Quantified {
                min,
                node: target,
                pos,
                ..
            } = node
                && *min >= 1
                && let PatternNode::Group {
                    kind, alternatives, ..
                } = target.as_ref()
                && !kind.is_lookaround()
                && alternatives
                    .iter()
                    .any(|branch| sequence_can_match_empty(branch))
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S5842",
                    "Rework this part of the regex to not match the empty string.",
                    site.sub_span(*pos, *pos),
                );
            }
        });
    }
}

/// `S6019`: a reluctant quantifier directly followed by something that can
/// match empty renders the laziness pointless.
fn check_pointless_reluctant_quantifier(
    sink: &mut IssueSink,
    site: &RegexSite,
    parsed: &ParsedRegex,
) {
    for alternative in &parsed.alternatives {
        for_every_sequence(alternative, &mut |sequence| {
            for pair in sequence.windows(2) {
                if let PatternNode::Quantified {
                    greedy: false,
                    min,
                    pos,
                    ..
                } = pair[0]
                    && node_can_match_empty(&pair[1])
                {
                    let plural = if min == 1 { "" } else { "s" };
                    sink.emit_span(
                        RuleScope::Both,
                        "S6019",
                        &format!(
                            "Fix this reluctant quantifier that will only ever match {min} repetition{plural}."
                        ),
                        site.sub_span(pos, pos),
                    );
                }
            }
        });
    }
}

/// `S6035`: every branch of an alternation being one literal char is a
/// character class in disguise (`a|b|c`).
fn check_single_char_alternation(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    flag_single_char_alternation(sink, &parsed.alternatives, site.whole_pattern_span());
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Group {
                alternatives,
                start,
                end,
                ..
            } = node
            {
                flag_single_char_alternation(sink, alternatives, site.sub_span(*start, *end));
            }
        });
    }
}

fn flag_single_char_alternation(
    sink: &mut IssueSink,
    alternatives: &[Vec<PatternNode>],
    span: Span,
) {
    let all_single_char = alternatives.len() > 1
        && alternatives
            .iter()
            .all(|branch| matches!(branch.as_slice(), [PatternNode::Literal { .. }]));
    if all_single_char {
        sink.emit_span(
            RuleScope::Both,
            "S6035",
            "Replace this alternation with a character class.",
            span,
        );
    }
}

/// `S5850`: `^a|b$` — anchors under a top-level alternation bind to one
/// branch only unless the branches are grouped.
fn check_anchor_precedence(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    if parsed.alternatives.len() < 2 {
        return;
    }
    let starts_anchored = matches!(
        parsed.alternatives[0].first(),
        Some(PatternNode::Anchor {
            kind: AnchorKind::Start,
            ..
        })
    );
    let ends_anchored = matches!(
        parsed.alternatives.last().and_then(|branch| branch.last()),
        Some(PatternNode::Anchor {
            kind: AnchorKind::End,
            ..
        })
    );
    if !(starts_anchored || ends_anchored) {
        return;
    }
    let pos = if starts_anchored {
        match parsed.alternatives[0].first() {
            Some(PatternNode::Anchor { pos, .. }) => *pos,
            _ => 0,
        }
    } else {
        match parsed.alternatives.last().and_then(|branch| branch.last()) {
            Some(PatternNode::Anchor { pos, .. }) => *pos,
            _ => 0,
        }
    };
    sink.emit_span(
        RuleScope::Both,
        "S5850",
        "Group parts of the regex together to make the intended operator precedence explicit.",
        site.sub_span(pos, pos),
    );
}

/// Grapheme components that silently truncate inside a character class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GraphemeComponentKind {
    CombiningMark,
    JoinSequence,
    ModifiedEmoji,
    RegionalIndicator,
}

fn grapheme_component_kind(ch: char) -> Option<GraphemeComponentKind> {
    let kind = match ch {
        '\u{0300}'..='\u{036F}'
        | '\u{1AB0}'..='\u{1AFF}'
        | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20F0}'
        | '\u{FE20}'..='\u{FE2F}' => GraphemeComponentKind::CombiningMark,
        '\u{200D}' => GraphemeComponentKind::JoinSequence,
        '\u{FE00}'..='\u{FE0F}' | '\u{1F3FB}'..='\u{1F3FF}' => GraphemeComponentKind::ModifiedEmoji,
        '\u{1F1E6}'..='\u{1F1FF}' => GraphemeComponentKind::RegionalIndicator,
        _ => return None,
    };
    Some(kind)
}

/// `S5868`: combining marks, ZWJ sequences, variation selectors, skin-tone
/// modifiers, and regional indicators inside `[...]` match one scalar, not
/// the grapheme the pattern author sees. Subset: UTF-16 surrogate pairs
/// cannot appear as `char`s and stay out of scope.
fn check_misleading_class_characters(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            let PatternNode::Class { start, end, .. } = node else {
                return;
            };
            let Some(slice) = site.pattern.get(*start..*end) else {
                return;
            };
            // Skip the leading `[`, plus `^` for negated classes.
            let skip = usize::from(slice.starts_with("[^")) + 1;
            for (relative, ch) in slice.char_indices().skip(skip) {
                let Some(kind) = grapheme_component_kind(ch) else {
                    continue;
                };
                let message = match kind {
                    GraphemeComponentKind::CombiningMark => format!(
                        "Move this Unicode combined character '{ch}' outside of the character class"
                    ),
                    GraphemeComponentKind::JoinSequence => String::from(
                        "Move this Unicode joined character sequence outside of the character class",
                    ),
                    GraphemeComponentKind::ModifiedEmoji => format!(
                        "Move this Unicode modified Emoji '{ch}' outside of the character class"
                    ),
                    GraphemeComponentKind::RegionalIndicator => format!(
                        "Move this Unicode regional indicator '{ch}' outside of the character class"
                    ),
                };
                let absolute = start + relative;
                sink.emit_span(
                    RuleScope::Both,
                    "S5868",
                    &message,
                    site.sub_span(absolute, absolute + ch.len_utf8()),
                );
            }
        });
    }
}

/// `S5843`: complexity budget exceeded (subset scoring, see
/// [`pattern_complexity`]).
fn check_regex_complexity(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    let score = pattern_complexity(&parsed.alternatives);
    if score > REGEX_COMPLEXITY_THRESHOLD {
        sink.emit_span(
            RuleScope::Both,
            "S5843",
            &format!(
                "Simplify this regular expression to reduce its complexity from {score} to the {REGEX_COMPLEXITY_THRESHOLD} allowed."
            ),
            site.whole_pattern_span(),
        );
    }
}

/// `S5852`: unbounded quantifiers nested inside unbounded quantifiers
/// (`(a+)+`) risk exponential backtracking. Conservative subset: any
/// containment counts; disjointness analysis stays out of scope.
fn check_exponential_backtracking(sink: &mut IssueSink, site: &RegexSite, parsed: &ParsedRegex) {
    for alternative in &parsed.alternatives {
        walk_pattern_nodes(alternative, &mut |node| {
            if let PatternNode::Quantified {
                max: None,
                node: target,
                pos,
                ..
            } = node
                && contains_unbounded_quantifier(target)
            {
                sink.emit_span(
                    RuleScope::Both,
                    "S5852",
                    "Fix this regular expression that is vulnerable to exponential backtracking, as it can lead to denial of service.",
                    site.sub_span(*pos, *pos),
                );
            }
        });
    }
}

fn contains_unbounded_quantifier(node: &PatternNode) -> bool {
    match node {
        PatternNode::Quantified { max: None, .. } => true,
        PatternNode::Quantified { node: inner, .. } => contains_unbounded_quantifier(inner),
        PatternNode::Group { alternatives, .. } => alternatives
            .iter()
            .flatten()
            .any(contains_unbounded_quantifier),
        _ => false,
    }
}

/// `S6324`: bare C0 control characters other than the tab/newline
/// conventions.
fn check_control_characters(sink: &mut IssueSink, site: &RegexSite) {
    for (offset, ch) in site.pattern.char_indices() {
        if is_bare_control_character(ch) {
            sink.emit_span(
                RuleScope::Both,
                "S6324",
                "Remove this control character.",
                site.sub_span(offset, offset + ch.len_utf8()),
            );
        }
    }
}

fn is_bare_control_character(ch: char) -> bool {
    matches!(
        ch,
        '\0'..='\u{0008}' | '\u{000B}' | '\u{000C}' | '\u{000E}'..='\u{001F}'
    )
}

/// `S5867`: `\p{…}` / `\P{…}` / `\u{…}` without the `u` (or `v`) flag
/// behave nothing like their intent.
fn check_unicode_constructs_without_u_flag(sink: &mut IssueSink, site: &RegexSite) {
    if site.has_flag('u') || site.has_flag('v') {
        return;
    }
    for construct in ["\\p{", "\\P{", "\\u{"] {
        let mut search_from = 0;
        while let Some(found) = site.pattern[search_from..].find(construct) {
            let start = search_from + found;
            let end = start + construct.len();
            sink.emit_span(
                RuleScope::Both,
                "S5867",
                "Enable the 'u' flag for this regex using Unicode constructs.",
                site.sub_span(start, end),
            );
            search_from = end;
        }
    }
}

// ----- Context-sensitive family members -----

/// One `$n` / `$<name>` reference found in a replacement string.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GroupReference {
    Index(u32),
    Name(String),
}

/// Scans replacement-string text for group references; `$$` escapes are
/// skipped and numeric references take up to two digits, like JavaScript.
fn replacement_group_references(text: &str) -> Vec<GroupReference> {
    let bytes = text.as_bytes();
    let mut references = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'$') {
            i += 2;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'<')
            && let Some(close) = text[i + 2..].find('>')
        {
            let name = &text[i + 2..i + 2 + close];
            if !name.is_empty() {
                references.push(GroupReference::Name(name.to_string()));
                i += close + 3;
                continue;
            }
        }
        let digits = bytes[i + 1..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count()
            .min(2);
        if digits > 0 {
            references.push(GroupReference::Index(
                text[i + 1..i + 1 + digits].parse().unwrap_or(u32::MAX),
            ));
            i += digits + 1;
            continue;
        }
        i += 1;
    }
    references
}

/// `S6328`: replacement strings referencing groups the paired regex never
/// captures.
fn check_replacement_groups(
    sink: &mut IssueSink,
    replacement_span: Span,
    text: &str,
    parsed: &ParsedRegex,
) {
    let invalid: Vec<String> = replacement_group_references(text)
        .into_iter()
        .filter(|reference| !reference_exists(reference, parsed))
        .map(|reference| match reference {
            GroupReference::Index(index) => format!("${index}"),
            GroupReference::Name(name) => format!("$<{name}>"),
        })
        .collect();
    if invalid.is_empty() {
        return;
    }
    let plural = if invalid.len() == 1 { "" } else { "s" };
    sink.emit_span(
        RuleScope::Both,
        "S6328",
        &format!(
            "Referencing non-existing group{plural}: {}.",
            invalid.join(", ")
        ),
        replacement_span,
    );
}

fn reference_exists(reference: &GroupReference, parsed: &ParsedRegex) -> bool {
    match reference {
        GroupReference::Index(index) => {
            *index > 0 && u32::try_from(parsed.capture_count).is_ok_and(|count| *index <= count)
        }
        GroupReference::Name(name) => parsed.capture_names.iter().any(|known| known == name),
    }
}

/// Calls `f` for every sequence in the tree — groups' alternatives and
/// quantified targets included; class internals excluded.
fn for_every_sequence(sequence: &[PatternNode], f: &mut dyn FnMut(&[PatternNode])) {
    f(sequence);
    for node in sequence {
        match node {
            PatternNode::Group { alternatives, .. } => {
                for alternative in alternatives {
                    for_every_sequence(alternative, f);
                }
            }
            PatternNode::Quantified { node: inner, .. } => {
                for_every_sequence(std::slice::from_ref(inner.as_ref()), f);
            }
            _ => {}
        }
    }
}

/// Drives [`check_constant_regex_site`] over every constant regex and adds
/// the context-sensitive rules: `S6325` (constructor preference), `S6328`
/// (replacement groups), and `S6351` (stateful global regexes in loops).
struct RegexFamilyCollector<'index> {
    sink: IssueSink<'index>,
    loop_depth: u32,
}

impl RegexFamilyCollector<'_> {
    /// `S6325`: a fully constant `RegExp` constructor call prefers literal
    /// notation (upstream `prefer-regex-literals` primary message).
    fn check_constructor(&mut self, arguments: &[oxc_ast::ast::Argument<'_>], span: Span) {
        let Some(site) = constructor_regex_site(arguments) else {
            return;
        };
        self.sink.emit_span(
            RuleScope::Both,
            "S6325",
            "Use a regular expression literal instead of the 'RegExp' constructor.",
            span,
        );
        check_constant_regex_site(&mut self.sink, &site);
    }

    /// `S6328`: `.replace(/…/, "…")` pairs cross-check replacement group
    /// references against the pattern's captures.
    fn check_replacement_pair(&mut self, call: &CallExpression<'_>) {
        let Some(regex) = regex_literal_argument(call.arguments.first()) else {
            return;
        };
        let Some(replacement) = call.arguments.get(1) else {
            return;
        };
        let Some(text) = literal_string_value(replacement) else {
            return;
        };
        let flags = regex_flags_text(regex.regex.flags);
        let unicode_mode = flags.contains('u') || flags.contains('v');
        if let Ok(parsed) = parse_regex_pattern(regex.regex.pattern.text.as_str(), unicode_mode) {
            check_replacement_groups(&mut self.sink, replacement.span(), &text, &parsed);
        }
    }

    /// `S6351` subset: a `/g` regex literal feeding `.test()` or `.exec()`
    /// inside a loop carries hidden `lastIndex` state.
    fn check_stateful_global_regex(&mut self, object_member: &MemberExpression<'_>, span: Span) {
        if self.loop_depth == 0 {
            return;
        }
        let Expression::RegExpLiteral(literal) = unparenthesized(member_object(object_member))
        else {
            return;
        };
        if literal.regex.flags.contains(RegExpFlags::G) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6351",
                "Extract this regular expression to avoid infinite loop.",
                span,
            );
        }
    }
}

impl Visit<'_> for RegexFamilyCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'_>) {
        if let Expression::RegExpLiteral(literal) = it {
            let site = regex_site_from_literal(literal);
            check_constant_regex_site(&mut self.sink, &site);
        }
        walk_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'_>) {
        if constructor_name(it) == Some("RegExp") {
            self.check_constructor(&it.arguments, it.span());
        }
        walk_new_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'_>) {
        if callee_name(it) == Some("RegExp") {
            self.check_constructor(&it.arguments, it.span());
        }
        if let Some((property, member)) = call_property(it) {
            match property {
                "replace" | "replaceAll" => self.check_replacement_pair(it),
                "test" | "exec" => self.check_stateful_global_regex(member, it.span()),
                _ => {}
            }
        }
        walk_call_expression(self, it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'_>) {
        self.loop_depth += 1;
        walk_for_statement(self, it);
        self.loop_depth -= 1;
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'_>) {
        self.loop_depth += 1;
        walk_for_in_statement(self, it);
        self.loop_depth -= 1;
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'_>) {
        self.loop_depth += 1;
        walk_for_of_statement(self, it);
        self.loop_depth -= 1;
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'_>) {
        self.loop_depth += 1;
        walk_while_statement(self, it);
        self.loop_depth -= 1;
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'_>) {
        self.loop_depth += 1;
        walk_do_while_statement(self, it);
        self.loop_depth -= 1;
    }
}

/// All Batch3 regex-family checks in one traversal: the shared pattern
/// walker over `S5856`, `S2639`, `S6323`, `S6331`, `S5869`, `S6397`,
/// `S6353`, `S6326`, `S6324`, `S5842`, `S6019`, `S6035`, `S5850`, `S5867`,
/// `S5868`, `S5843`, and `S5852`, plus context rules `S6325`, `S6328`, and
/// `S6351`.
fn check_regex_family(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = RegexFamilyCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        loop_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

// ===== Batch4 group R1: React/JSX structural rules =====
//
// `S6748` (children prop + nested children), `S6761` (children +
// dangerouslySetInnerHTML), `S6749` (single-child fragments), `S6750`
// (consumed `ReactDOM.render` results), `S6754` (asymmetric `useState`
// pairs), `S6443` (no-op state setters), `S6788` (`findDOMNode`),
// `S6789` (`isMounted`), and `S6790`/`S6791`. Group R2 adds `S6957`
// (deprecated React APIs), `S6763` (PureComponent updates), `S6746`
// (state mutation), `S6766` (unescaped entities), `S6438` (empty
// containers), `S6480` (inline function props), `S6477`/`S6479`
// (map keys), `S6770` (unknown lowercase tags), `S6435` (render return),
// and `S6439` (literal conditionals).

use oxc_allocator::ArenaVec;
use oxc_ast::ast::{
    JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXChild, JSXElement, JSXElementName,
    JSXExpression, JSXExpressionContainer, JSXFragment, JSXOpeningElement, JSXText,
    PropertyDefinition, ThisExpression,
};
use oxc_ast_visit::walk::{
    walk_jsx_children, walk_jsx_element, walk_jsx_expression_container, walk_jsx_fragment,
    walk_jsx_text, walk_property_definition, walk_statement, walk_this_expression,
};

/// `S6791`: pre-16.3 lifecycle names superseded by `UNSAFE_`-prefixed ones.
const LEGACY_LIFECYCLE_METHODS: [&str; 3] = [
    "componentWillMount",
    "componentWillReceiveProps",
    "componentWillUpdate",
];

/// Known intrinsic tag names (`S6770`): HTML plus a common SVG surface.
const HTML_TAG_ALLOWLIST: &[&str] = &[
    "a",
    "abbr",
    "acronym",
    "address",
    "animate",
    "animateMotion",
    "animateTransform",
    "applet",
    "area",
    "article",
    "aside",
    "audio",
    "b",
    "base",
    "basefont",
    "bdi",
    "bdo",
    "big",
    "blockquote",
    "body",
    "br",
    "button",
    "canvas",
    "caption",
    "circle",
    "cite",
    "clipPath",
    "code",
    "col",
    "colgroup",
    "data",
    "datalist",
    "dd",
    "defs",
    "del",
    "desc",
    "details",
    "dfn",
    "dialog",
    "dir",
    "div",
    "dl",
    "dt",
    "ellipse",
    "em",
    "embed",
    "feBlend",
    "feColorMatrix",
    "feComponentTransfer",
    "feComposite",
    "feConvolveMatrix",
    "feDiffuseLighting",
    "feDisplacementMap",
    "feDistantLight",
    "feDropShadow",
    "feFlood",
    "feFuncA",
    "feFuncB",
    "feFuncG",
    "feFuncR",
    "feGaussianBlur",
    "feImage",
    "feMerge",
    "feMergeNode",
    "feMorphology",
    "feOffset",
    "fePointLight",
    "feSpecularLighting",
    "feSpotLight",
    "feTile",
    "feTurbulence",
    "fieldset",
    "figcaption",
    "figure",
    "filter",
    "font",
    "footer",
    "foreignObject",
    "form",
    "frame",
    "frameset",
    "g",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "head",
    "header",
    "hgroup",
    "hr",
    "html",
    "i",
    "iframe",
    "image",
    "img",
    "input",
    "ins",
    "kbd",
    "label",
    "legend",
    "li",
    "line",
    "linearGradient",
    "link",
    "main",
    "map",
    "mark",
    "marker",
    "marquee",
    "mask",
    "menu",
    "menuitem",
    "meta",
    "metadata",
    "meter",
    "mpath",
    "nav",
    "nobr",
    "noframes",
    "noscript",
    "object",
    "ol",
    "optgroup",
    "option",
    "output",
    "p",
    "param",
    "path",
    "pattern",
    "picture",
    "polygon",
    "polyline",
    "pre",
    "progress",
    "q",
    "radialGradient",
    "rect",
    "rp",
    "rt",
    "ruby",
    "s",
    "samp",
    "script",
    "search",
    "section",
    "select",
    "set",
    "slot",
    "small",
    "solidcolor",
    "source",
    "span",
    "stop",
    "strike",
    "strong",
    "style",
    "sub",
    "summary",
    "sup",
    "svg",
    "symbol",
    "table",
    "tbody",
    "td",
    "template",
    "text",
    "textPath",
    "textarea",
    "tfoot",
    "th",
    "thead",
    "time",
    "title",
    "tr",
    "track",
    "tspan",
    "tt",
    "u",
    "ul",
    "use",
    "var",
    "video",
    "view",
    "wbr",
];

/// In-place array mutations flagged on `this.state` chains (`S6746`).
const STATE_MUTATION_METHODS: [&str; 9] = [
    "push",
    "pop",
    "shift",
    "unshift",
    "splice",
    "sort",
    "reverse",
    "fill",
    "copyWithin",
];

/// Tags whose adjacent collapsible whitespace behaves inconsistently
/// (`S6772`).
const INLINE_TAGS: [&str; 36] = [
    "a", "abbr", "b", "bdi", "bdo", "br", "button", "cite", "code", "data", "dfn", "em", "i",
    "img", "input", "kbd", "label", "mark", "q", "rp", "rt", "ruby", "s", "samp", "select", "slot",
    "small", "span", "strong", "sub", "sup", "time", "u", "textarea", "var", "wbr",
];

/// Known DOM and React attribute names (`S6747`). Event handlers (`on*`),
/// `data-*`/`aria-*` attributes, and the configured `whitelist` extend this
/// table.
const REACT_DOM_ATTRIBUTES: &[&str] = &[
    "accept",
    "acceptCharset",
    "accessKey",
    "action",
    "allowFullScreen",
    "alt",
    "async",
    "autoComplete",
    "autoFocus",
    "autoPlay",
    "autoSave",
    "capture",
    "cellPadding",
    "cellSpacing",
    "challenge",
    "charSet",
    "checked",
    "children",
    "className",
    "cite",
    "classId",
    "clipPath",
    "colSpan",
    "cols",
    "content",
    "contentEditable",
    "controls",
    "controlsList",
    "coords",
    "crossOrigin",
    "dangerouslySetInnerHTML",
    "dateTime",
    "decoding",
    "default",
    "defaultChecked",
    "defaultValue",
    "defer",
    "dir",
    "dirName",
    "disabled",
    "disablePictureInPicture",
    "disableRemotePlayback",
    "download",
    "draggable",
    "encType",
    "enterKeyHint",
    "fetchPriority",
    "form",
    "formAction",
    "formEncType",
    "formMethod",
    "formNoValidate",
    "formTarget",
    "frameBorder",
    "headers",
    "height",
    "hidden",
    "high",
    "href",
    "hrefLang",
    "htmlFor",
    "httpEquiv",
    "icon",
    "id",
    "inputMode",
    "integrity",
    "is",
    "itemID",
    "itemProp",
    "itemRef",
    "itemScope",
    "itemType",
    "key",
    "keyParams",
    "keyType",
    "kind",
    "label",
    "lang",
    "list",
    "loading",
    "loop",
    "low",
    "manifest",
    "marginHeight",
    "marginWidth",
    "max",
    "maxLength",
    "media",
    "mediaGroup",
    "method",
    "min",
    "minLength",
    "multiple",
    "muted",
    "name",
    "nonce",
    "noValidate",
    "open",
    "optimum",
    "pattern",
    "placeholder",
    "playsInline",
    "poster",
    "preload",
    "profile",
    "radioGroup",
    "readOnly",
    "referrerPolicy",
    "ref",
    "rel",
    "required",
    "reversed",
    "role",
    "rows",
    "rowSpan",
    "sandbox",
    "scope",
    "scoped",
    "scrolling",
    "seamless",
    "selected",
    "shape",
    "size",
    "sizes",
    "slot",
    "span",
    "spellCheck",
    "src",
    "srcDoc",
    "srcLang",
    "srcSet",
    "start",
    "step",
    "style",
    "summary",
    "suppressContentEditableWarning",
    "suppressHydrationWarning",
    "tabIndex",
    "target",
    "title",
    "translate",
    "type",
    "useMap",
    "value",
    "width",
    "wmode",
    "wrap",
    // Common SVG surface.
    "alignmentBaseline",
    "attributeName",
    "azimuth",
    "baseFrequency",
    "baselineShift",
    "baseProfile",
    "bbox",
    "begin",
    "by",
    "calcMode",
    "capHeight",
    "clipRule",
    "clipPathUnits",
    "colorInterpolation",
    "colorInterpolationFilters",
    "colorProfile",
    "colorRendering",
    "cursor",
    "cx",
    "cy",
    "d",
    "decelerate",
    "descent",
    "diffuseConstant",
    "direction",
    "display",
    "divisor",
    "dominantBaseline",
    "dur",
    "dx",
    "dy",
    "edgeMode",
    "elevation",
    "enableBackground",
    "end",
    "exponent",
    "externalResourcesRequired",
    "fill",
    "fillOpacity",
    "fillRule",
    "filter",
    "filterRes",
    "filterUnits",
    "floodColor",
    "floodOpacity",
    "focusable",
    "fontFamily",
    "fontSize",
    "fontSizeAdjust",
    "fontStretch",
    "fontStyle",
    "fontVariant",
    "fontWeight",
    "format",
    "from",
    "fr",
    "fx",
    "fy",
    "g1",
    "g2",
    "glyphName",
    "glyphOrientationHorizontal",
    "glyphOrientationVertical",
    "gradientTransform",
    "gradientUnits",
    "hanging",
    "horizAdvX",
    "horizOriginX",
    "ideographic",
    "in",
    "in2",
    "intercept",
    "k",
    "k1",
    "k2",
    "k3",
    "k4",
    "kernelMatrix",
    "kernelUnitLength",
    "keyPoints",
    "keySplines",
    "keyTimes",
    "lengthAdjust",
    "letterSpacing",
    "lightingColor",
    "limitingConeAngle",
    "local",
    "markerEnd",
    "markerHeight",
    "markerMid",
    "markerStart",
    "markerUnits",
    "markerWidth",
    "mask",
    "maskContentUnits",
    "maskUnits",
    "mathematical",
    "mode",
    "numOctaves",
    "offset",
    "opacity",
    "operator",
    "order",
    "orient",
    "orientation",
    "origin",
    "overflow",
    "overlinePosition",
    "overlineThickness",
    "paintOrder",
    "panose1",
    "pathLength",
    "patternContentUnits",
    "patternTransform",
    "patternUnits",
    "ping",
    "points",
    "pointsAtX",
    "pointsAtY",
    "pointsAtZ",
    "preserveAlpha",
    "preserveAspectRatio",
    "primitiveUnits",
    "r",
    "radius",
    "repeatCount",
    "repeatDur",
    "requiredExtensions",
    "requiredFeatures",
    "restart",
    "result",
    "rotate",
    "rx",
    "ry",
    "scale",
    "seed",
    "shapeRendering",
    "side",
    "slope",
    "spacing",
    "specularConstant",
    "specularExponent",
    "speed",
    "spreadMethod",
    "startOffset",
    "stdDeviation",
    "stemh",
    "stemv",
    "stitchTiles",
    "stopColor",
    "stopOpacity",
    "strikethroughPosition",
    "strikethroughThickness",
    "string",
    "stroke",
    "strokeDasharray",
    "strokeDashoffset",
    "strokeLinecap",
    "strokeLinejoin",
    "strokeMiterlimit",
    "strokeOpacity",
    "strokeWidth",
    "surfaceScale",
    "systemLanguage",
    "tableValues",
    "targetX",
    "targetY",
    "textAnchor",
    "textDecoration",
    "textLength",
    "textRendering",
    "to",
    "transform",
    "transformOrigin",
    "u1",
    "u2",
    "underlinePosition",
    "underlineThickness",
    "unicode",
    "unicodeBidi",
    "unicodeRange",
    "unitsPerEm",
    "vAlphabetic",
    "vHanging",
    "vIdeographic",
    "vMathematical",
    "values",
    "vectorEffect",
    "version",
    "vertAdvY",
    "vertOriginX",
    "vertOriginY",
    "viewBox",
    "viewTarget",
    "visibility",
    "wordSpacing",
    "writingMode",
    "x",
    "x1",
    "x2",
    "xChannelSelector",
    "xHeight",
    "xlinkActuate",
    "xlinkArcrole",
    "xlinkHref",
    "xlinkRole",
    "xlinkShow",
    "xlinkTitle",
    "xlinkType",
    "xmlBase",
    "xmlLang",
    "xmlSpace",
    "xmlns",
    "xmlnsXlink",
    "y",
    "y1",
    "y2",
    "yChannelSelector",
    "zoomAndPan",
];

/// React/JSX structural rules in one traversal. Context stacks track
/// expression statements (`S6750`), `.map()` callbacks (`S6477`/`S6479`),
/// component nesting (`S6478`/`S6757`), and conditional/hook positions
/// (`S6440`); `source` backs the comment probe of `S6438`. The prop maps
/// feed the `S6775` post-pass.
struct ReactCollector<'index> {
    sink: IssueSink<'index>,
    source: &'index str,
    rules: &'index RuleOptions,
    expression_statement_depth: usize,
    jsx_child_depth: usize,
    conditional_depth: usize,
    map_frames: Vec<MapFrame>,
    component_stack: Vec<bool>,
    class_depth: usize,
    method_guard: usize,
    prop_declarations: BTreeMap<String, BTreeMap<String, PropKind>>,
    prop_defaults: BTreeMap<String, BTreeMap<String, Span>>,
}

/// Whether a collected `propTypes` entry is declared `.isRequired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropKind {
    Optional,
    Required,
}

/// One `.map(callback)` traversal frame: the callback's second parameter
/// name (the array index) and whether its root element was already checked.
struct MapFrame {
    index_param: Option<String>,
    root_checked: bool,
}

impl<'a> Visit<'a> for ReactCollector<'_> {
    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'_>) {
        self.expression_statement_depth += 1;
        walk_expression_statement(self, it);
        self.expression_statement_depth -= 1;
    }

    fn visit_jsx_element(&mut self, it: &JSXElement<'_>) {
        self.check_map_root_key(it);
        self.check_element_rules(it);
        self.check_inline_function_values(it);
        self.check_index_key(it);
        self.check_unknown_tag(it);
        self.check_context_provider_value(it);
        self.check_unknown_attributes(it);
        walk_jsx_element(self, it);
    }

    fn visit_jsx_fragment(&mut self, it: &JSXFragment<'_>) {
        self.check_single_child_fragment(it);
        walk_jsx_fragment(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'_>) {
        self.check_react_dom_calls(it);
        self.check_noop_state_setter(it);
        self.check_state_mutation_call(it);
        self.check_set_state_argument(it);
        self.check_hook_call_site(it);
        let pushed_map_frame = match map_callback_frame(it) {
            Some(frame) => {
                self.map_frames.push(frame);
                true
            }
            None => false,
        };
        let argument_functions = call_argument_function_count(it);
        self.conditional_depth += argument_functions;
        walk_call_expression(self, it);
        self.conditional_depth -= argument_functions;
        if pushed_map_frame {
            self.map_frames.pop();
        }
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'_>) {
        self.check_use_state_pair(it);
        let frame = declarator_component_frame(it);
        if let Some((returns_jsx, name_span)) = frame {
            self.check_nested_component(returns_jsx, Some(name_span), it.span());
            self.component_stack.push(returns_jsx);
        }
        walk_variable_declarator(self, it);
        if frame.is_some() {
            self.component_stack.pop();
        }
    }

    fn visit_expression(&mut self, it: &Expression<'_>) {
        self.check_refs_access(it);
        walk_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'_>) {
        self.check_refs_write(it);
        self.check_state_mutation_assignment(it);
        self.collect_prop_metadata(it);
        walk_assignment_expression(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'_>) {
        self.method_guard += 1;
        self.check_legacy_lifecycle(it);
        walk_method_definition(self, it);
        self.method_guard -= 1;
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'_>) {
        self.method_guard += 1;
        walk_property_definition(self, it);
        self.method_guard -= 1;
    }

    fn visit_class(&mut self, it: &Class<'_>) {
        self.check_pure_component_update(it);
        self.check_render_method_return(it);
        self.check_props_without_prop_types(it);
        let is_component = class_returns_jsx(it);
        self.check_nested_component(is_component, it.id.as_ref().map(GetSpan::span), it.span());
        self.component_stack.push(is_component);
        self.class_depth += 1;
        walk_class(self, it);
        self.class_depth -= 1;
        self.component_stack.pop();
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'_>) {
        self.check_deprecated_import(it);
        walk_import_declaration(self, it);
    }

    fn visit_statement(&mut self, it: &Statement<'_>) {
        if let Statement::FunctionDeclaration(function) = it {
            let returns_jsx = function
                .body
                .as_ref()
                .is_some_and(|body| body_returns_jsx(body));
            self.check_nested_component(
                returns_jsx,
                function.id.as_ref().map(GetSpan::span),
                function.span(),
            );
            self.component_stack.push(returns_jsx);
        }
        walk_statement(self, it);
        if let Statement::FunctionDeclaration(_) = it {
            self.component_stack.pop();
        }
    }
    fn visit_this_expression(&mut self, it: &ThisExpression) {
        if self.method_guard == 0
            && self.class_depth == 0
            && self.component_stack.last() == Some(&true)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6757",
                "'this' is undefined inside a functional component; capture the needed values instead.",
                it.span(),
            );
        }
        walk_this_expression(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'_>) {
        self.conditional_depth += 1;
        walk_if_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'_>) {
        self.conditional_depth += 1;
        walk_for_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'_>) {
        self.conditional_depth += 1;
        walk_for_in_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'_>) {
        self.conditional_depth += 1;
        walk_for_of_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'_>) {
        self.conditional_depth += 1;
        walk_while_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'_>) {
        self.conditional_depth += 1;
        walk_do_while_statement(self, it);
        self.conditional_depth -= 1;
    }

    fn visit_jsx_text(&mut self, it: &JSXText<'_>) {
        self.check_unescaped_entities(it);
        walk_jsx_text(self, it);
    }

    fn visit_jsx_expression_container(&mut self, it: &JSXExpressionContainer<'_>) {
        self.check_empty_container(it);
        self.check_literal_conditional_child(it);
        walk_jsx_expression_container(self, it);
    }

    fn visit_jsx_children(&mut self, it: &ArenaVec<'a, JSXChild<'a>>) {
        self.jsx_child_depth += 1;
        self.check_whitespace_only_gaps(it);
        walk_jsx_children(self, it);
        self.jsx_child_depth -= 1;
    }
}

impl ReactCollector<'_> {
    /// `S6748`, `S6761`, and the attribute half of `S6790`: conflicts
    /// between the `children` prop, `dangerouslySetInnerHTML`, and nested
    /// children, plus string `ref` attributes.
    fn check_element_rules(&mut self, element: &JSXElement<'_>) {
        let opening = &element.opening_element;
        let children_attribute = jsx_find_attribute(opening, "children");
        let raw_html_attribute = jsx_find_attribute(opening, "dangerouslySetInnerHTML");
        if let Some(attribute) = children_attribute
            && !element.children.is_empty()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6748",
                "Remove this 'children' prop; the component already receives nested children.",
                attribute.span(),
            );
        }
        if let (Some(_children), Some(raw_html)) = (children_attribute, raw_html_attribute) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6761",
                "Remove 'dangerouslySetInnerHTML' or the 'children' prop; using both together is redundant.",
                raw_html.span(),
            );
        }
        if let Some(attribute) = jsx_find_attribute(opening, "ref")
            && matches!(attribute.value, Some(JSXAttributeValue::StringLiteral(_)))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6790",
                "Replace this string ref with a callback ref.",
                attribute.span(),
            );
        }
    }

    fn check_single_child_fragment(&mut self, fragment: &JSXFragment<'_>) {
        let single_child = matches!(
            fragment.children.as_slice(),
            [JSXChild::Element(_) | JSXChild::ExpressionContainer(_)]
        );
        if single_child {
            self.sink.emit_span(
                RuleScope::Both,
                "S6749",
                "Remove this unnecessary fragment; it wraps a single child.",
                fragment.span(),
            );
        }
    }

    /// `S6750`, `S6788`, `S6789`, and the call half of `S6957`: deprecated
    /// `ReactDOM` entry points and `this.isMounted` probes.
    fn check_react_dom_calls(&mut self, call: &CallExpression<'_>) {
        if let Some((property, member)) = call_property(call) {
            let root = member_root_name(member);
            let is_render = root == Some("ReactDOM") && property == "render";
            let is_find_dom_node = root == Some("ReactDOM") && property == "findDOMNode";
            let is_create_class =
                (root == Some("React") || root == Some("ReactDOM")) && property == "createClass";
            if is_render && self.expression_statement_depth == 0 {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6750",
                    "'ReactDOM.render' should be called as a statement; do not consume its return value.",
                    call.span(),
                );
            }
            if is_find_dom_node {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6788",
                    "'ReactDOM.findDOMNode' is deprecated; use refs instead.",
                    call.span(),
                );
            }
            if is_render || is_find_dom_node || is_create_class {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6957",
                    "Remove this deprecated React API usage.",
                    call.span(),
                );
            }
        }
        if callee_this_property(call) == Some("isMounted") {
            self.sink.emit_span(
                RuleScope::Both,
                "S6789",
                "'this.isMounted' is deprecated and unreliable; track mounted state explicitly.",
                call.callee.span(),
            );
        }
    }

    /// `S6443`: `setX(x)` calls passing the state variable back to its own
    /// setter.
    fn check_noop_state_setter(&mut self, call: &CallExpression<'_>) {
        let Some(callee) = callee_name(call) else {
            return;
        };
        if !is_state_setter_name(callee) || call.arguments.len() != 1 {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Some(name) = identifier_name(argument) else {
            return;
        };
        if capitalize_first(name) == callee[3..] {
            self.sink.emit_span(
                RuleScope::Both,
                "S6443",
                "Pass a different value or an updater function; setting the state to itself changes nothing.",
                call.span(),
            );
        }
    }

    /// `S6754`: `useState` destructuring pairs follow the
    /// `[value, setValue]` naming convention.
    fn check_use_state_pair(&mut self, declarator: &VariableDeclarator<'_>) {
        let Some(Expression::CallExpression(call)) = &declarator.init else {
            return;
        };
        if callee_name(call) != Some("useState") {
            return;
        }
        if matches!(&declarator.id, BindingPattern::BindingIdentifier(_)) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6442",
                "Destructure the 'useState' result into a '[value, setter]' pair.",
                declarator.span(),
            );
            return;
        }
        let BindingPattern::ArrayPattern(array) = &declarator.id else {
            return;
        };
        if array.elements.len() != 2 || array.rest.is_some() {
            return;
        }
        let (Some(value), Some(setter)) = (&array.elements[0], &array.elements[1]) else {
            return;
        };
        let (Some(value), Some(setter)) = (
            binding_identifier_name(value),
            binding_identifier_name(setter),
        ) else {
            return;
        };
        if !is_state_setter_name(setter) || capitalize_first(value) != setter[3..] {
            self.sink.emit_span(
                RuleScope::Both,
                "S6754",
                "Rename this 'useState' pair to follow the '[value, setValue]' naming convention.",
                declarator.span(),
            );
        }
    }

    /// `S6790` read half: any member chain rooted at `this.refs`.
    fn check_refs_access(&mut self, expression: &Expression<'_>) {
        let Expression::StaticMemberExpression(member) = expression else {
            return;
        };
        if !matches!(&member.object, Expression::ThisExpression(_))
            || member.property.name != "refs"
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6790",
            "Replace 'this.refs' accesses with callback refs.",
            member.span(),
        );
    }

    /// `S6790` write half: assignments into `this.refs.*`.
    fn check_refs_write(&mut self, assignment: &AssignmentExpression<'_>) {
        let Some(SimpleAssignmentTarget::StaticMemberExpression(member)) =
            assignment.left.as_simple_assignment_target()
        else {
            return;
        };
        if !matches!(&member.object, Expression::ThisExpression(_))
            || member.property.name != "refs"
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6790",
            "Replace 'this.refs' accesses with callback refs.",
            member.span(),
        );
    }

    /// `S6791`: legacy lifecycle method names on class bodies.
    fn check_legacy_lifecycle(&mut self, method: &MethodDefinition<'_>) {
        if method.kind == MethodDefinitionKind::Constructor {
            return;
        }
        let Some(name) = duplicated_key_name(&method.key) else {
            return;
        };
        if LEGACY_LIFECYCLE_METHODS.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6791",
                "This legacy lifecycle method is deprecated; use the 'UNSAFE_'-prefixed version or refactor.",
                method.key.span(),
            );
        }
    }
    /// `S6957` import half: `prop-types` sources and `PropTypes` names.
    fn check_deprecated_import(&mut self, declaration: &ImportDeclaration<'_>) {
        let prop_types_import = declaration.source.value == "prop-types"
            || declaration
                .specifiers
                .iter()
                .flatten()
                .any(|specifier| match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(imported) => {
                        module_export_name_is(&imported.imported, "PropTypes")
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(defaulted) => {
                        defaulted.local.name == "PropTypes"
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(_) => false,
                });
        if prop_types_import {
            self.sink.emit_span(
                RuleScope::Both,
                "S6957",
                "Remove this deprecated React API usage; PropTypes checks vanish in production builds.",
                declaration.span(),
            );
        }
    }

    /// `S6763`: `shouldComponentUpdate` is pointless on `PureComponent`.
    fn check_pure_component_update(&mut self, class: &Class<'_>) {
        let Some(heritage) = &class.heritage else {
            return;
        };
        let pure_base = match &heritage.expression {
            Expression::Identifier(identifier) => identifier.name.ends_with("PureComponent"),
            Expression::StaticMemberExpression(member) => member.property.name == "PureComponent",
            _ => false,
        };
        if !pure_base {
            return;
        }
        for element in &class.body.body {
            let ClassElement::MethodDefinition(method) = element else {
                continue;
            };
            if duplicated_key_name(&method.key) != Some("shouldComponentUpdate") {
                continue;
            }
            self.sink.emit_span(
                RuleScope::Both,
                "S6763",
                "'shouldComponentUpdate' is useless on a PureComponent subclass; remove it.",
                method.key.span(),
            );
        }
    }

    /// `S6435`: class `render` methods must return JSX or null somewhere.
    fn check_render_method_return(&mut self, class: &Class<'_>) {
        for element in &class.body.body {
            let ClassElement::MethodDefinition(method) = element else {
                continue;
            };
            if duplicated_key_name(&method.key) != Some("render")
                || method.kind != MethodDefinitionKind::Method
            {
                continue;
            }
            let Some(body) = &method.value.body else {
                continue;
            };
            let mut scanner = RenderReturnScanner::default();
            scanner.visit_function_body(body);
            if !scanner.satisfied {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6435",
                    "Add a return statement returning JSX or null to this 'render' method.",
                    method.key.span(),
                );
            }
        }
    }

    /// `S6746` assignment half: writes into `this.state.*`.
    fn check_state_mutation_assignment(&mut self, assignment: &AssignmentExpression<'_>) {
        let through_state = match assignment.left.as_simple_assignment_target() {
            Some(SimpleAssignmentTarget::StaticMemberExpression(member)) => {
                (matches!(&member.object, Expression::ThisExpression(_))
                    && member.property.name == "state")
                    || expression_through_this_state(&member.object)
            }
            Some(SimpleAssignmentTarget::ComputedMemberExpression(member)) => {
                expression_through_this_state(&member.object)
            }
            _ => false,
        };
        if through_state {
            self.sink.emit_span(
                RuleScope::Both,
                "S6746",
                "Update state immutably; mutate a copy instead of 'this.state'.",
                assignment.left.span(),
            );
        }
    }

    /// `S6746` call half: in-place mutations on `this.state.*` chains.
    fn check_state_mutation_call(&mut self, call: &CallExpression<'_>) {
        let Some((property, member)) = call_property(call) else {
            return;
        };
        if STATE_MUTATION_METHODS.contains(&property)
            && expression_through_this_state(member_object(member))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6746",
                "Update state immutably; mutate a copy instead of 'this.state'.",
                call.span(),
            );
        }
    }

    /// `S6766`: raw quote characters in JSX text nodes. Raw `>` and `}`
    /// never reach the AST (the oxc lexer rejects them; the tolerant parse
    /// recovers with an empty program), so quotes are the flaggable subset.
    fn check_unescaped_entities(&mut self, text: &JSXText<'_>) {
        let unescaped = text
            .value
            .chars()
            .any(|ch| matches!(ch, '>' | '}' | '{' | '"' | '\''));
        if unescaped {
            self.sink.emit_span(
                RuleScope::Both,
                "S6766",
                "Escape this character in JSX text; use an HTML entity instead.",
                text.span(),
            );
        }
    }

    /// `S6438`: empty expression containers whose comment content was
    /// dropped by the lexer.
    fn check_empty_container(&mut self, container: &JSXExpressionContainer<'_>) {
        if !matches!(&container.expression, JSXExpression::EmptyExpression(_)) {
            return;
        }
        let span = container.span();
        if span_text_contains(self.source, span, "/*")
            || span_text_contains(self.source, span, "//")
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6438",
            "Remove this empty JSX expression container.",
            span,
        );
    }

    /// `S6439`: `{literal && <element/>}` children render the literal when
    /// the condition is falsy-but-present.
    fn check_literal_conditional_child(&mut self, container: &JSXExpressionContainer<'_>) {
        if self.jsx_child_depth == 0 {
            return;
        }
        let Some(Expression::LogicalExpression(logical)) = container.expression.as_expression()
        else {
            return;
        };
        if logical.operator != LogicalOperator::And
            || !matches!(
                logical.left,
                Expression::NumericLiteral(_)
                    | Expression::StringLiteral(_)
                    | Expression::BigIntLiteral(_)
            )
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6439",
            "This branch renders a literal; guard it with an explicit boolean condition.",
            container.span(),
        );
    }

    /// `S6480`: inline arrow or `.bind(...)` attribute values create a new
    /// function on every render.
    fn check_inline_function_values(&mut self, element: &JSXElement<'_>) {
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(JSXAttributeValue::ExpressionContainer(container)) = &attribute.value else {
                continue;
            };
            let inline = match container.expression.as_expression() {
                Some(Expression::ArrowFunctionExpression(_)) => true,
                Some(Expression::CallExpression(call)) => matches!(
                    &call.callee,
                    Expression::StaticMemberExpression(member) if member.property.name == "bind"
                ),
                _ => false,
            };
            if inline {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6480",
                    "Create this function outside of the render path; a fresh instance is created on every render.",
                    attribute.span(),
                );
            }
        }
    }

    /// `S6479`: `key={index}` where `index` is the surrounding `.map()`
    /// callback's second parameter.
    fn check_index_key(&mut self, element: &JSXElement<'_>) {
        let Some(index_param) = self
            .map_frames
            .last()
            .and_then(|frame| frame.index_param.clone())
        else {
            return;
        };
        let Some(key_attribute) = jsx_find_attribute(&element.opening_element, "key") else {
            return;
        };
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &key_attribute.value else {
            return;
        };
        let is_index_key = matches!(
            container.expression.as_expression(),
            Some(Expression::Identifier(reference)) if reference.name == index_param.as_str()
        );
        if is_index_key {
            self.sink.emit_span(
                RuleScope::Both,
                "S6479",
                "Avoid using the array index as the 'key'; use a stable identifier instead.",
                key_attribute.span(),
            );
        }
    }

    /// `S6770`: lowercase tag names that are neither DOM elements nor
    /// custom elements.
    fn check_unknown_tag(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if jsx_tag_is_intrinsic(tag) && !tag.contains('-') && !HTML_TAG_ALLOWLIST.contains(&tag) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6770",
                "Capitalize this component name; lowercase tags are treated as built-in DOM elements.",
                element.opening_element.name.span(),
            );
        }
    }

    /// `S6477`: root elements returned from `.map()` callbacks need keys.
    fn check_map_root_key(&mut self, element: &JSXElement<'_>) {
        let needs_key = match self.map_frames.last_mut() {
            Some(frame) if !frame.root_checked => {
                frame.root_checked = true;
                frame.index_param.is_some()
            }
            _ => return,
        };
        if !needs_key
            || jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "key").is_some()
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6477",
            "Add a 'key' prop to this element returned from '.map()'.",
            element.opening_element.span(),
        );
    }
    /// `S6440`: hook calls under conditions, loops, or callbacks.
    fn check_hook_call_site(&mut self, call: &CallExpression<'_>) {
        if self.conditional_depth == 0 {
            return;
        }
        let Some(callee) = callee_name(call) else {
            return;
        };
        let Some(tail) = callee.strip_prefix("use") else {
            return;
        };
        if !tail.starts_with(|ch: char| ch.is_ascii_uppercase()) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6440",
            "Move this hook call to the top level of the component; hooks must not run conditionally.",
            call.span(),
        );
    }

    /// `S6756`: `this.setState` arguments reaching into `this.state`
    /// instead of using the updater form.
    fn check_set_state_argument(&mut self, call: &CallExpression<'_>) {
        let is_method_call = matches!(
            &call.callee,
            Expression::StaticMemberExpression(member)
                if member.property.name == "setState"
                    && matches!(&member.object, Expression::ThisExpression(_))
        );
        if !is_method_call {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let mut scanner = ThisStateReferenceScanner::default();
        scanner.visit_expression(argument);
        if scanner.found {
            self.sink.emit_span(
                RuleScope::Both,
                "S6756",
                "Use the updater form of 'setState'; reading 'this.state' during the update misses batching.",
                call.span(),
            );
        }
    }

    /// `S6481`: inline objects or arrays passed as `Context.Provider`
    /// values.
    fn check_context_provider_value(&mut self, element: &JSXElement<'_>) {
        let JSXElementName::MemberExpression(member) = &element.opening_element.name else {
            return;
        };
        if member.property.name != "Provider" {
            return;
        }
        let Some(value_attribute) = jsx_find_attribute(&element.opening_element, "value") else {
            return;
        };
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &value_attribute.value else {
            return;
        };
        if matches!(
            container.expression.as_expression(),
            Some(Expression::ObjectExpression(_) | Expression::ArrayExpression(_))
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6481",
                "Pass a memoized 'value' instead of a fresh object or array literal.",
                value_attribute.span(),
            );
        }
    }

    /// `S6478`: components defined inside other components.
    fn check_nested_component(
        &mut self,
        returns_jsx: bool,
        name_span: Option<Span>,
        fallback_span: Span,
    ) {
        if !returns_jsx
            || !self.component_stack.iter().any(|&component| component)
            || self.method_guard > 0
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6478",
            "Define this component outside of its parent component.",
            name_span.unwrap_or(fallback_span),
        );
    }

    /// `S6772`: inline siblings separated only by collapsible whitespace.
    fn check_whitespace_only_gaps(&mut self, children: &[JSXChild<'_>]) {
        for window in children.windows(3) {
            let [first, middle, last] = window else {
                continue;
            };
            let (Some(first_tag), Some(last_tag)) =
                (jsx_child_element_tag(first), jsx_child_element_tag(last))
            else {
                continue;
            };
            if !INLINE_TAGS.contains(&first_tag) || !INLINE_TAGS.contains(&last_tag) {
                continue;
            }
            if let JSXChild::Text(text) = middle
                && !text.value.is_empty()
                && text.value.trim().is_empty()
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6772",
                    "Whitespace between these inline elements collapses inconsistently; make the separation explicit.",
                    text.span(),
                );
            }
        }
    }

    /// `S6774`: class components touching `this.props` without declared
    /// `propTypes` (JavaScript files only).
    fn check_props_without_prop_types(&mut self, class: &Class<'_>) {
        let declares_prop_types = class.body.body.iter().any(|element| {
            let ClassElement::PropertyDefinition(definition) = element else {
                return false;
            };
            definition.r#static && duplicated_key_name(&definition.key) == Some("propTypes")
        });
        if declares_prop_types {
            return;
        }
        let mut scanner = ThisPropsScanner::default();
        scanner.visit_class(class);
        if scanner.found {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S6774",
                "Declare 'propTypes' for this class component or migrate its props to types.",
                class.span(),
            );
        }
    }

    /// `S6747`: unknown attributes on intrinsic elements.
    fn check_unknown_attributes(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) {
            return;
        }
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            if attribute_is_known(name, &self.rules.jsx_attribute_whitelist) {
                continue;
            }
            let message = format!("'{name}' is not a known DOM or React attribute.");
            self.sink
                .emit_span(RuleScope::Both, "S6747", &message, attribute.span());
        }
    }

    /// `S6775` collection: records `X.propTypes` / `X.defaultProps`
    /// object assignments for the post-pass.
    fn collect_prop_metadata(&mut self, assignment: &AssignmentExpression<'_>) {
        if assignment.operator != AssignmentOperator::Assign {
            return;
        }
        let Some(SimpleAssignmentTarget::StaticMemberExpression(target)) =
            assignment.left.as_simple_assignment_target()
        else {
            return;
        };
        let Expression::ObjectExpression(object) = &assignment.right else {
            return;
        };
        let Some(component) = identifier_name(&target.object) else {
            return;
        };
        let kind = match target.property.name.as_str() {
            "propTypes" => PropSide::Declaration,
            "defaultProps" => PropSide::Default,
            _ => return,
        };
        for property_kind in &object.properties {
            let ObjectPropertyKind::ObjectProperty(property) = property_kind else {
                continue;
            };
            let Some(key) = duplicated_key_name(&property.key) else {
                continue;
            };
            match kind {
                PropSide::Declaration => {
                    let required = member_chain_has_link(&property.value, "isRequired");
                    let value = if required {
                        PropKind::Required
                    } else {
                        PropKind::Optional
                    };
                    self.prop_declarations
                        .entry(component.to_string())
                        .or_default()
                        .insert(key.to_string(), value);
                }
                PropSide::Default => {
                    self.prop_defaults
                        .entry(component.to_string())
                        .or_default()
                        .insert(key.to_string(), property.value.span());
                }
            }
        }
    }

    /// `S6775` post-pass: flags `defaultProps` entries without a matching
    /// `isRequired` declaration.
    fn report_uncovered_defaults(&mut self) {
        let mut uncovered = Vec::new();
        for (component, defaults) in &self.prop_defaults {
            let Some(declarations) = self.prop_declarations.get(component) else {
                continue;
            };
            for (property, span) in defaults {
                if declarations.get(property) != Some(&PropKind::Required) {
                    uncovered.push(*span);
                }
            }
        }
        for span in uncovered {
            self.sink.emit_span(
                RuleScope::Both,
                "S6775",
                "'defaultProps' entry without an 'isRequired' 'propTypes' declaration hides missing-prop mistakes.",
                span,
            );
        }
    }
}

/// Which side of the prop-metadata cross-check an assignment feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropSide {
    Declaration,
    Default,
}

/// Component frame for a declarator-initialized function or arrow:
/// whether it returns JSX plus its binding span (`S6478`).
fn declarator_component_frame(declarator: &VariableDeclarator<'_>) -> Option<(bool, Span)> {
    let init = declarator.init.as_ref()?;
    if !matches!(
        init,
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    ) {
        return None;
    }
    let returns_jsx = expression_returns_jsx(init)?;
    let name_span = match &declarator.id {
        BindingPattern::BindingIdentifier(identifier) => identifier.span(),
        _ => declarator.span(),
    };
    Some((returns_jsx, name_span))
}

/// Whether a function-like expression body returns JSX or null somewhere.
fn expression_returns_jsx(expression: &Expression<'_>) -> Option<bool> {
    match expression {
        Expression::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => Some(body_returns_jsx(body)),
            arrow_body => {
                let mut scanner = JsxOrNullScanner::default();
                if let Some(expression) = arrow_body.as_expression() {
                    scanner.visit_expression(expression);
                }
                Some(scanner.found)
            }
        },
        Expression::FunctionExpression(function) => {
            function.body.as_ref().map(|body| body_returns_jsx(body))
        }
        _ => None,
    }
}

/// Whether a function-like body contains a return of JSX or null.
fn body_returns_jsx(body: &FunctionBody<'_>) -> bool {
    let mut scanner = RenderReturnScanner::default();
    scanner.visit_function_body(body);
    scanner.satisfied
}

/// Whether a class renders (a `render` method returning JSX or null).
fn class_returns_jsx(class: &Class<'_>) -> bool {
    class.body.body.iter().any(|element| {
        let ClassElement::MethodDefinition(method) = element else {
            return false;
        };
        duplicated_key_name(&method.key) == Some("render")
            && method.kind == MethodDefinitionKind::Method
            && method
                .value
                .body
                .as_ref()
                .is_some_and(|body| body_returns_jsx(body))
    })
}

/// Whether a `useXxx`-shaped callee names a hook.
fn call_argument_function_count(call: &CallExpression<'_>) -> usize {
    call.arguments
        .iter()
        .filter_map(argument_expression)
        .filter(|expression| {
            matches!(
                expression,
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            )
        })
        .count()
}

/// Element tag behind a child position, if it is a plain element.
fn jsx_child_element_tag<'a>(child: &'a JSXChild<'a>) -> Option<&'a str> {
    match child {
        JSXChild::Element(element) => jsx_element_tag(&element.opening_element.name),
        _ => None,
    }
}

/// Whether a member chain contains a link spelled `link`.
fn member_chain_has_link(expression: &Expression<'_>, link: &str) -> bool {
    match expression {
        Expression::StaticMemberExpression(member) => {
            member.property.name == link || member_chain_has_link(&member.object, link)
        }
        _ => false,
    }
}

/// Whether a member chain passes through a `this.<link>` access.
fn expression_through_this_link(expression: &Expression<'_>, link: &str) -> bool {
    match expression {
        Expression::StaticMemberExpression(member) => {
            (matches!(&member.object, Expression::ThisExpression(_))
                && member.property.name == link)
                || expression_through_this_link(&member.object, link)
        }
        Expression::ComputedMemberExpression(member) => {
            expression_through_this_link(&member.object, link)
        }
        Expression::PrivateFieldExpression(member) => {
            expression_through_this_link(&member.object, link)
        }
        _ => false,
    }
}

/// Whether an intrinsic-element attribute is a known DOM/React name
/// (`S6747`): table, configured extras, `data-*`/`aria-*`, and handlers.
fn attribute_is_known(name: &str, whitelist: &[String]) -> bool {
    name.starts_with("data-")
        || name.starts_with("aria-")
        || (name.starts_with("on") && name[2..].starts_with(|ch: char| ch.is_ascii_alphabetic()))
        || REACT_DOM_ATTRIBUTES.contains(&name)
        || whitelist.iter().any(|allowed| allowed == name)
}

/// Subtree probe for reads through `this.state` (`S6756`).
#[derive(Default)]
struct ThisStateReferenceScanner {
    found: bool,
}

impl Visit<'_> for ThisStateReferenceScanner {
    fn visit_expression(&mut self, it: &Expression<'_>) {
        if expression_through_this_link(it, "state") {
            self.found = true;
            return;
        }
        walk_expression(self, it);
    }
}

/// Subtree probe for reads through `this.props` (`S6774`).
#[derive(Default)]
struct ThisPropsScanner {
    found: bool,
}

impl Visit<'_> for ThisPropsScanner {
    fn visit_expression(&mut self, it: &Expression<'_>) {
        if expression_through_this_link(it, "props") {
            self.found = true;
            return;
        }
        walk_expression(self, it);
    }
}
/// Frame for a `.map(callback)` traversal: remembers the callback's second
/// parameter (the array index) for `S6477`/`S6479`.
fn map_callback_frame(call: &CallExpression<'_>) -> Option<MapFrame> {
    let (property, _) = call_property(call)?;
    if property != "map" {
        return None;
    }
    let callback = call.arguments.first().and_then(argument_expression)?;
    let params = match callback {
        Expression::FunctionExpression(function) => &function.params,
        Expression::ArrowFunctionExpression(arrow) => &arrow.params,
        _ => return None,
    };
    let index_param = params
        .items
        .get(1)
        .and_then(|parameter| binding_identifier_name(&parameter.pattern))
        .map(str::to_string);
    Some(MapFrame {
        index_param,
        root_checked: false,
    })
}

/// Tag name of a JSX attribute (`ref`, `children`, ...); namespaced names
/// (`xlink:href`) have no plain name.
fn jsx_attribute_name<'a>(attribute: &'a JSXAttribute<'a>) -> Option<&'a str> {
    match &attribute.name {
        JSXAttributeName::Identifier(identifier) => Some(identifier.name.as_str()),
        JSXAttributeName::NamespacedName(_) => None,
    }
}

/// First attribute with the given name on an opening tag, if any.
fn jsx_find_attribute<'a>(
    opening: &'a JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a JSXAttribute<'a>> {
    opening.attributes.iter().find_map(|item| match item {
        JSXAttributeItem::Attribute(attribute) if jsx_attribute_name(attribute) == Some(name) => {
            Some(&**attribute)
        }
        _ => None,
    })
}

/// Tag name of a JSX element when spelled as a plain identifier (`div`,
/// `Widget`); namespaced, member, and `this` names have none.
fn jsx_element_tag<'a>(name: &'a JSXElementName<'a>) -> Option<&'a str> {
    match name {
        JSXElementName::Identifier(identifier) => Some(identifier.name.as_str()),
        JSXElementName::IdentifierReference(reference) => Some(&reference.name),
        _ => None,
    }
}

/// Whether a tag starts lowercase (intrinsic HTML/SVG spelling).
fn jsx_tag_is_intrinsic(tag: &str) -> bool {
    tag.starts_with(|ch: char| ch.is_ascii_lowercase())
}

/// Whether the opening tag carries a spread attribute (unknown props).
fn jsx_has_spread_attribute(opening: &JSXOpeningElement<'_>) -> bool {
    opening
        .attributes
        .iter()
        .any(|item| matches!(item, JSXAttributeItem::SpreadAttribute(_)))
}

/// Whether a member chain passes through a `this.state` link (`S6746`).
fn expression_through_this_state(expression: &Expression<'_>) -> bool {
    expression_through_this_link(expression, "state")
}

/// Whether a module export name spells `expected` (`import {a as b}` keeps
/// the imported spelling).
fn module_export_name_is(name: &ModuleExportName<'_>, expected: &str) -> bool {
    match name {
        ModuleExportName::IdentifierName(identifier) => identifier.name == expected,
        ModuleExportName::IdentifierReference(reference) => reference.name == expected,
        ModuleExportName::StringLiteral(literal) => literal.value == expected,
    }
}

/// Scans a `render` body for a return statement whose value subtree
/// contains JSX or a null literal (`S6435`).
#[derive(Default)]
struct RenderReturnScanner {
    satisfied: bool,
}

impl Visit<'_> for RenderReturnScanner {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'_>) {
        if let Some(argument) = &it.argument {
            let mut probe = JsxOrNullScanner::default();
            probe.visit_expression(argument);
            self.satisfied |= probe.found;
        }
    }
}

/// Subtree probe for JSX elements, fragments, and null literals.
#[derive(Default)]
struct JsxOrNullScanner {
    found: bool,
}

impl Visit<'_> for JsxOrNullScanner {
    fn visit_expression(&mut self, it: &Expression<'_>) {
        if matches!(
            it,
            Expression::JSXElement(_) | Expression::JSXFragment(_) | Expression::NullLiteral(_)
        ) {
            self.found = true;
            return;
        }
        walk_expression(self, it);
    }
}

/// `setFoo` shape: a `set` prefix followed by an uppercase letter.
fn is_state_setter_name(name: &str) -> bool {
    name.strip_prefix("set")
        .is_some_and(|tail| tail.starts_with(|ch: char| ch.is_ascii_uppercase()))
}

/// `value` becomes `Value` (first ASCII letter uppercased).
fn capitalize_first(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Property name of a `this.<property>` callee, if the call target is
/// exactly that shape.
fn callee_this_property<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    match &call.callee {
        Expression::StaticMemberExpression(member)
            if matches!(&member.object, Expression::ThisExpression(_)) =>
        {
            Some(&member.property.name)
        }
        _ => None,
    }
}

/// All Batch4 React/JSX structural checks in one traversal (groups R1-R3):
/// `S6748`, `S6761`, `S6749`, `S6750`, `S6754`, `S6443`, `S6788`, `S6789`,
/// `S6790`, `S6791`, `S6957`, `S6763`, `S6746`, `S6766`, `S6438`, `S6480`,
/// `S6477`, `S6479`, `S6770`, `S6435`, `S6439`, `S6440`, `S6442`, `S6481`,
/// `S6478`, `S6756`, `S6757`, `S6772`, `S6774`, `S6775`, and `S6747`.
fn check_react_jsx_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    let mut collector = ReactCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        rules,
        expression_statement_depth: 0,
        jsx_child_depth: 0,
        conditional_depth: 0,
        map_frames: Vec::new(),
        component_stack: Vec::new(),
        class_depth: 0,
        method_guard: 0,
        prop_declarations: BTreeMap::new(),
        prop_defaults: BTreeMap::new(),
    };
    collector.visit_program(program);
    collector.report_uncovered_defaults();
    collector.sink.issues
}

// ===== Batch4 groups A1-A3: JSX accessibility rules =====
//
// Table-driven jsx-a11y checks over one JSX walk: `S1077` (alt text),
// `S1082` (mouse handlers), `S1090` (iframe title), `S4084` (media
// captions), `S5254` (html lang), `S5256`/`S5257`/`S5260` (table
// structure), `S5264` (object alternative), `S6846` (accesskey), and
// `S6841` (tabIndex values). Groups A2/A3 add the role and interaction
// matrices.

/// Abstract roles that must never reach an element's `role` attribute.
const ABSTRACT_ROLES: [&str; 12] = [
    "command",
    "composite",
    "input",
    "landmark",
    "range",
    "roletype",
    "section",
    "sectionhead",
    "select",
    "structure",
    "widget",
    "window",
];

/// Tag to implicit ARIA role, refined by the `a[href]` and `input[type]`
/// adjustments in [`implicit_role`].
const IMPLICIT_ROLES: [(&str, &str); 22] = [
    ("article", "article"),
    ("aside", "complementary"),
    ("button", "button"),
    ("footer", "contentinfo"),
    ("form", "form"),
    ("h1", "heading"),
    ("h2", "heading"),
    ("h3", "heading"),
    ("h4", "heading"),
    ("h5", "heading"),
    ("h6", "heading"),
    ("header", "banner"),
    ("img", "img"),
    ("li", "listitem"),
    ("main", "main"),
    ("nav", "navigation"),
    ("ol", "list"),
    ("section", "region"),
    ("table", "table"),
    ("tbody", "rowgroup"),
    ("ul", "list"),
    ("textarea", "textbox"),
];

/// Global ARIA properties valid on every role (`S6811` exemptions).
const GLOBAL_ARIA_PROPERTIES: [&str; 18] = [
    "aria-atomic",
    "aria-busy",
    "aria-controls",
    "aria-current",
    "aria-describedby",
    "aria-disabled",
    "aria-dropeffect",
    "aria-errormessage",
    "aria-flowto",
    "aria-grabbed",
    "aria-haspopup",
    "aria-hidden",
    "aria-invalid",
    "aria-keyshortcuts",
    "aria-label",
    "aria-labelledby",
    "aria-live",
    "aria-owns",
];

/// Strictly boolean-valued ARIA attributes (`S6793`).
const BOOLEAN_ARIA_PROPERTIES: [&str; 13] = [
    "aria-atomic",
    "aria-busy",
    "aria-checked",
    "aria-disabled",
    "aria-expanded",
    "aria-grabbed",
    "aria-hidden",
    "aria-modal",
    "aria-multiline",
    "aria-multiselectable",
    "aria-pressed",
    "aria-readonly",
    "aria-selected",
];

/// Token-set ARIA attributes and their accepted literal values (`S6793`);
/// `"true"`/`"false"` are valid for every entry.
const TOKEN_ARIA_PROPERTIES: &[(&str, &[&str])] = &[
    (
        "aria-current",
        &["page", "step", "location", "date", "time"],
    ),
    (
        "aria-haspopup",
        &["menu", "listbox", "tree", "grid", "dialog"],
    ),
    ("aria-invalid", &["grammar", "spelling"]),
    ("aria-live", &["off", "assertive", "polite"]),
    ("aria-orientation", &["horizontal", "vertical"]),
    ("aria-sort", &["ascending", "descending", "other"]),
];

/// Numeric ARIA attributes validated as non-negative integers (`S6793`).
const NUMERIC_ARIA_PROPERTIES: [&str; 3] = ["aria-level", "aria-posinset", "aria-setsize"];

/// Redundant image alt texts (`S6851`).
const REDUNDANT_ALT_WORDS: [&str; 6] = ["image", "photo", "picture", "grafik", "bild", "logo"];

/// Roles that require owned descendant roles (`S6807`).
const ROLE_REQUIRED_CHILDREN: &[(&str, &[&str])] = &[
    ("grid", &["row"]),
    ("list", &["listitem"]),
    ("listbox", &["option"]),
    ("menu", &["menuitem", "menuitemcheckbox", "menuitemradio"]),
    ("row", &["cell", "columnheader", "rowheader"]),
    ("table", &["row"]),
    ("tablist", &["tab"]),
    ("tree", &["treeitem"]),
];

/// Non-global ARIA properties each explicit role supports (`S6811`).
const ROLE_SUPPORTED_PROPERTIES: &[(&str, &[&str])] = &[
    ("button", &["aria-expanded", "aria-pressed"]),
    ("checkbox", &["aria-checked", "aria-readonly"]),
    (
        "combobox",
        &["aria-autocomplete", "aria-expanded", "aria-required"],
    ),
    ("heading", &["aria-level"]),
    ("link", &["aria-expanded", "aria-pressed"]),
    (
        "menuitem",
        &[
            "aria-checked",
            "aria-expanded",
            "aria-posinset",
            "aria-setsize",
        ],
    ),
    (
        "option",
        &[
            "aria-checked",
            "aria-posinset",
            "aria-selected",
            "aria-setsize",
        ],
    ),
    ("radio", &["aria-checked", "aria-readonly"]),
    (
        "searchbox",
        &[
            "aria-autocomplete",
            "aria-multiline",
            "aria-readonly",
            "aria-required",
        ],
    ),
    (
        "slider",
        &[
            "aria-orientation",
            "aria-valuemax",
            "aria-valuemin",
            "aria-valuenow",
            "aria-valuetext",
        ],
    ),
    (
        "spinbutton",
        &[
            "aria-orientation",
            "aria-valuemax",
            "aria-valuemin",
            "aria-valuenow",
            "aria-valuetext",
        ],
    ),
    ("switch", &["aria-checked"]),
    (
        "tab",
        &[
            "aria-expanded",
            "aria-posinset",
            "aria-selected",
            "aria-setsize",
        ],
    ),
    (
        "tablist",
        &["aria-level", "aria-multiselectable", "aria-orientation"],
    ),
    (
        "textbox",
        &[
            "aria-autocomplete",
            "aria-multiline",
            "aria-readonly",
            "aria-required",
        ],
    ),
];

/// Every ARIA property this subset knows (`S6811` only judges names it
/// recognizes; unknown names stay silent).
const KNOWN_ARIA_PROPERTIES: [&str; 24] = [
    "aria-activedescendant",
    "aria-autocomplete",
    "aria-checked",
    "aria-colcount",
    "aria-colindex",
    "aria-colspan",
    "aria-expanded",
    "aria-level",
    "aria-multiselectable",
    "aria-orientation",
    "aria-posinset",
    "aria-pressed",
    "aria-readonly",
    "aria-required",
    "aria-rowcount",
    "aria-rowindex",
    "aria-rowspan",
    "aria-selected",
    "aria-setsize",
    "aria-valuemax",
    "aria-valuemin",
    "aria-valuenow",
    "aria-valuetext",
    "aria-sort",
];

/// Roles a list container (`ol`/`ul`) may take (`S6824`).
const LIST_CONTAINER_ROLES: [&str; 9] = [
    "group",
    "list",
    "menu",
    "menubar",
    "none",
    "presentation",
    "tablist",
    "toolbar",
    "tree",
];

/// Roles each restrictive element permits (`S6824`); elements outside this
/// table accept any explicit role.
const ALLOWED_ROLES_BY_ELEMENT: &[(&str, &[&str])] = &[
    ("article", &["article", "feed", "none", "presentation"]),
    (
        "aside",
        &["complementary", "feed", "none", "presentation", "search"],
    ),
    ("caption", &["none", "presentation"]),
    ("code", &["none", "presentation"]),
    ("dd", &["none", "presentation"]),
    ("dfn", &["none", "presentation"]),
    ("dialog", &["alertdialog", "dialog"]),
    ("dt", &["listitem", "none", "presentation"]),
    ("footer", &["contentinfo", "group", "none", "presentation"]),
    ("form", &["form", "none", "presentation", "search"]),
    ("header", &["banner", "group", "none", "presentation"]),
    ("h1", &["heading", "none", "presentation"]),
    ("h2", &["heading", "none", "presentation"]),
    ("h3", &["heading", "none", "presentation"]),
    ("h4", &["heading", "none", "presentation"]),
    ("h5", &["heading", "none", "presentation"]),
    ("h6", &["heading", "none", "presentation"]),
    (
        "li",
        &[
            "listitem",
            "menuitem",
            "menuitemcheckbox",
            "menuitemradio",
            "none",
            "option",
            "presentation",
            "row",
            "tab",
            "treeitem",
        ],
    ),
    ("main", &["main", "none", "presentation"]),
    (
        "nav",
        &[
            "menu",
            "menubar",
            "navigation",
            "none",
            "presentation",
            "tablist",
        ],
    ),
    ("ol", &LIST_CONTAINER_ROLES),
    (
        "section",
        &[
            "alert",
            "alertdialog",
            "application",
            "banner",
            "complementary",
            "contentinfo",
            "dialog",
            "document",
            "feed",
            "form",
            "main",
            "marquee",
            "navigation",
            "none",
            "note",
            "presentation",
            "region",
            "search",
            "status",
        ],
    ),
    ("tbody", &["rowgroup"]),
    ("td", &["cell", "gridcell", "none", "presentation"]),
    ("tfoot", &["rowgroup"]),
    ("th", &["columnheader", "none", "presentation", "rowheader"]),
    ("thead", &["rowgroup"]),
    ("tr", &["none", "presentation", "row"]),
    ("ul", &LIST_CONTAINER_ROLES),
];

/// Roles that make an element interactive (matrix groups `S6842`, `S6843`,
/// `S6845`, and `S6852`).
const INTERACTIVE_ROLES: [&str; 29] = [
    "button",
    "checkbox",
    "columnheader",
    "combobox",
    "grid",
    "gridcell",
    "link",
    "listbox",
    "menu",
    "menubar",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "option",
    "progressbar",
    "radio",
    "radiogroup",
    "row",
    "rowheader",
    "scrollbar",
    "searchbox",
    "slider",
    "spinbutton",
    "switch",
    "tab",
    "textbox",
    "tree",
    "treegrid",
    "treeitem",
];
/// Roles that never make an element interactive (`S6843`); interactive
/// elements must not take them.
const NON_INTERACTIVE_ROLES: [&str; 28] = [
    "alert",
    "article",
    "banner",
    "complementary",
    "contentinfo",
    "definition",
    "document",
    "feed",
    "figure",
    "form",
    "img",
    "list",
    "listitem",
    "log",
    "main",
    "math",
    "navigation",
    "none",
    "note",
    "presentation",
    "region",
    "rowgroup",
    "search",
    "status",
    "table",
    "term",
    "time",
    "tooltip",
];

/// Interaction handler props the matrix rules consider (`S6847`).
const INTERACTION_HANDLERS: [&str; 8] = [
    "onChange",
    "onClick",
    "onDoubleClick",
    "onKeyDown",
    "onKeyPress",
    "onKeyUp",
    "onMouseDown",
    "onMouseUp",
];

/// Keyboard handlers that pair with `onClick` for `S6848`.
const KEYBOARD_HANDLERS: [&str; 3] = ["onKeyDown", "onKeyPress", "onKeyUp"];

/// Autocomplete tokens valid on every autofill-capable element (`S6840`).
const AUTOCOMPLETE_GENERAL_TOKENS: [&str; 14] = [
    "address-line1",
    "address-line2",
    "country",
    "country-name",
    "current-password",
    "given-name",
    "new-password",
    "off",
    "on",
    "one-time-code",
    "organization",
    "postal-code",
    "street-address",
    "username",
];

/// Input types whose autocomplete accepts their matching contact token
/// (`S6840`).
const AUTOCOMPLETE_TYPE_TOKENS: &[(&str, &str)] =
    &[("email", "email"), ("tel", "tel"), ("url", "url")];

/// Which header affordances a table subtree provides.
#[derive(Clone, Copy, Default, PartialEq)]
enum TableMarkers {
    #[default]
    Plain,
    Caption,
    Headers,
}

/// Facts gathered from one subtree for the table, media, and text rules.
#[derive(Default)]
struct SubtreeFacts {
    table_markers: TableMarkers,
    track_captions: bool,
    has_visible_text: bool,
    header_ids: BTreeSet<String>,
    header_references: Vec<(Span, Vec<String>)>,
    descendant_roles: BTreeSet<String>,
    labelable_controls: u32,
}

/// Implicit ARIA role of an intrinsic tag, refined by `a[href]` and
/// `input[type]`.
fn implicit_role(tag: &str, opening: &JSXOpeningElement) -> Option<&'static str> {
    match tag {
        "a" | "area" => jsx_find_attribute(opening, "href").map(|_| "link"),
        "input" => {
            let input_type = jsx_find_attribute(opening, "type").and_then(attribute_static_value);
            Some(match input_type {
                Some("checkbox") => "checkbox",
                Some("radio") => "radio",
                Some("button" | "image") => "button",
                Some("number") => "spinbutton",
                Some("range") => "slider",
                Some("search") => "searchbox",
                _ => "textbox",
            })
        }
        _ => IMPLICIT_ROLES
            .iter()
            .find(|(name, _)| *name == tag)
            .map(|(_, role)| *role),
    }
}

/// Effective role of an element: explicit attribute value or the tag's
/// implicit role.
fn resolved_role(tag: &str, opening: &JSXOpeningElement) -> Option<String> {
    explicit_role(opening)
        .map(str::to_string)
        .or_else(|| implicit_role(tag, opening).map(str::to_string))
}

impl Visit<'_> for SubtreeFacts {
    fn visit_jsx_element(&mut self, it: &JSXElement<'_>) {
        if let Some(tag) = jsx_element_tag(&it.opening_element.name) {
            match tag {
                "th" | "thead" => self.table_markers = TableMarkers::Headers,
                "caption" => {
                    if self.table_markers == TableMarkers::Plain {
                        self.table_markers = TableMarkers::Caption;
                    }
                }
                "track"
                    if jsx_find_attribute(&it.opening_element, "kind")
                        .and_then(attribute_static_value)
                        == Some("captions") =>
                {
                    self.track_captions = true;
                }
                "button" | "input" | "meter" | "output" | "progress" | "select" | "textarea" => {
                    self.labelable_controls += 1
                }
                _ => {}
            }
            if tag == "th"
                && let Some(id_attribute) = jsx_find_attribute(&it.opening_element, "id")
                && let Some(value) = attribute_static_value(id_attribute)
            {
                self.header_ids.insert(value.to_string());
            }
            if matches!(tag, "td" | "th")
                && let Some(headers_attribute) = jsx_find_attribute(&it.opening_element, "headers")
                && let Some(value) = attribute_static_value(headers_attribute)
            {
                let tokens: Vec<String> = value.split_whitespace().map(str::to_string).collect();
                if !tokens.is_empty() {
                    self.header_references
                        .push((headers_attribute.span(), tokens));
                }
            }
            if let Some(role) = resolved_role(tag, &it.opening_element) {
                self.descendant_roles.insert(role);
            }
        }
        walk_jsx_element(self, it);
    }

    fn visit_jsx_text(&mut self, it: &JSXText<'_>) {
        if !it.value.trim().is_empty() {
            self.has_visible_text = true;
        }
    }
}

/// Accessibility rules in one JSX traversal (groups A1-A3).
struct A11yCollector<'index> {
    sink: IssueSink<'index>,
}

impl Visit<'_> for A11yCollector<'_> {
    fn visit_jsx_element(&mut self, it: &JSXElement<'_>) {
        self.check_alt_text(it);
        self.check_mouse_keyboard_pair(it);
        self.check_iframe_title(it);
        self.check_media_captions(it);
        self.check_html_lang(it);
        self.check_table_facts(it);
        self.check_object_alternative(it);
        self.check_accesskey(it);
        self.check_tab_index_value(it);
        self.check_heading_content(it);
        self.check_redundant_alt(it);
        self.check_anchor_content(it);
        self.check_role_duplicates(it);
        self.check_abstract_role(it);
        self.check_aria_values(it);
        self.check_required_owned(it);
        self.check_supported_properties(it);
        self.check_activedescendant_focusable(it);
        self.check_allowed_roles(it);
        self.check_aria_hidden_focusable(it);
        self.check_autocomplete_value(it);
        self.check_noninteractive_with_interactive_role(it);
        self.check_interactive_with_noninteractive_role(it);
        self.check_interactive_role_focusable(it);
        self.check_anchor_click_without_href(it);
        self.check_noninteractive_tab_index(it);
        self.check_noninteractive_handlers(it);
        self.check_click_keyboard_pair(it);
        self.check_label_association(it);
        walk_jsx_element(self, it);
    }
}

impl A11yCollector<'_> {
    /// `S1077`: images, areas, objects, and image inputs need alt text.
    fn check_alt_text(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) {
            return;
        }
        let needs_alt = match tag {
            "img" | "area" | "object" => true,
            "input" => {
                jsx_find_attribute(&element.opening_element, "type")
                    .and_then(attribute_static_value)
                    == Some("image")
            }
            _ => false,
        };
        if !needs_alt || jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        if jsx_find_attribute(&element.opening_element, "alt").is_none() {
            let message = format!("Add an 'alt' attribute to this <{tag}> element.");
            self.sink.emit_span(
                RuleScope::Both,
                "S1077",
                &message,
                element.opening_element.span(),
            );
        }
    }

    /// `S1082`: mouse-over/out handlers need focus/blur counterparts.
    fn check_mouse_keyboard_pair(&mut self, element: &JSXElement<'_>) {
        if jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        for (mouse, keyboard) in [("onMouseOver", "onFocus"), ("onMouseOut", "onBlur")] {
            let Some(mouse_attribute) = jsx_find_attribute(&element.opening_element, mouse) else {
                continue;
            };
            if jsx_find_attribute(&element.opening_element, keyboard).is_none() {
                let message =
                    format!("Add the '{keyboard}' handler to pair with this '{mouse}' handler.");
                self.sink
                    .emit_span(RuleScope::Both, "S1082", &message, mouse_attribute.span());
            }
        }
    }

    /// `S1090`: iframes need titles.
    fn check_iframe_title(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("iframe")
            || jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "title").is_some()
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S1090",
            "Add a 'title' attribute to this <iframe>.",
            element.opening_element.span(),
        );
    }

    /// `S4084`: audio and video elements need caption tracks.
    fn check_media_captions(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !matches!(tag, "audio" | "video") {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.track_captions {
            self.sink.emit_span(
                RuleScope::Both,
                "S4084",
                "Provide captions for this media element with a <track kind=\"captions\"> descendant.",
                element.opening_element.span(),
            );
        }
    }

    /// `S5254`: the root `<html>` element needs a valid language tag.
    fn check_html_lang(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("html")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let lang_valid = jsx_find_attribute(&element.opening_element, "lang")
            .and_then(attribute_static_value)
            .is_some_and(language_tag_is_valid);
        if !lang_valid {
            self.sink.emit_span(
                RuleScope::Both,
                "S5254",
                "Give the <html> element a valid 'lang' attribute.",
                element.opening_element.span(),
            );
        }
    }

    /// `S5256`, `S5257`, and `S5260`: header structure inside tables.
    fn check_table_facts(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("table") {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        let presentation_role = explicit_role(&element.opening_element)
            .is_some_and(|role| role == "presentation" || role == "none");
        if facts.table_markers != TableMarkers::Headers {
            self.sink.emit_span(
                RuleScope::Both,
                "S5256",
                "Add header cells (<th> or <thead>) to this table.",
                element.opening_element.span(),
            );
            if facts.table_markers == TableMarkers::Plain && !presentation_role {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5257",
                    "Mark this layout table with role=\"presentation\" or give it real headers.",
                    element.opening_element.span(),
                );
            }
        }
        for (span, tokens) in &facts.header_references {
            if tokens.iter().any(|token| !facts.header_ids.contains(token)) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5260",
                    "This 'headers' reference does not match any <th id> in the table.",
                    *span,
                );
            }
        }
    }

    /// `S5264`: object elements need a text alternative.
    fn check_object_alternative(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("object")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let labeled = ["aria-label", "aria-labelledby", "title"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some());
        if labeled {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.has_visible_text {
            self.sink.emit_span(
                RuleScope::Both,
                "S5264",
                "Provide a text alternative for this <object> element.",
                element.opening_element.span(),
            );
        }
    }

    /// `S6846`: access keys conflict with assistive shortcuts.
    fn check_accesskey(&mut self, element: &JSXElement<'_>) {
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            if jsx_attribute_name(attribute) == Some("accesskey") {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6846",
                    "Remove this 'accesskey'; it conflicts with assistive technology shortcuts.",
                    attribute.span(),
                );
            }
        }
    }

    /// `S6841`: tab indices are restricted to 0 and -1.
    fn check_tab_index_value(&mut self, element: &JSXElement<'_>) {
        let Some(index_attribute) = ["tabIndex", "tabindex"]
            .iter()
            .find_map(|name| jsx_find_attribute(&element.opening_element, name))
        else {
            return;
        };
        match attribute_integer_value(index_attribute) {
            Some(0 | -1) | None => {}
            Some(_) => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6841",
                    "Use only 0 or -1 for 'tabIndex'.",
                    index_attribute.span(),
                );
            }
        }
    }

    /// `S6850`: headings must have text content or a label.
    fn check_heading_content(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
            return;
        }
        let labeled = ["aria-label", "aria-labelledby", "title"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some());
        if labeled {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.has_visible_text {
            self.sink.emit_span(
                RuleScope::Both,
                "S6850",
                "This heading has no text content.",
                element.opening_element.span(),
            );
        }
    }

    /// `S6851`: alt text repeating the file name or a filler word.
    fn check_redundant_alt(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("img") {
            return;
        }
        let Some(alt_attribute) = jsx_find_attribute(&element.opening_element, "alt") else {
            return;
        };
        let Some(alt) = attribute_static_value(alt_attribute) else {
            return;
        };
        let normalized = alt.trim().to_lowercase();
        let source_stem = jsx_find_attribute(&element.opening_element, "src")
            .and_then(attribute_static_value)
            .and_then(|source| source.rsplit('/').next())
            .and_then(|name| name.rsplit_once('.').map(|(stem, _)| stem))
            .map(str::to_lowercase);
        if REDUNDANT_ALT_WORDS.contains(&normalized.as_str())
            || source_stem.as_deref() == Some(normalized.as_str())
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6851",
                "Redundant 'alt' text; describe the image purpose instead.",
                alt_attribute.span(),
            );
        }
    }

    /// `S6827`: anchors without `href` still need accessible text.
    fn check_anchor_content(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("a")
            || jsx_find_attribute(&element.opening_element, "href").is_some()
        {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.has_visible_text {
            self.sink.emit_span(
                RuleScope::Both,
                "S6827",
                "Give this <a> an 'href' or accessible text content.",
                element.opening_element.span(),
            );
        }
    }

    /// `S6822` and `S6819`: explicit roles duplicating the implicit ones.
    fn check_role_duplicates(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if implicit_role(tag, &element.opening_element) != Some(role) {
            return;
        }
        let Some(role_attribute) = jsx_find_attribute(&element.opening_element, "role") else {
            return;
        };
        self.sink.emit_span(
            RuleScope::Both,
            "S6822",
            "This 'role' duplicates the element's implicit role; remove it.",
            role_attribute.span(),
        );
        self.sink.emit_span(
            RuleScope::Both,
            "S6819",
            "Remove this explicit 'role'; the element already has these semantics implicitly.",
            role_attribute.span(),
        );
    }

    /// `S6821`: abstract roles cannot be used on elements.
    fn check_abstract_role(&mut self, element: &JSXElement<'_>) {
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if !ABSTRACT_ROLES.contains(&role) {
            return;
        }
        let message = format!("'{role}' is an abstract role and cannot be used on elements.");
        let role_attribute = jsx_find_attribute(&element.opening_element, "role");
        self.sink.emit_span(
            RuleScope::Both,
            "S6821",
            &message,
            role_attribute.map_or(element.span(), GetSpan::span),
        );
    }

    /// `S6793`: literal ARIA attribute values validated against tables.
    fn check_aria_values(&mut self, element: &JSXElement<'_>) {
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            let Some(value) = attribute_static_value(attribute) else {
                continue;
            };
            let invalid = if BOOLEAN_ARIA_PROPERTIES.contains(&name) {
                !matches!(value, "true" | "false")
            } else if let Some((_, tokens)) = TOKEN_ARIA_PROPERTIES
                .iter()
                .find(|(property, _)| *property == name)
            {
                !matches!(value, "true" | "false") && !tokens.contains(&value)
            } else if NUMERIC_ARIA_PROPERTIES.contains(&name) {
                value.parse::<u32>().is_err()
            } else {
                continue;
            };
            if invalid {
                let message = format!("'{value}' is not a valid value for '{name}'.");
                self.sink
                    .emit_span(RuleScope::Both, "S6793", &message, attribute.span());
            }
        }
    }

    /// `S6807`: roles with required owned descendants.
    fn check_required_owned(&mut self, element: &JSXElement<'_>) {
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        let Some((_, required)) = ROLE_REQUIRED_CHILDREN
            .iter()
            .find(|(name, _)| *name == role)
        else {
            return;
        };
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        let owns_required = facts
            .descendant_roles
            .iter()
            .any(|descendant| required.contains(&descendant.as_str()));
        if !owns_required {
            let message = format!(
                "A '{role}' must own a '{}' descendant to be complete.",
                required[0]
            );
            let role_attribute = jsx_find_attribute(&element.opening_element, "role");
            self.sink.emit_span(
                RuleScope::Both,
                "S6807",
                &message,
                role_attribute.map_or(element.span(), GetSpan::span),
            );
        }
    }

    /// `S6811`: known ARIA properties must be supported by the explicit
    /// role (globals are always allowed).
    fn check_supported_properties(&mut self, element: &JSXElement<'_>) {
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        let Some(supported) = ROLE_SUPPORTED_PROPERTIES
            .iter()
            .find(|(name, _)| *name == role)
            .map(|(_, properties)| *properties)
        else {
            return;
        };
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            if !KNOWN_ARIA_PROPERTIES.contains(&name)
                || GLOBAL_ARIA_PROPERTIES.contains(&name)
                || supported.contains(&name)
            {
                continue;
            }
            let message = format!("'{name}' is not supported by role '{role}'.");
            self.sink
                .emit_span(RuleScope::Both, "S6811", &message, attribute.span());
        }
    }

    /// `S6823`: `aria-activedescendant` requires a tab index.
    fn check_activedescendant_focusable(&mut self, element: &JSXElement<'_>) {
        if jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(active_attribute) =
            jsx_find_attribute(&element.opening_element, "aria-activedescendant")
        else {
            return;
        };
        if ["tabIndex", "tabindex"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some())
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6823",
            "Elements with 'aria-activedescendant' must carry 'tabIndex'.",
            active_attribute.span(),
        );
    }

    /// `S6824`: explicit roles must be permitted on the carrying element.
    fn check_allowed_roles(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) || jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        let Some((_, allowed)) = ALLOWED_ROLES_BY_ELEMENT
            .iter()
            .find(|(name, _)| *name == tag)
        else {
            return;
        };
        if !allowed.contains(&role) {
            let message = format!("'{role}' is not an allowed role for <{tag}> elements.");
            self.sink.emit_span(
                RuleScope::Both,
                "S6824",
                &message,
                element.opening_element.span(),
            );
        }
    }

    /// `S6825`: focusable elements cannot be hidden from assistive tech.
    fn check_aria_hidden_focusable(&mut self, element: &JSXElement<'_>) {
        if jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(hidden_attribute) = jsx_find_attribute(&element.opening_element, "aria-hidden")
        else {
            return;
        };
        if attribute_static_value(hidden_attribute) != Some("true") {
            return;
        }
        let intrinsically_focusable = match jsx_element_tag(&element.opening_element.name) {
            Some(tag) if jsx_tag_is_intrinsic(tag) => {
                is_interactive_element(tag, &element.opening_element)
            }
            _ => false,
        };
        let tabbable = ["tabIndex", "tabindex"].iter().any(|name| {
            jsx_find_attribute(&element.opening_element, name)
                .and_then(attribute_integer_value)
                .is_some_and(|value| value >= 0)
        });
        if intrinsically_focusable || tabbable {
            self.sink.emit_span(
                RuleScope::Both,
                "S6825",
                "Do not hide this focusable element with 'aria-hidden=\"true\"'.",
                hidden_attribute.span(),
            );
        }
    }

    /// `S6840`: autocomplete values must fit the element's input type.
    fn check_autocomplete_value(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !matches!(tag, "input" | "select" | "textarea")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let Some(autocomplete_attribute) = ["autocomplete", "autoComplete"]
            .iter()
            .find_map(|name| jsx_find_attribute(&element.opening_element, name))
        else {
            return;
        };
        let Some(value) = attribute_static_value(autocomplete_attribute) else {
            return;
        };
        let token = value.trim().to_lowercase();
        let input_type = attribute_named_static_value(&element.opening_element, "type");
        let valid = AUTOCOMPLETE_GENERAL_TOKENS.contains(&token.as_str())
            || AUTOCOMPLETE_TYPE_TOKENS
                .iter()
                .any(|(scoped_type, scoped_token)| {
                    input_type == Some(*scoped_type) && token == *scoped_token
                });
        if !valid {
            let message = format!("\"{value}\" is not a valid 'autocomplete' value here.");
            self.sink.emit_span(
                RuleScope::Both,
                "S6840",
                &message,
                autocomplete_attribute.span(),
            );
        }
    }

    /// `S6842`: interactive roles belong on natively interactive elements.
    fn check_noninteractive_with_interactive_role(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
        {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if is_interactive_role(role) {
            let message = format!(
                "Replace this <{tag}> with an interactive element or remove the '{role}' role."
            );
            let role_attribute = jsx_find_attribute(&element.opening_element, "role");
            self.sink.emit_span(
                RuleScope::Both,
                "S6842",
                &message,
                role_attribute.map_or(element.span(), GetSpan::span),
            );
        }
    }

    /// `S6843`: interactive elements must not take structural roles.
    fn check_interactive_with_noninteractive_role(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || !is_interactive_element(tag, &element.opening_element)
        {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if is_non_interactive_role(role) {
            let message = format!("Interactive <{tag}> elements cannot take the '{role}' role.");
            let role_attribute = jsx_find_attribute(&element.opening_element, "role");
            self.sink.emit_span(
                RuleScope::Both,
                "S6843",
                &message,
                role_attribute.map_or(element.span(), GetSpan::span),
            );
        }
    }

    /// `S6852`: elements with an interactive role must be focusable.
    fn check_interactive_role_focusable(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) || jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if !is_interactive_role(role)
            || is_interactive_element(tag, &element.opening_element)
            || ["tabIndex", "tabindex"]
                .iter()
                .any(|name| jsx_find_attribute(&element.opening_element, name).is_some())
        {
            return;
        }
        let message =
            format!("Elements with the '{role}' role must be focusable; add a 'tabIndex'.");
        let role_attribute = jsx_find_attribute(&element.opening_element, "role");
        self.sink.emit_span(
            RuleScope::Both,
            "S6852",
            &message,
            role_attribute.map_or(element.span(), GetSpan::span),
        );
    }

    /// `S6844`: click handlers on anchors without `href`.
    fn check_anchor_click_without_href(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("a")
            || jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "href").is_some()
        {
            return;
        }
        if jsx_find_attribute(&element.opening_element, "onClick").is_some() {
            self.sink.emit_span(
                RuleScope::Both,
                "S6844",
                "Add an 'href' to this <a> or use a <button> for this action.",
                element.opening_element.span(),
            );
        }
    }

    /// `S6845`: positive tab indices belong on interactive elements.
    fn check_noninteractive_tab_index(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
            || jsx_find_attribute(&element.opening_element, "aria-activedescendant").is_some()
        {
            return;
        }
        let Some(index_attribute) = ["tabIndex", "tabindex"]
            .iter()
            .find_map(|name| jsx_find_attribute(&element.opening_element, name))
        else {
            return;
        };
        let focusable_by_role =
            explicit_role(&element.opening_element).is_some_and(is_interactive_role);
        if !focusable_by_role
            && attribute_integer_value(index_attribute).is_some_and(|value| value >= 0)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6845",
                "Remove this positive 'tabIndex'; make the element properly interactive instead.",
                index_attribute.span(),
            );
        }
    }

    /// `S6847`: interaction handlers belong on interactive elements.
    fn check_noninteractive_handlers(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
            || explicit_role(&element.opening_element).is_some_and(is_interactive_role)
        {
            return;
        }
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            if INTERACTION_HANDLERS.contains(&name) {
                let message = format!("Move this '{name}' handler to an interactive element.");
                self.sink
                    .emit_span(RuleScope::Both, "S6847", &message, attribute.span());
            }
        }
    }

    /// `S6848`: click handlers need keyboard counterparts on
    /// non-interactive elements.
    fn check_click_keyboard_pair(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
            || explicit_role(&element.opening_element).is_some_and(is_interactive_role)
        {
            return;
        }
        let Some(click_attribute) = jsx_find_attribute(&element.opening_element, "onClick") else {
            return;
        };
        if KEYBOARD_HANDLERS
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some())
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6848",
            "Add a keyboard handler ('onKeyDown', 'onKeyPress', or 'onKeyUp') to pair with this 'onClick'.",
            click_attribute.span(),
        );
    }

    /// `S6853`: labels need text and a control association.
    fn check_label_association(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("label")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        let labeled = ["aria-label", "aria-labelledby"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some());
        let associated = jsx_find_attribute(&element.opening_element, "htmlFor").is_some()
            || facts.labelable_controls > 0;
        if (!facts.has_visible_text && !labeled) || !associated {
            self.sink.emit_span(
                RuleScope::Both,
                "S6853",
                "Associate this <label> with a form control and give it text content.",
                element.opening_element.span(),
            );
        }
    }
}

/// Static string content of an attribute value, if it is a string literal
/// or a container wrapping one.
fn attribute_static_value<'a>(attribute: &'a JSXAttribute<'a>) -> Option<&'a str> {
    match attribute.value.as_ref()? {
        JSXAttributeValue::StringLiteral(literal) => Some(literal.value.as_str()),
        JSXAttributeValue::ExpressionContainer(container) => {
            match container.expression.as_expression()? {
                Expression::StringLiteral(literal) => Some(literal.value.as_str()),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Integer content of an attribute value: numeric literals or strings that
/// parse as integers.
fn attribute_integer_value(attribute: &JSXAttribute<'_>) -> Option<i64> {
    match attribute.value.as_ref()? {
        JSXAttributeValue::StringLiteral(literal) => literal.value.trim().parse().ok(),
        JSXAttributeValue::ExpressionContainer(container) => {
            match container.expression.as_expression()? {
                Expression::NumericLiteral(literal) => {
                    literal.raw.as_ref().and_then(|raw| raw.trim().parse().ok())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Explicit single-token `role` attribute value, if any.
fn explicit_role<'x>(opening: &'x JSXOpeningElement<'x>) -> Option<&'x str> {
    let value = attribute_static_value(jsx_find_attribute(opening, "role")?)?;
    value.split_whitespace().last()
}

/// Whether the opening tag carries the named attribute at all.
fn jsx_has_attribute(opening: &JSXOpeningElement<'_>, name: &str) -> bool {
    opening.attributes.iter().any(|item| {
        matches!(item, JSXAttributeItem::Attribute(attribute) if jsx_attribute_name(attribute) == Some(name))
    })
}

/// Static string value of the named attribute, if it carries one.
fn attribute_named_static_value<'x>(
    opening: &'x JSXOpeningElement<'x>,
    name: &str,
) -> Option<&'x str> {
    jsx_find_attribute(opening, name).and_then(attribute_static_value)
}

/// Whether an intrinsic element is natively interactive (interaction-matrix
/// rules).
fn is_interactive_element(tag: &str, opening: &JSXOpeningElement<'_>) -> bool {
    match tag {
        "a" | "area" => jsx_find_attribute(opening, "href").is_some(),
        "audio" | "video" => jsx_has_attribute(opening, "controls"),
        "img" | "object" => jsx_has_attribute(opening, "usemap"),
        "input" => attribute_named_static_value(opening, "type") != Some("hidden"),
        "button" | "details" | "embed" | "iframe" | "label" | "menu" | "menuitem" | "select"
        | "summary" | "textarea" => true,
        _ => false,
    }
}

/// Whether an explicit role makes an element interactive.
fn is_interactive_role(role: &str) -> bool {
    INTERACTIVE_ROLES.contains(&role)
}

/// Whether an explicit role is a purely structural or document role.
fn is_non_interactive_role(role: &str) -> bool {
    NON_INTERACTIVE_ROLES.contains(&role)
}

/// Whether a language tag looks like a BCP-47 subset form (`en`, `pt-BR`).
fn language_tag_is_valid(value: &str) -> bool {
    let segments: Vec<&str> = value.split('-').collect();
    if segments.len() > 3 {
        return false;
    }
    let Some((primary, subtags)) = segments.split_first() else {
        return false;
    };
    (2..=3).contains(&primary.len())
        && primary.chars().all(|ch| ch.is_ascii_alphabetic())
        && subtags.iter().all(|segment| {
            !segment.is_empty()
                && segment.len() <= 8
                && segment.chars().all(|ch| ch.is_ascii_alphanumeric())
        })
}

/// All Batch4 JSX accessibility checks in one traversal (groups A1-A3).
fn check_jsx_accessibility_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = A11yCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

#[cfg(test)]
mod tests {

    use super::{AnalyzerOptions, JstsLanguage, RuleOptions, analyze, language_for_extension};
    use std::fmt::Write as _;
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
eval('a');
let b = x; let c = y;
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
eval('x');
const f = new Function('return 1');
foo(eval(nested));
window.eval('not plain identifier');
new window.Function('also ignored');

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
                    "javascript:S3523",
                    "Remove this use of the \"Function\" constructor.",
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

    fn js_with_rules(source: &str, rules: &RuleOptions) -> hoonarqube_ir::FileReport {
        super::analyze_with_rules(
            PathBuf::from("test.js"),
            source,
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            rules,
        )
    }

    fn keys_with_rules(source: &str, rules: &RuleOptions) -> Vec<(String, u32)> {
        report_keys(&js_with_rules(source, rules))
    }

    // ===== Batch2a naming/format rule tests =====

    #[test]
    fn function_class_and_interface_names_follow_catalog_formats() {
        let report = js(
            "function goodName() {}\nfunction BadName() {}\nfunction _underscoreOk() {}\nclass GoodClass {}\nclass badClass {}\n",
        );
        assert_eq!(count_key(&report_keys(&report), "javascript:S100"), 1);
        assert_eq!(count_key(&report_keys(&report), "javascript:S101"), 1);
        let bad_function: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S100")
            .collect();
        assert_eq!(
            bad_function,
            vec![&issue(
                "javascript:S100",
                "Rename this function to match the regular expression '^[_a-z][a-zA-Z0-9]*$'.",
                (2, 9),
                (2, 16),
            )]
        );

        let ts_report = ts("interface goodInterface {}\ninterface GoodInterface {}\n");
        assert_eq!(count_key(&report_keys(&ts_report), "typescript:S101"), 1);
        assert_eq!(count_key(&report_keys(&ts_report), "typescript:S100"), 0);
    }

    #[test]
    fn method_names_are_checked_but_constructors_are_exempt() {
        let rules = RuleOptions {
            format_functions: "^doRe$".to_string(),
            ..RuleOptions::default()
        };
        let flagged = keys_with_rules("class C { constructor() {} doIt() {} doRe() {} }\n", &rules);
        assert_eq!(count_key(&flagged, "javascript:S100"), 1);
    }

    #[test]
    fn variables_parameters_and_properties_honor_format() {
        let defaults_clean = js_keys(
            "function f(goodParam) { let goodVar = 1; const UPPER_SNAKE = 2; const opts = { anyKey: 3 }; }\n",
        );
        assert_eq!(count_key(&defaults_clean, "javascript:S117"), 0);

        let rules = RuleOptions {
            format_variables: "^[a-z][a-zA-Z0-9]*$".to_string(),
            ..RuleOptions::default()
        };
        let strict = keys_with_rules(
            "function f(BadParam) { let BadVar = 1; let okVar = 2; }\n",
            &rules,
        );
        assert_eq!(count_key(&strict, "javascript:S117"), 2);
    }

    #[test]
    fn magic_numbers_flagged_only_outside_allowed_contexts() {
        let report = js(
            "const LIMIT = 42;\nlet retries = 3;\nitems[0] = LIMIT;\nfunction g(x = 1, y = 5) { return x; }\nfunction h(z = -1) { return z; }\nlet offset = -7;\ng(2);\n",
        );
        let magic: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S109")
            .collect();
        let message = "This numeric literal should be replaced by a named constant.";
        assert_eq!(
            magic,
            vec![
                &issue("javascript:S109", message, (2, 14), (2, 15)),
                &issue("javascript:S109", message, (4, 22), (4, 23)),
                &issue("javascript:S109", message, (6, 14), (6, 15)),
                &issue("javascript:S109", message, (7, 2), (7, 3)),
            ]
        );

        // Boundary: `-1..=2` parameter defaults are allowed, larger ones are not.
        let boundary = js("function k(a = 2, b = 3) {}\n");
        assert_eq!(count_key(&report_keys(&boundary), "javascript:S109"), 1);
    }

    #[test]
    fn duplicate_string_literals_report_once_at_first_occurrence() {
        let report = js(
            "log('application/json');\nlog('application/json');\nlog('application/json');\nwarn('dup');\nwarn('dup');\nwarn('dup');\ntag('x');\ntag('x');\n",
        );
        let duplicates: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S1192")
            .collect();
        // The configured `ignoreStrings` entry never fires; single-character
        // literals are excluded; the third occurrence reaches the threshold.
        assert_eq!(
            duplicates,
            vec![&issue(
                "javascript:S1192",
                "Define a constant instead of duplicating this literal \"dup\" 3 times.",
                (4, 5),
                (4, 10),
            )]
        );

        let eager = RuleOptions {
            duplicate_string_threshold: 2,
            ..RuleOptions::default()
        };
        let flagged = keys_with_rules("a('aa');\nb('aa');\nc('bb');\n", &eager);
        assert_eq!(count_key(&flagged, "javascript:S1192"), 1);
    }

    #[test]
    fn string_quote_style_follows_single_quotes_param() {
        let report = js(
            "const a = \"double\";\nconst b = 'single';\nconst c = \"escaped \\\"quote\\\"\";\nconst d = `template`;\n",
        );
        let quotes: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S1441")
            .collect();
        assert_eq!(
            quotes,
            vec![&issue(
                "javascript:S1441",
                "Use single quotes for this string literal.",
                (1, 10),
                (1, 18),
            )]
        );

        let double = RuleOptions {
            single_quotes: false,
            ..RuleOptions::default()
        };
        let relaxed = keys_with_rules("const a = 'quoted';\nconst b = \"doubled\";\n", &double);
        assert_eq!(count_key(&relaxed, "javascript:S1441"), 1);
    }

    #[test]
    fn lowercase_constructor_callees_flagged() {
        let report = js("new foo();\nnew Foo();\nnew lib.Bar();\n");
        let constructors: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S2430")
            .collect();
        assert_eq!(
            constructors,
            vec![&issue(
                "javascript:S2430",
                "Rename this constructor to start with an uppercase letter.",
                (1, 4),
                (1, 7),
            )]
        );
    }

    // ===== Batch2a structural duplicate/identity rule tests =====

    #[test]
    fn identical_binary_operands_flagged() {
        let report =
            js("if (a === a) {}\nif (b + c === b + c) {}\nif (x == y) {}\nlet t = p && p;\n");
        assert_eq!(count_key(&report_keys(&report), "javascript:S1764"), 2);
        let first: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S1764")
            .collect();
        assert_eq!(
            first[0].range,
            hoonarqube_ir::Range {
                start: pos(1, 4),
                end: pos(1, 11),
            }
        );
    }

    #[test]
    fn identical_if_branches_and_switch_cases_flagged() {
        let report = js(
            "function f(cond) {\n  if (cond) { work(); cleanup(); } else { work(); cleanup(); }\n}\n",
        );
        // The identical if/else pair is reported by both rule keys.
        assert_eq!(count_key(&report_keys(&report), "javascript:S1871"), 1);
        assert_eq!(count_key(&report_keys(&report), "javascript:S3923"), 1);

        let switch = js(
            "function g(v) {\nswitch (v) { case 1: a(); break; case 2: a(); break; case 3: b(); break; }\n}\n",
        );
        assert_eq!(count_key(&report_keys(&switch), "javascript:S1871"), 1);

        // Fallthrough placeholders are not duplicated bodies.
        let fallthrough = js("switch (v) { case 1: case 2: a(); break; }\n");
        assert_eq!(count_key(&report_keys(&fallthrough), "javascript:S1871"), 0);
    }

    #[test]
    fn all_identical_branch_structures_flagged_once() {
        let ternary = js("const r = flag ? 1 : 1;\n");
        assert_eq!(count_key(&report_keys(&ternary), "javascript:S3923"), 1);

        let chain =
            js("function f(a, b) {\n  if (a) { x(); } else if (b) { x(); } else { x(); }\n}\n");
        assert_eq!(count_key(&report_keys(&chain), "javascript:S3923"), 1);
        // Only the last link's branches are identical.
        assert_eq!(count_key(&report_keys(&chain), "javascript:S1871"), 1);
    }

    #[test]
    fn duplicated_conditions_in_chains_and_switches_flagged() {
        let chain = js("function f(a) {\n  if (a === 1) { x(); } else if (a === 1) { y(); }\n}\n");
        assert_eq!(count_key(&report_keys(&chain), "javascript:S1862"), 1);

        let distinct =
            js("function f(a, b) {\n  if (a === 1) { x(); } else if (b === 1) { y(); }\n}\n");
        assert_eq!(count_key(&report_keys(&distinct), "javascript:S1862"), 0);

        let switch = js("switch (v) { case 1: r(); break; case 1: s(); break; }\n");
        assert_eq!(count_key(&report_keys(&switch), "javascript:S1862"), 1);
    }

    #[test]
    fn identical_function_bodies_flagged_but_trivial_ones_skipped() {
        let source = "\
function alpha() {
  setup();
  run();
}
function beta() {
  setup();
  run();
}
function gamma() {
  other();
}
";
        let report = js(source);
        assert_eq!(count_key(&report_keys(&report), "javascript:S4144"), 1);

        let trivial = js("function d1() { x(); }\nfunction d2() { x(); }\n");
        assert_eq!(count_key(&report_keys(&trivial), "javascript:S4144"), 0);
    }

    #[test]
    fn invariant_literal_returns_flagged_once_per_function() {
        let same = js("function f(n) {\n  if (n) { return 'same'; }\n  return 'same';\n}\n");
        assert_eq!(count_key(&report_keys(&same), "javascript:S3516"), 1);

        let differing = js("function f(n) {\n  if (n) { return 'a'; }\n  return 'b';\n}\n");
        assert_eq!(count_key(&report_keys(&differing), "javascript:S3516"), 0);

        // A bare `return` means the returns are not all literal values.
        let bare_mixed = js("function f(n) {\n  if (n) { return; }\n  return 'x';\n}\n");
        assert_eq!(count_key(&report_keys(&bare_mixed), "javascript:S3516"), 0);

        // Non-literal returns never count as invariant duplicates.
        let identifiers = js("function f(n, m) {\n  if (n) { return m; }\n  return m;\n}\n");
        assert_eq!(count_key(&report_keys(&identifiers), "javascript:S3516"), 0);
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

    // ===== Batch2b tests: statement-shape and control-flow walks =====

    #[test]
    fn s126_flags_else_if_chain_without_final_else() {
        let chained =
            js_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n} else if (c) {\n  h();\n}\n");
        assert_eq!(count_key(&chained, "javascript:S126"), 1);
        let tail_line = chained
            .iter()
            .find(|(key, _)| key == "javascript:S126")
            .map(|(_, line)| *line);
        assert_eq!(tail_line, Some(5));

        let with_final_else =
            js_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n} else {\n  h();\n}\n");
        assert_eq!(count_key(&with_final_else, "javascript:S126"), 0);

        // A lone `if` is not a chain.
        let plain_if = js_keys("if (a) {\n  f();\n}\n");
        assert_eq!(count_key(&plain_if, "javascript:S126"), 0);
    }

    #[test]
    fn s128_requires_unconditional_case_termination() {
        let falling_through = js_keys("switch (x) {\n  case 1:\n    f();\n}\n");
        assert_eq!(count_key(&falling_through, "javascript:S128"), 1);

        let with_break = js_keys("switch (x) {\n  case 1:\n    f();\n    break;\n}\n");
        assert_eq!(count_key(&with_break, "javascript:S128"), 0);

        // Empty consequents (case grouping) and block-wrapped jumps stay
        // clean.
        let grouped = js_keys("switch (x) {\n  case 1:\n  case 2:\n    f();\n    break;\n}\n");
        assert_eq!(count_key(&grouped, "javascript:S128"), 0);

        let via_block_return = js_keys(
            "function f(x) {\n  switch (x) {\n    case 1:\n      { g(); return; }\n  }\n}\n",
        );
        assert_eq!(count_key(&via_block_return, "javascript:S128"), 0);
    }

    #[test]
    fn s131_flags_switch_without_default_case() {
        let source = "switch (x) {\n  case 1:\n    break;\n}\n";
        let missing = js_keys(source);
        assert_eq!(count_key(&missing, "javascript:S131"), 1);

        let with_default =
            js_keys("switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&with_default, "javascript:S131"), 0);

        let typescript = findings(source, JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S131"), 1);
        assert_eq!(count_key(&typescript, "javascript:S131"), 0);
    }

    #[test]
    fn s4524_flags_default_case_not_in_last_position() {
        let misplaced = js_keys("switch (x) {\n  default:\n    break;\n  case 1:\n    break;\n}\n");
        assert_eq!(count_key(&misplaced, "javascript:S4524"), 1);

        let last = js_keys("switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&last, "javascript:S4524"), 0);
    }

    #[test]
    fn s3616_flags_sequence_and_logical_or_case_tests() {
        let sequence = js_keys("switch (x) {\n  case (a(), b):\n    break;\n}\n");
        assert_eq!(count_key(&sequence, "javascript:S3616"), 1);

        let logical_or = js_keys("switch (x) {\n  case a || b:\n    break;\n}\n");
        assert_eq!(count_key(&logical_or, "javascript:S3616"), 1);

        // Logical AND tests are ordinary expressions.
        let logical_and = js_keys("switch (x) {\n  case a && b:\n    break;\n}\n");
        assert_eq!(count_key(&logical_and, "javascript:S3616"), 0);
    }

    #[test]
    fn s1479_flags_switches_with_more_than_thirty_cases() {
        let build = |case_count: usize| {
            let mut source = String::from("switch (x) {\n");
            for case_number in 0..case_count {
                let _ = write!(source, "  case {case_number}:\n    break;\n");
            }
            source.push_str("}\n");
            source
        };

        let at_limit = js_keys(&build(super::MAX_SWITCH_CASES));
        assert_eq!(count_key(&at_limit, "javascript:S1479"), 0);

        let over_limit = js_keys(&build(super::MAX_SWITCH_CASES + 1));
        assert_eq!(count_key(&over_limit, "javascript:S1479"), 1);
    }

    #[test]
    fn s1301_flags_switches_convertible_to_if() {
        let two_cases = js_keys(
            "switch (x) {\n  case 1:\n    f();\n    break;\n  case 2:\n    g();\n    break;\n  default:\n    break;\n}\n",
        );
        assert_eq!(count_key(&two_cases, "javascript:S1301"), 1);

        let one_case =
            js_keys("switch (x) {\n  case 1:\n    f();\n    break;\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&one_case, "javascript:S1301"), 1);

        let mut three_cases_source = String::from("switch (x) {\n  default:\n    break;\n");
        for case_number in 0..3 {
            let _ = write!(three_cases_source, "  case {case_number}:\n    break;\n");
        }
        three_cases_source.push_str("}\n");
        let three_cases = js_keys(&three_cases_source);
        assert_eq!(count_key(&three_cases, "javascript:S1301"), 0);
    }

    #[test]
    fn s1821_flags_switch_nested_inside_case_consequent() {
        let nested = js_keys(
            "switch (x) {\n  case 1:\n    switch (y) {\n      case 2:\n        break;\n    }\n    break;\n}\n",
        );
        assert_eq!(count_key(&nested, "javascript:S1821"), 1);
        let inner_line = nested
            .iter()
            .find(|(key, _)| key == "javascript:S1821")
            .map(|(_, line)| *line);
        assert_eq!(inner_line, Some(3));

        // Sibling switches at the top level stay clean.
        let sibling = js_keys(
            "switch (x) {\n  case 1:\n    break;\n}\nswitch (y) {\n  default:\n    break;\n}\n",
        );
        assert_eq!(count_key(&sibling, "javascript:S1821"), 0);
    }

    #[test]
    fn s888_flags_loose_equality_in_for_test() {
        let loose = js_keys("for (let i = 0; i == n; i++) {}\n");
        assert_eq!(count_key(&loose, "javascript:S888"), 1);

        let strict = js_keys("for (let i = 0; i === n; i++) {}\n");
        assert_eq!(count_key(&strict, "javascript:S888"), 0);
    }

    #[test]
    fn s1264_flags_init_and_update_less_for_loops() {
        let bare = js_keys("for (;;) {\n  break;\n}\n");
        assert_eq!(count_key(&bare, "javascript:S1264"), 1);

        let counted = js_keys("for (let i = 0; i < n; i++) {\n  f(i);\n}\n");
        assert_eq!(count_key(&counted, "javascript:S1264"), 0);
    }

    #[test]
    fn s2251_flags_counter_moving_away_from_bound() {
        let away = js_keys("for (let i = 0; i < n; i--) {}\n");
        assert_eq!(count_key(&away, "javascript:S2251"), 1);

        let towards = js_keys("for (let i = 0; i > n; i--) {}\n");
        assert_eq!(count_key(&towards, "javascript:S2251"), 0);

        let incrementing_up = js_keys("for (let i = 0; i < n; i++) {}\n");
        assert_eq!(count_key(&incrementing_up, "javascript:S2251"), 0);
    }

    #[test]
    fn s1994_flags_update_clause_not_touching_counter() {
        let other_counter = js_keys("let j = 0;\nfor (let i = 0; i < n; j++) {}\n");
        assert_eq!(count_key(&other_counter, "javascript:S1994"), 1);

        let compound_update = js_keys("for (let i = 0; i < n; i += 2) {}\n");
        assert_eq!(count_key(&compound_update, "javascript:S1994"), 0);
    }

    #[test]
    fn s2310_flags_counter_writes_inside_loop_body() {
        let assigned = js_keys("for (let i = 0; i < n; i++) {\n  i = 5;\n}\n");
        assert_eq!(count_key(&assigned, "javascript:S2310"), 1);

        let updated = js_keys("for (let i = 0; i < n; i++) {\n  i++;\n}\n");
        assert_eq!(count_key(&updated, "javascript:S2310"), 1);

        let other_variable = js_keys("for (let i = 0; i < n; i++) {\n  j = 5;\n}\n");
        assert_eq!(count_key(&other_variable, "javascript:S2310"), 0);
    }

    #[test]
    fn s135_flags_more_than_one_direct_exit_point() {
        let two_breaks =
            js_keys("while (a) {\n  if (b) {\n    break;\n  }\n  if (c) {\n    break;\n  }\n}\n");
        assert_eq!(count_key(&two_breaks, "javascript:S135"), 1);

        let one_break = js_keys("while (a) {\n  if (b) {\n    break;\n  }\n  f();\n}\n");
        assert_eq!(count_key(&one_break, "javascript:S135"), 0);

        // Breaks inside a nested loop count for the inner loop only.
        let nested = js_keys(
            "while (a) {\n  if (b) {\n    break;\n  }\n  while (c) {\n    if (d) {\n      break;\n    }\n    break;\n  }\n}\n",
        );
        assert_eq!(count_key(&nested, "javascript:S135"), 1);
        let inner_line = nested
            .iter()
            .find(|(key, _)| key == "javascript:S135")
            .map(|(_, line)| *line);
        assert_eq!(inner_line, Some(5));
    }

    #[test]
    fn s1751_flags_single_iteration_loops() {
        let constant_false = js_keys("while (false) {\n  f();\n}\n");
        assert_eq!(count_key(&constant_false, "javascript:S1751"), 1);

        let terminal_break = js_keys("while (x) {\n  f();\n  break;\n}\n");
        assert_eq!(count_key(&terminal_break, "javascript:S1751"), 1);

        let continue_keeps_iterations =
            js_keys("while (x) {\n  if (y) {\n    continue;\n  }\n  break;\n}\n");
        assert_eq!(count_key(&continue_keeps_iterations, "javascript:S1751"), 0);

        let ordinary = js_keys("while (x) {\n  f();\n}\n");
        assert_eq!(count_key(&ordinary, "javascript:S1751"), 0);
    }

    #[test]
    fn s2189_flags_endless_loops_without_terminators() {
        let forever = js_keys("while (true) {\n  f();\n}\n");
        assert_eq!(count_key(&forever, "javascript:S2189"), 1);

        let do_forever = js_keys("do {\n  f();\n} while (true);\n");
        assert_eq!(count_key(&do_forever, "javascript:S2189"), 1);

        let with_break = js_keys("while (true) {\n  break;\n}\n");
        assert_eq!(count_key(&with_break, "javascript:S2189"), 0);

        let with_return = js_keys("function f() {\n  for (;;) {\n    return 1;\n  }\n}\n");
        assert_eq!(count_key(&with_return, "javascript:S2189"), 0);

        // JS-only rule: TypeScript files are never flagged.
        let typescript = findings("while (true) {\n  f();\n}\n", JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S2189"), 0);
    }

    #[test]
    fn s1535_requires_hasownproperty_guard_in_for_in() {
        let bare = js_keys("for (const k in obj) {\n  f(k);\n}\n");
        assert_eq!(count_key(&bare, "javascript:S1535"), 1);

        let guarded =
            js_keys("for (const k in obj) {\n  if (obj.hasOwnProperty(k)) {\n    f(k);\n  }\n}\n");
        assert_eq!(count_key(&guarded, "javascript:S1535"), 0);
    }

    #[test]
    fn s4139_flags_for_in_over_arrays_and_strings() {
        let array = js_keys("for (const v in [\"a\", \"b\"]) {\n  f(v);\n}\n");
        assert_eq!(count_key(&array, "javascript:S4139"), 1);

        let string = js_keys("for (const v in \"ab\") {\n  f(v);\n}\n");
        assert_eq!(count_key(&string, "javascript:S4139"), 1);

        let object = js_keys("for (const v in obj) {\n  f(v);\n}\n");
        assert_eq!(count_key(&object, "javascript:S4139"), 0);
    }

    #[test]
    fn s4138_flags_for_of_over_non_iterables() {
        let object = js_keys("for (const v of { a: 1 }) {\n  f(v);\n}\n");
        assert_eq!(count_key(&object, "javascript:S4138"), 1);

        let number = js_keys("for (const v of 5) {\n  f(v);\n}\n");
        assert_eq!(count_key(&number, "javascript:S4138"), 1);

        let array = js_keys("for (const v of [1, 2]) {\n  f(v);\n}\n");
        assert_eq!(count_key(&array, "javascript:S4138"), 0);
    }

    #[test]
    fn too_many_parameters_flags_eighth_and_counts_rest() {
        assert_eq!(
            count_key(
                &js_keys("function f(a, b, c, d, e, g, h) { return a; }\n"),
                "javascript:S107"
            ),
            0
        );

        let over = js("function f(a, b, c, d, e, g, h, i) { return a; }\n");
        let s107: Vec<_> = over
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S107"))
            .collect();
        assert_eq!(s107.len(), 1);
        assert_eq!(
            s107[0].message,
            "This function has 8 parameters, which is greater than the 7 authorized."
        );
        assert_eq!(s107[0].range.start, pos(1, 10));

        // A rest parameter counts as one parameter toward the limit.
        assert_eq!(
            count_key(
                &js_keys("const f = (a, b, c, d, e, g, ...rest) => a;\n"),
                "javascript:S107"
            ),
            0
        );
        assert_eq!(
            count_key(
                &js_keys("const f = (a, b, c, d, e, g, h, ...rest) => a;\n"),
                "javascript:S107"
            ),
            1
        );
    }

    #[test]
    fn control_flow_nesting_flags_fourth_level_and_resets_per_function() {
        let deep = js("if (a) { for (;;) { while (b) { if (c) { d(); } } } }\n");
        let s134: Vec<_> = deep
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S134"))
            .collect();
        assert_eq!(s134.len(), 1);
        assert_eq!(s134[0].range.start, pos(1, 32));

        // Three levels of nesting are exactly at the allowed maximum.
        assert_eq!(
            count_key(
                &js_keys("if (a) {\n  for (;;) {\n    while (b) {\n      c();\n    }\n  }\n}\n"),
                "javascript:S134"
            ),
            0
        );

        // Function boundaries reset the depth: without the reset, `if (c)`
        // would sit at depth four.
        assert_eq!(
            count_key(
                &js_keys(
                    "function outer() {\n  if (a) {\n    function inner() {\n      if (b) {\n        if (c) {\n          e();\n        }\n      }\n    }\n  }\n}\n"
                ),
                "javascript:S134"
            ),
            0
        );
    }

    #[test]
    fn jumps_in_finally_flagged_but_catch_return_allowed() {
        let source = "\
function withReturn() {
  try {
    a();
  } finally {
    return 1;
  }
}
function catchReturn() {
  try {
    b();
  } catch (e) {
    return e;
  } finally {
    c();
  }
}
function withThrow() {
  try {
    d();
  } finally {
    throw 'x';
  }
}
function loopJump() {
  for (;;) {
    try {
      e();
    } finally {
      continue;
    }
  }
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S1143"), 3);

        // A `return` in the catch clause is fine when there is no jump of
        // its own anywhere in the try statement.
        assert_eq!(
            count_key(
                &js_keys(
                    "function f() {\n  try {\n    a();\n  } catch (err) {\n    return err;\n  }\n}\n"
                ),
                "javascript:S1143"
            ),
            0
        );
    }

    #[test]
    fn embedded_updates_and_assignments_require_statement_roots() {
        let source = "\
let i = 0;
i++;
for (i = 0; i < 3; i++) {
  foo(i++);
}
let j = i++;
foo(k = 1);
if (k = 1) {}
m = n = 1;
";
        let report = js(source);
        let embedded: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| {
                matches!(
                    issue.rule_key.as_str(),
                    "javascript:S881" | "javascript:S1121"
                )
            })
            .map(|issue| {
                (
                    issue.rule_key.clone(),
                    (
                        issue.range.start.line,
                        issue.range.start.column,
                        issue.range.end.line,
                        issue.range.end.column,
                    ),
                )
            })
            .collect();
        // Standalone `i++`, the assignment in the `for` header, and the
        // statement-root assignment are clean; everything embedded deeper
        // than a statement root is flagged once per construct.
        let hit = |rule: &str, line: u32, start: u32, end: u32| {
            (rule.to_string(), (line, start, line, end))
        };
        assert_eq!(
            embedded,
            vec![
                hit("javascript:S881", 4, 6, 9),
                hit("javascript:S881", 6, 8, 11),
                hit("javascript:S1121", 7, 4, 9),
                hit("javascript:S1121", 8, 4, 9),
                hit("javascript:S1121", 9, 4, 9),
            ]
        );
    }

    #[test]
    fn pointless_expression_statements_flagged_directives_exempt() {
        let source = "\
\"use strict\";
42;
foo;
-1;
`plain`;
void 0;
foo();
`tpl${x}`;
delete obj.a;
";
        let report = js(source);
        let pointless_lines: Vec<u32> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S905"))
            .map(|issue| issue.range.start.line)
            .collect();
        // The `"use strict"` directive prologue stays exempt; calls, template
        // substitutions, and `delete` have effects.
        assert_eq!(pointless_lines, vec![2, 3, 4, 5, 6]);
    }

    #[test]
    fn opening_brace_must_share_head_token_line() {
        let bad =
            js("function bad()\n{\n  if (a)\n  {\n    b();\n  }\n  else\n  {\n    c();\n  }\n}\n");
        let braces: Vec<_> = bad
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1105"))
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(braces, vec![(2, 0), (4, 2), (8, 2)]);

        let mixed = js(
            "class A\n{ m() { n(); } }\nswitch (x)\n{ case 1: p(); break; }\nconst f = () =>\n{ q(); };\n",
        );
        let braces: Vec<_> = mixed
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1105"))
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(braces, vec![(2, 0), (4, 0), (6, 0)]);
    }

    #[test]
    fn brace_style_tolerates_comments_between_head_and_brace() {
        // The trailing comment shares the head's line; the brace on the next
        // line is still flagged against it.
        let trailing = js("if (a) // note\n{\n  b();\n}\n");
        let braces: Vec<_> = trailing
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1105"))
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(braces, vec![(2, 0)]);

        // A comment-only line between head and brace is skipped entirely.
        let separated = js("if (a)\n// note\n{\n  b();\n}\n");
        let braces: Vec<_> = separated
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1105"))
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(braces, vec![(3, 0)]);

        // Fully 1tbs code stays clean across constructs.
        assert_eq!(
            count_key(
                &js_keys(
                    "function good() {\n  if (a) {\n    b();\n  } else {\n    c();\n  }\n  try {\n    d();\n  } catch (e) {\n    f();\n  } finally {\n    g();\n  }\n  while (a) {\n    h();\n  }\n}\n"
                ),
                "javascript:S1105"
            ),
            0
        );
    }

    #[test]
    fn labels_on_switch_cases_and_non_loops_are_flagged() {
        assert_eq!(
            count_key(
                &js_keys("switch (x) {\n  case 1:\n    outer: break;\n}\n"),
                "javascript:S1219"
            ),
            1
        );

        assert_eq!(
            count_key(
                &js_keys("outer: for (;;) {\n  break outer;\n}\n"),
                "javascript:S1439"
            ),
            0
        );

        assert_eq!(
            count_key(&js_keys("outer: {\n  f();\n}\n"), "javascript:S1439"),
            1
        );
    }

    #[test]
    fn declare_then_return_and_throw_pairs_are_flagged() {
        let source = "\
function f() {
  const value = compute();
  return value;
}
function g() {
  let failure = build();
  throw failure;
}
function clean() {
  const kept = compute();
  return other;
}
";
        let report = js(source);
        let s1488: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1488"))
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(s1488, vec![2, 6]);
    }

    #[test]
    fn statements_after_jumps_are_unreachable() {
        let source = "\
function f() {
  return 1;
  g();
}
function clean() {
  if (a) {
    return 1;
  }
  g();
}
";
        let report = js(source);
        let s1763: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1763"))
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(s1763, vec![3]);
    }

    #[test]
    fn functions_in_loops_blocks_and_depths_are_flagged() {
        // S1515: a closure created inside a loop body.
        let in_loop = js_keys("for (const v of items) {\n  setTimeout(() => v);\n}\n");
        assert_eq!(count_key(&in_loop, "javascript:S1515"), 1);

        let in_header = js_keys("for (const f of makers) {\n  f();\n}\n");
        assert_eq!(count_key(&in_header, "javascript:S1515"), 0);

        // S1530: function declaration nested in a block; top level is fine.
        let in_block = js_keys("{\n  function inner() {}\n}\n");
        assert_eq!(count_key(&in_block, "javascript:S1530"), 1);
        let top_level = js_keys("function outer() {}\n");
        assert_eq!(count_key(&top_level, "javascript:S1530"), 0);

        // S2004: five levels of nesting exceed the maximum of four.
        let deep_keys = js_keys(
            "function a() {\n  const b = () => {\n    const c = () => {\n      const d = () => {\n        const e = () => {};\n      };\n    };\n  };\n}\n",
        );
        assert_eq!(count_key(&deep_keys, "javascript:S2004"), 1);
        assert_eq!(count_key(&deep_keys, "javascript:S1515"), 0);

        // Four levels are exactly at the allowed maximum.
        assert_eq!(
            count_key(
                &js_keys(
                    "function a() {\n  const b = () => {\n    const c = () => {\n      const d = () => {};\n    };\n  };\n}\n"
                ),
                "javascript:S2004"
            ),
            0
        );
    }

    #[test]
    fn default_parameters_must_come_last() {
        let ordered = js_keys("function f(a, b = 1, c = 2) { return a; }\n");
        assert_eq!(count_key(&ordered, "javascript:S1788"), 0);

        let unordered = js_keys("function f(a = 1, b) { return b; }\n");
        assert_eq!(count_key(&unordered, "javascript:S1788"), 1);
    }

    #[test]
    fn call_arguments_split_across_lines_are_flagged() {
        let split = js("foo(\n  bar);\n");
        let s1472: Vec<_> = split
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1472"))
            .collect();
        assert_eq!(s1472.len(), 1);
        assert_eq!(
            s1472[0].range,
            hoonarqube_ir::Range {
                start: pos(2, 2),
                end: pos(2, 5),
            }
        );

        assert_eq!(count_key(&js_keys("foo(bar);\n"), "javascript:S1472"), 0);
    }

    #[test]
    fn self_assignments_are_flagged_for_names_and_chains() {
        let source = "\
a = a;
obj.x = obj.x;
b = c;
";
        let report = js(source);
        let s1656_lines: Vec<u32> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1656"))
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(s1656_lines, vec![1, 2]);
    }
    #[test]
    fn exception_handling_rules_flag_empty_rethrow_and_setter_returns() {
        let source = "\
function rethrowOnly() {
  try {
    a();
  } catch (e) {
    throw e;
  }
}
function meaningful() {
  try {
    b();
  } catch (e) {
    log(e);
    throw e;
  }
}
function silent() {
  try {
    c();
  } catch {
  }
}
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S2737"), 1);
        // The comment-only catch is tolerated by `S2486`.
        let with_comment = js_keys(
            "function f() {\n  try {\n    d();\n  } catch {\n    // ignored on purpose\n  }\n}\n",
        );
        assert_eq!(count_key(&with_comment, "javascript:S2486"), 0);
        assert_eq!(count_key(&keys, "javascript:S2486"), 1);

        // A setter returning a value is flagged only for JavaScript files.
        let setter_source = "class A {\n  set value(next) {\n    return next;\n  }\n}\n";
        assert_eq!(
            js(setter_source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S2432"))
                .count(),
            1
        );
        assert_eq!(
            ts(setter_source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S2432"))
                .count(),
            0
        );
    }

    #[test]
    fn delete_prototype_and_generator_rules_flag_expected_shapes() {
        let delete_plain = js_keys("delete variable;\n");
        assert_eq!(count_key(&delete_plain, "javascript:S3001"), 1);
        let delete_member = js_keys("delete obj.field;\n");
        assert_eq!(count_key(&delete_member, "javascript:S3001"), 0);

        let prototype_assignment = js_keys("Type.prototype.method = function () {};\n");
        assert_eq!(count_key(&prototype_assignment, "javascript:S3525"), 1);
        let plain_assignment = js_keys("obj.handler = function () {};\n");
        assert_eq!(count_key(&plain_assignment, "javascript:S3525"), 0);

        let empty_generator = js_keys("function* generate() {}\n");
        assert_eq!(count_key(&empty_generator, "javascript:S3531"), 1);
        let yielding_generator = js_keys("function* generate() {\n  yield 1;\n}\n");
        assert_eq!(count_key(&yielding_generator, "javascript:S3531"), 0);
        // A yield inside a nested generator belongs to that nested function.
        let nested_yield_only =
            js_keys("function* outer() {\n  function* inner() {\n    yield 1;\n  }\n}\n");
        assert_eq!(count_key(&nested_yield_only, "javascript:S3531"), 1);
    }

    #[test]
    fn trailing_jumps_flagged_only_in_redundant_positions() {
        let loop_break = js_keys("while (a) {\n  break;\n}\n");
        assert_eq!(count_key(&loop_break, "javascript:S3626"), 1);

        let bare_block = js("function f() {\n  {\n    return 1;\n  }\n}\n");
        let s3626_lines: Vec<u32> = bare_block
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S3626"))
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(s3626_lines, vec![3]);

        // Function bodies and case bodies end with jumps conventionally.
        let conventional = js_keys("switch (x) {\n  case 1:\n    break;\n}\n");
        assert_eq!(count_key(&conventional, "javascript:S3626"), 0);
        let fn_tail = js_keys("function f() {\n  return 1;\n}\n");
        assert_eq!(count_key(&fn_tail, "javascript:S3626"), 0);
    }

    #[test]
    fn getters_without_setters_are_flagged_on_classes_and_objects() {
        let class_unpaired = js_keys("class A {\n  get value() {\n    return 1;\n  }\n}\n");
        assert_eq!(count_key(&class_unpaired, "javascript:S2376"), 1);
        let class_paired =
            js_keys("class A {\n  get value() {\n    return 1;\n  }\n  set value(next) {}\n}\n");
        assert_eq!(count_key(&class_paired, "javascript:S2376"), 0);

        let object_unpaired =
            js_keys("const obj = {\n  get count() {\n    return this.n;\n  }\n};\n");
        assert_eq!(count_key(&object_unpaired, "javascript:S2376"), 1);
    }

    #[test]
    fn swapped_call_arguments_detected_by_name_match() {
        let source = "\
function draw(width, height) {}
draw(height, width);
draw(width, height);
draw(other, more);
";
        let report = js(source);
        let s2234_lines: Vec<u32> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S2234"))
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(s2234_lines, vec![2]);
    }

    #[test]
    fn mixed_arrow_body_styles_flag_the_minority() {
        let minority_block =
            js_keys("const a = () => 1;\nconst b = () => 2;\nconst c = () => {\n  return 3;\n};\n");
        assert_eq!(count_key(&minority_block, "javascript:S3524"), 1);

        let consistent = js_keys("const a = () => 1;\nconst b = () => 2;\n");
        assert_eq!(count_key(&consistent, "javascript:S3524"), 0);

        // On ties the expression-bodied arrows are flagged.
        let tie = js_keys("const a = () => {\n  return 1;\n};\nconst b = () => 2;\n");
        assert_eq!(count_key(&tie, "javascript:S3524"), 1);
    }
    #[test]
    fn cognitive_complexity_threshold_and_nesting_weights() {
        // Five chained ifs: 1+2+3+4+5 = 15, exactly at the threshold: clean.
        let at_limit = js_keys(
            "function f(a) {\n  if (a) {\n    if (a) {\n      if (a) {\n        if (a) {\n          if (a) {}\n        }\n      }\n    }\n  }\n}\n",
        );
        assert_eq!(count_key(&at_limit, "javascript:S3776"), 0);

        // One more nesting level: 21 > 15.
        let over = js_keys(
            "function f(a) {\n  if (a) {\n    if (a) {\n      if (a) {\n        if (a) {\n          if (a) {\n            while (a) {}\n          }\n        }\n      }\n    }\n  }\n}\n",
        );
        assert_eq!(count_key(&over, "javascript:S3776"), 1);
        assert_eq!(
            over.iter()
                .find(|(key, _)| key == "javascript:S3776")
                .map(|(_, line)| *line),
            Some(1)
        );

        // Logical operator sequences: same chain counts once, a switch
        // counts again; nested functions are measured separately.
        let logicals = js_keys("function f(a, b) {\n  if (a && b && a && b || b) {}\n}\n");
        assert_eq!(count_key(&logicals, "javascript:S3776"), 0);
    }

    #[test]
    fn cyclomatic_complexity_boundary_is_ten() {
        let source = |count: usize| {
            let mut text = String::from("function f(a) {\n");
            for _ in 0..count {
                text.push_str("  if (a) {}\n");
            }
            text.push_str("}\n");
            js_keys(&text)
        };
        // 9 ifs + base 1 = 10: clean. 10 ifs = 11: flagged.
        assert_eq!(count_key(&source(9), "javascript:S1541"), 0);
        assert_eq!(count_key(&source(10), "javascript:S1541"), 1);
    }

    #[test]
    fn mixed_return_styles_are_flagged() {
        let mixed = js_keys("function f(c) {\n  if (c) {\n    return 1;\n  }\n  return;\n}\n");
        assert_eq!(count_key(&mixed, "javascript:S3801"), 1);

        // Valued returns plus an implicit fall-off end.
        let falls_off = js_keys("function g(c) {\n  if (c) {\n    return 1;\n  }\n}\n");
        assert_eq!(count_key(&falls_off, "javascript:S3801"), 1);

        let consistent =
            js_keys("function h(c) {\n  if (c) {\n    return 1;\n  }\n  return 2;\n}\n");
        assert_eq!(count_key(&consistent, "javascript:S3801"), 0);

        // Constructors, accessors, and generators are exempt.
        let exempt = js_keys(
            "class C {\n  constructor(c) {\n    if (c) {\n      return 1;\n    }\n  }\n  get v() {\n    return 2;\n  }\n}\nfunction* gen(c) {\n  if (c) {\n    return 1;\n  }\n  yield 2;\n}\n",
        );
        assert_eq!(count_key(&exempt, "javascript:S3801"), 0);
    }

    #[test]
    fn array_callbacks_without_returns_flagged_javascript_only() {
        let flagged = js_keys("[1].map(function f(x) {\n  g(x);\n});\n");
        assert_eq!(count_key(&flagged, "javascript:S3796"), 1);

        let block_arrow = js_keys("[1].filter(x => {\n  g(x);\n});\n");
        assert_eq!(count_key(&block_arrow, "javascript:S3796"), 1);

        // Expression-bodied arrows and valued callbacks are clean; forEach
        // callbacks legitimately return nothing and are never flagged.
        let clean = js_keys(
            "[1].map(x => x * 2);\n[1].every(function (x) {\n  return x > 0;\n});\n[1].forEach(function (x) {\n  g(x);\n});\n",
        );
        assert_eq!(count_key(&clean, "javascript:S3796"), 0);

        // A return inside a nested function does not count for the callback.
        let nested = js_keys(
            "[1].map(function (x) {\n  setTimeout(function () {\n    return 5;\n  });\n});\n",
        );
        assert_eq!(count_key(&nested, "javascript:S3796"), 1);

        let typescript = findings(
            "[1].map(function f(x) {\n  g(x);\n});\n",
            JstsLanguage::TypeScript,
        );
        assert_eq!(count_key(&typescript, "typescript:S3796"), 0);
    }
    #[test]
    fn constructor_super_call_defects_are_flagged() {
        // Missing super() with a base class.
        let missing = js_keys("class A extends B {\n  constructor() {\n    this.x = 1;\n  }\n}\n");
        assert_eq!(count_key(&missing, "javascript:S3854"), 1);
        // this-use is not separately flagged when no super() exists at all.

        // Duplicate super() calls.
        let duplicated =
            js_keys("class A extends B {\n  constructor() {\n    super();\n    super();\n  }\n}\n");
        assert_eq!(count_key(&duplicated, "javascript:S3854"), 1);

        // Conditional super() must move to the top.
        let conditional = js_keys(
            "class A extends B {\n  constructor(c) {\n    if (c) {\n      super();\n    }\n  }\n}\n",
        );
        assert_eq!(count_key(&conditional, "javascript:S3854"), 1);

        // Well-formed constructor: clean, and classes without heritage are
        // never flagged for a missing super().
        let clean = js_keys(
            "class A extends B {\n  constructor() {\n    super();\n    this.x = 1;\n  }\n}\nclass C {\n  constructor() {\n    this.x = 1;\n  }\n}\n",
        );
        assert_eq!(count_key(&clean, "javascript:S3854"), 0);
    }

    #[test]
    fn constructors_returning_values_are_flagged() {
        let flagged =
            js_keys("class A {\n  constructor() {\n    if (x) {\n      return 1;\n    }\n  }\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S6635"), 1);

        let bare_return = js_keys("class A {\n  constructor() {\n    return;\n  }\n}\n");
        assert_eq!(count_key(&bare_return, "javascript:S6635"), 0);
    }

    #[test]
    fn accessors_must_touch_their_named_field() {
        let getter_bad = js_keys(
            "class C {\n  get size() {\n    return this.length;\n  }\n}\nconst o = {\n  get count() {\n    return 1;\n  },\n};\n",
        );
        assert_eq!(count_key(&getter_bad, "javascript:S4275"), 2);

        let setter_bad =
            js_keys("class C {\n  set size(value) {\n    this.length = value;\n  }\n}\n");
        assert_eq!(count_key(&setter_bad, "javascript:S4275"), 1);

        let clean = js_keys(
            "class C {\n  get size() {\n    return this.size;\n  }\n  set size(value) {\n    this.size = value;\n  }\n}\n",
        );
        assert_eq!(count_key(&clean, "javascript:S4275"), 0);
    }

    #[test]
    fn else_catch_finally_keywords_must_sit_on_their_own_line() {
        let same_line_else = js_keys("if (a) {\n  b();\n} else {\n  c();\n}\n");
        assert_eq!(count_key(&same_line_else, "javascript:S3972"), 1);

        let same_line_catch =
            js_keys("try {\n  a();\n} catch (e) {\n  b(e);\n} finally {\n  c();\n}\n");
        assert_eq!(count_key(&same_line_catch, "javascript:S3972"), 2);

        let separated = js_keys(
            "if (a) {\n  b();\n}\nelse\n{\n  c();\n}\ntry {\n  a();\n}\ncatch (e) {\n  b(e);\n}\nfinally {\n  c();\n}\n",
        );
        assert_eq!(count_key(&separated, "javascript:S3972"), 0);
    }

    #[test]
    fn unbraced_bodies_must_be_indented_deeper() {
        let flagged = js_keys("function f() {\n  while (a)\n  b();\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S3973"), 1);

        // Same-line bodies and properly indented bodies are clean.
        let clean = js_keys("function f() {\n  if (a) b();\n  if (a)\n    c();\n}\n");
        assert_eq!(count_key(&clean, "javascript:S3973"), 0);
    }

    #[test]
    fn membership_in_operator_on_arrays_is_flagged() {
        let literal_rhs = js_keys("const ok = 'a' in obj;\nconst bad = 'a' in [1, 2];\n");
        assert_eq!(count_key(&literal_rhs, "javascript:S4619"), 1);

        let binding_rhs =
            js_keys("const xs = [];\nif ('a' in xs) {\n  g();\n}\nconst fine = k2 in obj;\n");
        assert_eq!(count_key(&binding_rhs, "javascript:S4619"), 1);
        // Object right-hand sides are untouched; only arrays flag.
    }

    #[test]
    fn immediately_settled_promise_executors_are_flagged() {
        let flagged = js_keys("new Promise(resolve => resolve(42));\n");
        assert_eq!(count_key(&flagged, "javascript:S4634"), 1);

        let async_work =
            js_keys("new Promise(resolve => {\n  setTimeout(() => resolve(42), 10);\n});\n");
        assert_eq!(count_key(&async_work, "javascript:S4634"), 0);
    }

    #[test]
    fn rejecting_literal_values_is_flagged() {
        let flagged = js_keys("Promise.reject('boom');\nfunction f(reject) {\n  reject(7);\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S6671"), 2);

        let clean = js_keys("Promise.reject(new Error('boom'));\n");
        assert_eq!(count_key(&clean, "javascript:S6671"), 0);
    }

    #[test]
    fn unawaited_promise_calls_inside_try_are_flagged() {
        let flagged = js_keys(
            "try {\n  fetch(url);\n  client.then(r => r.json());\n  await fetch(other);\n} catch (e) {\n  log(e);\n}\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S4822"), 2);

        let awaited_only = js_keys("try {\n  await fetch(url);\n} catch (e) {\n  log(e);\n}\n");
        assert_eq!(count_key(&awaited_only, "javascript:S4822"), 0);
    }
    #[test]
    fn duplicated_object_and_class_keys_are_flagged() {
        let object = js_keys("const o = {\n  a: 1,\n  b: 2,\n  'a': 3,\n};\n");
        assert_eq!(count_key(&object, "javascript:S1534"), 1);

        // Getter plus setter of one name pair up; two getters collide.
        let class_dupes = js_keys(
            "class C {\n  m() {}\n  m() {}\n  get p() {}\n  set p(v) {}\n  get q() {}\n  get q() {}\n}\n",
        );
        assert_eq!(count_key(&class_dupes, "javascript:S1534"), 2);

        let clean = js_keys("const o = { a: 1, b: 2 };\nclass D {\n  x() {}\n  y() {}\n}\n");
        assert_eq!(count_key(&clean, "javascript:S1534"), 0);
    }

    #[test]
    fn duplicated_function_parameters_are_javascript_only() {
        let flagged = js_keys("function f(a, b, a) {\n  return a + b;\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S1536"), 1);

        let clean = js_keys("function f(a, b, c) {\n  return a + b;\n}\n");
        assert_eq!(count_key(&clean, "javascript:S1536"), 0);

        let typescript = findings(
            "function f(a, b, a) {\n  return a + b;\n}\n",
            JstsLanguage::TypeScript,
        );
        assert_eq!(count_key(&typescript, "typescript:S1536"), 0);
    }

    #[test]
    fn mutable_exports_are_flagged() {
        let flagged = js_keys("export let counter = 1;\nexport var legacy = 2;\n");
        assert_eq!(count_key(&flagged, "javascript:S6861"), 2);

        let clean = js_keys("export const stable = 1;\nconst renamed = 2;\nexport { renamed };\n");
        assert_eq!(count_key(&clean, "javascript:S6861"), 0);
    }

    #[test]
    fn condition_operator_limit_is_three() {
        let at_limit = js_keys("if (a && b && c && d) {\n  g();\n}\n");
        assert_eq!(count_key(&at_limit, "javascript:S1067"), 0);

        let over = js_keys("while (a && !b && c || d) {\n  g();\n}\n");
        assert_eq!(count_key(&over, "javascript:S1067"), 1);

        // Conditions inside nested functions are their own units and are
        // still examined when reached.
        let nested = js_keys("const g = () => {\n  if (a && b && c && d && e) {}\n};\n");
        assert_eq!(count_key(&nested, "javascript:S1067"), 1);
    }
    #[test]
    fn nested_ternaries_are_flagged_in_both_branches() {
        let flagged =
            js_keys("const a = cond ? (x ? 1 : 2) : 3;\nconst b = cond ? 1 : (y ? 2 : 3);\n");
        assert_eq!(count_key(&flagged, "javascript:S3358"), 2);

        let clean = js_keys("const ok = cond ? 1 : 2;\n");
        assert_eq!(count_key(&clean, "javascript:S3358"), 0);
    }

    #[test]
    fn shorthand_property_rules_flag_order_and_redundancy() {
        // `{ a: a }` should be shorthand.
        let redundant = js_keys("const o = { a: a };\n");
        assert_eq!(count_key(&redundant, "javascript:S3498"), 1);

        // Shorthand after non-shorthand is out of order; different names are
        // never flagged.
        let ordering = js_keys("const p = { a: 1, b, c: c };\n");
        assert_eq!(count_key(&ordering, "javascript:S3499"), 1);
        assert_eq!(count_key(&ordering, "javascript:S3498"), 1);

        let clean = js_keys("const q = { b, a: 1 };\n");
        assert_eq!(count_key(&clean, "javascript:S3499"), 0);
        assert_eq!(count_key(&clean, "javascript:S3498"), 0);
    }

    #[test]
    fn pure_string_concatenation_suggests_template_literals() {
        let flagged = js_keys("const s = 'a' + 'b' + 'c';\n");
        // Only the outermost chain root is flagged.
        assert_eq!(count_key(&flagged, "javascript:S3512"), 1);

        let dynamic = js_keys("const t = 'a' + name;\n");
        assert_eq!(count_key(&dynamic, "javascript:S3512"), 0);
    }

    #[test]
    fn arguments_reads_are_flagged_unless_shadowed() {
        let flagged = js_keys("function f() {\n  return arguments.length;\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S3513"), 1);

        // A parameter named `arguments` shadows the built-in for its scope.
        let shadowed = js_keys("function g(arguments) {\n  return arguments.length;\n}\n");
        assert_eq!(count_key(&shadowed, "javascript:S3513"), 0);
    }

    #[test]
    fn temp_variable_swaps_suggest_destructuring() {
        let flagged = js_keys("let t = a;\na = b;\nb = t;\n");
        assert_eq!(count_key(&flagged, "javascript:S3514"), 1);

        // Unrelated statement sequences stay untouched.
        let clean = js_keys("let u = a;\nwork(u);\nreturn u;\n");
        assert_eq!(count_key(&clean, "javascript:S3514"), 0);
    }

    #[test]
    fn function_constructor_is_javascript_only() {
        let flagged = js_keys("const f = new Function('a', 'return a');\n");
        assert_eq!(count_key(&flagged, "javascript:S3523"), 1);

        let typescript = findings(
            "const f = new Function('a', 'return a');\n",
            JstsLanguage::TypeScript,
        );
        assert_eq!(count_key(&typescript, "typescript:S3523"), 0);
    }

    #[test]
    fn operations_on_empty_array_literals_are_flagged() {
        let member = js_keys("const n = [].length;\n[].forEach(g);\n");
        assert_eq!(count_key(&member, "javascript:S4158"), 2);

        let populated = js_keys("const m = [1].length;\n");
        assert_eq!(count_key(&populated, "javascript:S4158"), 0);
    }

    #[test]
    fn null_guards_rewrite_to_optional_chaining() {
        let flagged =
            js_keys("if (a !== null && a.b) {\n  g();\n}\nconst v = a !== undefined && a.b();\n");
        assert_eq!(count_key(&flagged, "javascript:S6582"), 2);

        // Guards whose right side does not use the guarded identifier, or
        // that already use optional chaining semantics on other roots, are
        // left alone.
        let unrelated = js_keys("if (a !== null && b.c) {\n  g();\n}\n");
        assert_eq!(count_key(&unrelated, "javascript:S6582"), 0);
    }

    #[test]
    fn match_with_global_regex_prefers_match_all() {
        let flagged = js_keys("const hits = text.match(/ab/g);\n");
        assert_eq!(count_key(&flagged, "javascript:S6594"), 1);

        let no_global = js_keys("const one = text.match(/ab/);\n");
        assert_eq!(count_key(&no_global, "javascript:S6594"), 0);
    }

    // ----- Regex-literal family (Batch3, check_regex_family) -----

    #[test]
    fn invalid_regex_literals_are_flagged() {
        // Unbalanced parenthesis, unknown group header, and reversed class
        // range are definite syntax errors for the mini parser.
        assert_eq!(
            count_key(&js_keys("const re = /(/;\n"), "javascript:S5856"),
            1
        );
        assert_eq!(
            count_key(&js_keys("const re = /(?P<name>a)/;\n"), "javascript:S5856"),
            1
        );
        assert_eq!(
            count_key(&js_keys("const re = /[z-a]/;\n"), "javascript:S5856"),
            1
        );

        let clean = js_keys("const re = /ab+/;\n");
        assert_eq!(count_key(&clean, "javascript:S5856"), 0);

        // Forward class ranges are valid JavaScript; only reversed ones are
        // definite errors.
        let ranges = js_keys("const re = /[A-Z][a-z0-9]*/;\n");
        assert_eq!(count_key(&ranges, "javascript:S5856"), 0);

        // An escape on either side of a dash stays valid: `[a-z\d]` parses
        // as range plus shorthand, and `[a-\d]` keeps the dash literal
        // (Annex B) instead of failing.
        let mixed = js_keys("const re = /[a-z\\d]/;\n");
        assert_eq!(count_key(&mixed, "javascript:S5856"), 0);
        let dash_escape = js_keys("const re = /[a-\\d]/;\n");
        assert_eq!(count_key(&dash_escape, "javascript:S5856"), 0);

        // The family is cataloged for both languages; the prefix follows the
        // file language.
        let typescript = findings("const re = /[z-a]/;\n", JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S5856"), 1);
    }

    #[test]
    fn constant_regexp_constructor_prefers_literal() {
        let flagged = js_keys("const re = new RegExp('ab+c');\nRegExp('\\\\d+', 'g');\n");
        assert_eq!(count_key(&flagged, "javascript:S6325"), 2);

        // A substitution-free template literal also counts as constant.
        let template = js_keys("const re = new RegExp(`ab+c`);\n");
        assert_eq!(count_key(&template, "javascript:S6325"), 1);

        let dynamic = js_keys("const re = new RegExp(userPattern);\n");
        assert_eq!(count_key(&dynamic, "javascript:S6325"), 0);

        let literal_form = js_keys("const re = /ab+c/;\n");
        assert_eq!(count_key(&literal_form, "javascript:S6325"), 0);
    }

    #[test]
    fn empty_character_classes_are_flagged() {
        let empty = js_keys("const re = /[]/;\n");
        assert_eq!(count_key(&empty, "javascript:S2639"), 1);

        let negated = js_keys("const re = /[^]/;\n");
        assert_eq!(count_key(&negated, "javascript:S2639"), 1);

        let clean = js_keys("const re = /[ab]/;\n");
        assert_eq!(count_key(&clean, "javascript:S2639"), 0);
    }

    #[test]
    fn empty_alternation_branches_are_flagged() {
        let trailing = js_keys("const re = /a|/;\n");
        assert_eq!(count_key(&trailing, "javascript:S6323"), 1);

        let leading = js_keys("const re = /|b/;\n");
        assert_eq!(count_key(&leading, "javascript:S6323"), 1);

        // An empty branch inside a group belongs here, not to S6331.
        let in_group = js_keys("const re = /(a|)/;\n");
        assert_eq!(count_key(&in_group, "javascript:S6323"), 1);

        let clean = js_keys("const re = /a|b/;\n");
        assert_eq!(count_key(&clean, "javascript:S6323"), 0);
    }

    #[test]
    fn wholly_empty_groups_are_flagged() {
        let capturing = js_keys("const re = /()/;\n");
        assert_eq!(count_key(&capturing, "javascript:S6331"), 1);
        // A wholly empty group is not reported as an empty alternative.
        assert_eq!(count_key(&capturing, "javascript:S6323"), 0);

        let non_capturing = js_keys("const re = /(?:)/;\n");
        assert_eq!(count_key(&non_capturing, "javascript:S6331"), 1);

        let clean = js_keys("const re = /(a)/;\n");
        assert_eq!(count_key(&clean, "javascript:S6331"), 0);
    }

    #[test]
    fn duplicate_class_members_are_flagged() {
        let duplicated = js_keys("const re = /[aa]/;\n");
        assert_eq!(count_key(&duplicated, "javascript:S5869"), 1);
        // Duplicate-only classes additionally receive the concise rewrite.
        assert_eq!(count_key(&duplicated, "javascript:S6353"), 1);

        let twice = js_keys("const re = /[aaa]/;\n");
        assert_eq!(count_key(&twice, "javascript:S5869"), 2);

        let clean = js_keys("const re = /[ab]/;\n");
        assert_eq!(count_key(&clean, "javascript:S5869"), 0);
    }

    #[test]
    fn single_member_classes_are_flagged() {
        let single = js_keys("const re = /[a]/;\n");
        assert_eq!(count_key(&single, "javascript:S6397"), 1);

        // Shorthand escapes are not literal characters and stay out of the
        // rewrite scope.
        let escape = js_keys("const re = /[\\d]/;\n");
        assert_eq!(count_key(&escape, "javascript:S6397"), 0);

        let clean = js_keys("const re = /[ab]/;\n");
        assert_eq!(count_key(&clean, "javascript:S6397"), 0);
    }

    #[test]
    fn redundant_quantifier_shapes_are_flagged() {
        let exact = js_keys("const re = /a{1}/;\n");
        assert_eq!(count_key(&exact, "javascript:S6353"), 1);

        let explicit_range = js_keys("const re = /ab{1,1}c/;\n");
        assert_eq!(count_key(&explicit_range, "javascript:S6353"), 1);

        let clean = js_keys("const re = /a{2}/;\n");
        assert_eq!(count_key(&clean, "javascript:S6353"), 0);
    }

    #[test]
    fn space_runs_in_patterns_are_flagged() {
        let double = js_keys("const re = /a  b/;\n");
        assert_eq!(count_key(&double, "javascript:S6326"), 1);

        let triple = js_keys("const re = /a   b/;\n");
        assert_eq!(count_key(&triple, "javascript:S6326"), 1);

        let clean = js_keys("const re = /a b/;\n");
        assert_eq!(count_key(&clean, "javascript:S6326"), 0);
    }

    #[test]
    fn bare_control_characters_are_flagged() {
        let control = js_keys("const re = /a\u{0001}b/;\n");
        assert_eq!(count_key(&control, "javascript:S6324"), 1);

        // Tab/newline conventions are exempt.
        let tab = js_keys("const re = /a\tb/;\n");
        assert_eq!(count_key(&tab, "javascript:S6324"), 0);
    }

    #[test]
    fn replacement_group_references_are_validated() {
        let out_of_range = js_keys("'ab'.replace(/(a)(b)/, '$3');\n");
        assert_eq!(count_key(&out_of_range, "javascript:S6328"), 1);

        let unknown_name = js_keys("'a'.replace(/(?<first>a)/, '$<second>');\n");
        assert_eq!(count_key(&unknown_name, "javascript:S6328"), 1);

        let clean = js_keys("'ab'.replace(/(a)(b)/, '$2$1');\n'a'.replace(/(?<x>a)/, '$<x>');\n");
        assert_eq!(count_key(&clean, "javascript:S6328"), 0);

        // `$$` escapes the dollar and never references a group.
        let escaped = js_keys("'ab'.replace(/(a)/, '$$1');\n");
        assert_eq!(count_key(&escaped, "javascript:S6328"), 0);
    }

    #[test]
    fn empty_string_repetition_is_flagged() {
        // Bounded repetition over a group that can match empty still loops.
        let bounded = js_keys("const re = /x(a*){2}y/;\n");
        assert_eq!(count_key(&bounded, "javascript:S5842"), 1);

        // `(a*)+` trips both this rule and exponential backtracking.
        let unbounded = js_keys("const re = /(a*)+b/;\n");
        assert_eq!(count_key(&unbounded, "javascript:S5842"), 1);
        assert_eq!(count_key(&unbounded, "javascript:S5852"), 1);

        let clean = js_keys("const re = /(a+){2}/;\n");
        assert_eq!(count_key(&clean, "javascript:S5842"), 0);
    }

    #[test]
    fn pointless_reluctant_quantifiers_are_flagged() {
        let reluctant = js_keys("const re = /a*?b*/;\n");
        assert_eq!(count_key(&reluctant, "javascript:S6019"), 1);

        let clean = js_keys("const re = /a*?b/;\n");
        assert_eq!(count_key(&clean, "javascript:S6019"), 0);
    }

    #[test]
    fn single_char_alternations_become_classes() {
        let top_level = js_keys("const re = /a|b|c/;\n");
        assert_eq!(count_key(&top_level, "javascript:S6035"), 1);

        // Alternations nested inside groups are flagged at the group span.
        let nested = js_keys("const re = /x(a|b)y/;\n");
        assert_eq!(count_key(&nested, "javascript:S6035"), 1);

        let clean = js_keys("const re = /(ab)|c/;\n");
        assert_eq!(count_key(&clean, "javascript:S6035"), 0);
    }

    #[test]
    fn anchored_alternations_need_explicit_grouping() {
        let both_anchors = js_keys("const re = /^a|b$/;\n");
        assert_eq!(count_key(&both_anchors, "javascript:S5850"), 1);

        let start_only = js_keys("const re = /^a|b/;\n");
        assert_eq!(count_key(&start_only, "javascript:S5850"), 1);

        let grouped = js_keys("const re = /^(a|b)$/;\n");
        assert_eq!(count_key(&grouped, "javascript:S5850"), 0);

        let unanchored = js_keys("const re = /a|b/;\n");
        assert_eq!(count_key(&unanchored, "javascript:S5850"), 0);
    }

    #[test]
    fn unicode_constructs_require_the_u_flag() {
        let property_escape = js_keys("const re = /\\p{L}/;\n");
        assert_eq!(count_key(&property_escape, "javascript:S5867"), 1);

        let brace_escape = js_keys("const re = /\\u{1F600}/;\n");
        assert_eq!(count_key(&brace_escape, "javascript:S5867"), 1);

        let with_flag = js_keys("const re = /\\p{L}/u;\n");
        assert_eq!(count_key(&with_flag, "javascript:S5867"), 0);
    }

    #[test]
    fn grapheme_components_inside_classes_are_flagged() {
        // Combining acute accent after `e` matches one scalar, not `é`.
        let combining = js_keys("const re = /[e\u{0301}]/u;\n");
        assert_eq!(count_key(&combining, "javascript:S5868"), 1);

        // Each regional indicator inside a class is its own defect.
        let regional = js_keys("const flags = /[\u{1F1E6}\u{1F1E7}]/u;\n");
        assert_eq!(count_key(&regional, "javascript:S5868"), 2);

        let clean = js_keys("const re = /[ab]/u;\n");
        assert_eq!(count_key(&clean, "javascript:S5868"), 0);
    }
    #[test]
    fn regex_complexity_budget_is_enforced() {
        // Scores 29 against the budget of 20: three alternation branches
        // of quantified shorthands and classes.
        let over = js_keys("const re = /\\d{4}-\\d{2}-\\d{2}|\\d{8}|\\d{2}[A-Z]{4}/;\n");
        assert_eq!(count_key(&over, "javascript:S5843"), 1);

        let under = js_keys("const re = /\\d{4}-\\d{2}-\\d{2}/;\n");
        assert_eq!(count_key(&under, "javascript:S5843"), 0);
    }

    #[test]
    fn nested_unbounded_quantifiers_risk_backtracking() {
        let classic = js_keys("const re = /(a+)+$/;\n");
        assert_eq!(count_key(&classic, "javascript:S5852"), 1);
        // `(a+)` cannot match empty, so S5842 stays silent here.
        assert_eq!(count_key(&classic, "javascript:S5842"), 0);

        // Zero-minimum repetition escapes S5842's consuming-quantifier subset.
        let zero_min = js_keys("const re = /(a*)*b/;\n");
        assert_eq!(count_key(&zero_min, "javascript:S5852"), 1);
        assert_eq!(count_key(&zero_min, "javascript:S5842"), 0);

        let flat = js_keys("const re = /a+b+c/;\n");
        assert_eq!(count_key(&flat, "javascript:S5852"), 0);
    }

    #[test]
    fn stateful_global_regexes_inside_loops_are_flagged() {
        let while_loop =
            js_keys("while (more) {\n  if (/\\d+/g.test(input)) {\n    more = false;\n  }\n}\n");
        assert_eq!(count_key(&while_loop, "javascript:S6351"), 1);

        let for_of_loop =
            js_keys("for (const part of parts) {\n  const m = /[a-z]+/g.exec(part);\n}\n");
        assert_eq!(count_key(&for_of_loop, "javascript:S6351"), 1);

        let outside_loop = js_keys("const found = /\\d+/g.test(input);\n");
        assert_eq!(count_key(&outside_loop, "javascript:S6351"), 0);

        let not_global = js_keys("while (more) {\n  found = /\\d+/.test(input);\n}\n");
        assert_eq!(count_key(&not_global, "javascript:S6351"), 0);
    }
    // ===== Batch4 group R1 tests: React/JSX structural rules =====

    fn jsx_keys(source: &str) -> Vec<(String, u32)> {
        analyze(
            PathBuf::from("test.jsx"),
            source,
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        )
        .issues
        .into_iter()
        .map(|issue| (issue.rule_key, issue.range.start.line))
        .collect()
    }

    #[test]
    fn children_prop_conflicts_with_nested_children() {
        let both = jsx_keys("const el = <div children={<a/>}><b/></div>;\n");
        assert_eq!(count_key(&both, "javascript:S6748"), 1);

        let attribute_only = jsx_keys("const el = <div children={<a/>}/>;\n");
        assert_eq!(count_key(&attribute_only, "javascript:S6748"), 0);

        let nested_only = jsx_keys("const el = <div><b/></div>;\n");
        assert_eq!(count_key(&nested_only, "javascript:S6748"), 0);
    }

    #[test]
    fn children_and_raw_html_attributes_conflict() {
        let both = jsx_keys(
            "const el = <div children={<a/>} dangerouslySetInnerHTML={{__html: 'x'}}/>;\n",
        );
        assert_eq!(count_key(&both, "javascript:S6761"), 1);

        let raw_only = jsx_keys("const el = <div dangerouslySetInnerHTML={{__html: 'x'}}/>;\n");
        assert_eq!(count_key(&raw_only, "javascript:S6761"), 0);
    }

    #[test]
    fn single_child_fragments_are_flagged() {
        let element_child = jsx_keys("const el = <><span/></>;\n");
        assert_eq!(count_key(&element_child, "javascript:S6749"), 1);

        let expression_child = jsx_keys("let item = 1;\nconst el = <>{item}</>;\n");
        assert_eq!(count_key(&expression_child, "javascript:S6749"), 1);

        let two_children = jsx_keys("const el = <><span/><span/></>;\n");
        assert_eq!(count_key(&two_children, "javascript:S6749"), 0);

        let empty_fragment = jsx_keys("const el = <></>;\n");
        assert_eq!(count_key(&empty_fragment, "javascript:S6749"), 0);
    }

    #[test]
    fn consumed_render_results_are_flagged() {
        let consumed = jsx_keys("const el = ReactDOM.render(<span/>, node);\n");
        assert_eq!(count_key(&consumed, "javascript:S6750"), 1);

        let statement = jsx_keys("ReactDOM.render(<span/>, node);\n");
        assert_eq!(count_key(&statement, "javascript:S6750"), 0);
    }

    #[test]
    fn use_state_pairs_follow_naming_convention() {
        let symmetric = js_keys("const [count, setCount] = useState(0);\n");
        assert_eq!(count_key(&symmetric, "javascript:S6754"), 0);

        let asymmetric = js_keys("const [count, setValue] = useState(0);\n");
        assert_eq!(count_key(&asymmetric, "javascript:S6754"), 1);

        let missing_set_prefix = js_keys("const [count, countUpdated] = useState(0);\n");
        assert_eq!(count_key(&missing_set_prefix, "javascript:S6754"), 1);
    }

    #[test]
    fn noop_state_setters_are_flagged() {
        let self_assigning = js_keys("setCount(count);\n");
        assert_eq!(count_key(&self_assigning, "javascript:S6443"), 1);

        let updater = js_keys("setCount(count + 1);\n");
        assert_eq!(count_key(&updater, "javascript:S6443"), 0);

        let different_value = js_keys("setCount(other);\n");
        assert_eq!(count_key(&different_value, "javascript:S6443"), 0);
    }

    #[test]
    fn find_dom_node_calls_are_flagged() {
        let flagged = js_keys("ReactDOM.findDOMNode(this).focus();\n");
        assert_eq!(count_key(&flagged, "javascript:S6788"), 1);

        let other_root = js_keys("wrapper.findDOMNode(this);\n");
        assert_eq!(count_key(&other_root, "javascript:S6788"), 0);
    }

    #[test]
    fn is_mounted_calls_are_flagged() {
        let flagged = js_keys("if (this.isMounted()) {\n  done();\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S6789"), 1);

        let other_object = js_keys("if (widget.isMounted()) {\n  done();\n}\n");
        assert_eq!(count_key(&other_object, "javascript:S6789"), 0);
    }

    #[test]
    fn string_refs_and_refs_accesses_are_flagged() {
        let string_ref = jsx_keys("const el = <input ref=\"name\"/>;\n");
        assert_eq!(count_key(&string_ref, "javascript:S6790"), 1);

        let callback_ref = jsx_keys("const el = <input ref={(node) => save(node)}/>;\n");
        assert_eq!(count_key(&callback_ref, "javascript:S6790"), 0);

        let refs_access = js_keys("this.refs.name.focus();\n");
        assert_eq!(count_key(&refs_access, "javascript:S6790"), 1);

        let refs_write = js_keys("this.refs.name = node;\n");
        assert_eq!(count_key(&refs_write, "javascript:S6790"), 1);

        let plain_member = js_keys("this.props.name.focus();\n");
        assert_eq!(count_key(&plain_member, "javascript:S6790"), 0);
    }

    #[test]
    fn legacy_lifecycle_methods_are_flagged() {
        let flagged = js_keys(
            "class A extends B {\n  componentWillMount() {}\n  componentDidMount() {}\n}\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S6791"), 1);

        let safe = js_keys("class A extends B {\n  UNSAFE_componentWillMount() {}\n}\n");
        assert_eq!(count_key(&safe, "javascript:S6791"), 0);
    }

    #[test]
    fn deprecated_react_apis_are_flagged() {
        let prop_types_package = js_keys("import PropTypes from 'prop-types';\n");
        assert_eq!(count_key(&prop_types_package, "javascript:S6957"), 1);
        let create_class = js_keys("const x = React.createClass({});\n");
        assert_eq!(count_key(&create_class, "javascript:S6957"), 1);

        let render_call = jsx_keys("ReactDOM.render(<span/>, node);\n");
        assert_eq!(count_key(&render_call, "javascript:S6957"), 1);

        let current_api =
            js_keys("import React from 'react';\nconst x = React.createElement('div');\n");
        assert_eq!(count_key(&current_api, "javascript:S6957"), 0);
    }

    #[test]
    fn pure_component_update_is_useless() {
        let flagged = js_keys(
            "class A extends PureComponent {\n  shouldComponentUpdate() {\n    return true;\n  }\n}\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S6763"), 1);

        let plain_component = js_keys(
            "class A extends Component {\n  shouldComponentUpdate() {\n    return true;\n  }\n}\n",
        );
        assert_eq!(count_key(&plain_component, "javascript:S6763"), 0);
    }

    #[test]
    fn direct_state_mutations_are_flagged() {
        let method_mutation = js_keys("this.state.items.push(1);\n");
        assert_eq!(count_key(&method_mutation, "javascript:S6746"), 1);

        let field_write = js_keys("this.state.count = 5;\n");
        assert_eq!(count_key(&field_write, "javascript:S6746"), 1);

        let copy_first = js_keys("const copy = [...this.state.items];\ncopy.push(1);\n");
        assert_eq!(count_key(&copy_first, "javascript:S6746"), 0);

        let props_chain = js_keys("this.props.items.push(1);\n");
        assert_eq!(count_key(&props_chain, "javascript:S6746"), 0);
    }

    #[test]
    fn unescaped_jsx_entities_are_flagged() {
        // oxc's JSX lexer rejects raw `>` and `}` in text (tolerant parse
        // recovers with no AST), so the flaggable surface is quote marks.
        let double_quoted = jsx_keys("const el = <div>say \"hi\"</div>;\n");
        assert_eq!(count_key(&double_quoted, "javascript:S6766"), 1);

        let apostrophe = jsx_keys("const el = <div>it's here</div>;\n");
        assert_eq!(count_key(&apostrophe, "javascript:S6766"), 1);

        let plain_text = jsx_keys("const el = <div>plain text</div>;\n");
        assert_eq!(count_key(&plain_text, "javascript:S6766"), 0);
    }

    #[test]
    fn empty_containers_without_comments_are_flagged() {
        let empty = jsx_keys("const el = <div>{}</div>;\n");
        assert_eq!(count_key(&empty, "javascript:S6438"), 1);

        let commented = jsx_keys("const el = <div>{/* note */}</div>;\n");
        assert_eq!(count_key(&commented, "javascript:S6438"), 0);
    }

    #[test]
    fn inline_function_props_are_flagged() {
        let arrow_value = jsx_keys("const el = <button onClick={() => save()}/>;\n");
        assert_eq!(count_key(&arrow_value, "javascript:S6480"), 1);

        let bound_value = jsx_keys("const el = <button onClick={handler.bind(this)}/>;\n");
        assert_eq!(count_key(&bound_value, "javascript:S6480"), 1);

        let reference_value = jsx_keys("const el = <button onClick={handler}/>\n;\n");
        assert_eq!(count_key(&reference_value, "javascript:S6480"), 0);
    }

    #[test]
    fn map_index_keys_and_missing_keys_are_flagged() {
        let index_key = jsx_keys("items.map((item, index) => <li key={index}/>);\n");
        assert_eq!(count_key(&index_key, "javascript:S6479"), 1);
        assert_eq!(count_key(&index_key, "javascript:S6477"), 0);

        let stable_key = jsx_keys("items.map((item) => <li key={item.id}/>);\n");
        assert_eq!(count_key(&stable_key, "javascript:S6479"), 0);

        let missing_key = jsx_keys("items.map((item, index) => <li/>);\n");
        assert_eq!(count_key(&missing_key, "javascript:S6477"), 1);
    }

    #[test]
    fn unknown_lowercase_tags_are_flagged() {
        let unknown = jsx_keys("const el = <widget/>;\n");
        assert_eq!(count_key(&unknown, "javascript:S6770"), 1);

        let intrinsic = jsx_keys("const el = <div/>;\n");
        assert_eq!(count_key(&intrinsic, "javascript:S6770"), 0);

        let custom_element = jsx_keys("const el = <my-widget/>;\n");
        assert_eq!(count_key(&custom_element, "javascript:S6770"), 0);

        let component = jsx_keys("const el = <Widget/>;\n");
        assert_eq!(count_key(&component, "javascript:S6770"), 0);
    }

    #[test]
    fn render_methods_must_return_jsx_or_null() {
        let returns_jsx = js_keys("class A {\n  render() {\n    return <span/>;\n  }\n}\n");
        assert_eq!(count_key(&returns_jsx, "javascript:S6435"), 0);

        let returns_nothing = js_keys("class A {\n  render() {\n    console.log(1);\n  }\n}\n");
        assert_eq!(count_key(&returns_nothing, "javascript:S6435"), 1);

        let conditional_null = js_keys(
            "class A {\n  render() {\n    if (done) {\n      return null;\n    }\n    return <span/>;\n  }\n}\n",
        );
        assert_eq!(count_key(&conditional_null, "javascript:S6435"), 0);
    }

    #[test]
    fn literal_conditionals_rendering_children_are_flagged() {
        let numeric_guard = jsx_keys("const el = <div>{5 && <span/>}</div>;\n");
        assert_eq!(count_key(&numeric_guard, "javascript:S6439"), 1);

        let string_guard = jsx_keys("const el = <div>{'x' && <span/>}</div>;\n");
        assert_eq!(count_key(&string_guard, "javascript:S6439"), 1);

        let boolean_guard =
            jsx_keys("let ready = true;\nconst el = <div>{ready && <span/>}</div>;\n");
        assert_eq!(count_key(&boolean_guard, "javascript:S6439"), 0);

        let attribute_position = jsx_keys("const el = <div prop={5 && <span/>}/>;\n");
        assert_eq!(count_key(&attribute_position, "javascript:S6439"), 0);
    }
    #[test]
    fn hook_calls_under_conditions_are_flagged() {
        let under_if = js_keys("function C() {\n  if (ready) {\n    useState();\n  }\n}\n");
        assert_eq!(count_key(&under_if, "javascript:S6440"), 1);

        let under_loop = js_keys("for (const item of items) {\n  useState();\n}\n");
        assert_eq!(count_key(&under_loop, "javascript:S6440"), 1);

        let in_callback = js_keys("useEffect(() => {\n  useState();\n}, []);\n");
        assert_eq!(count_key(&in_callback, "javascript:S6440"), 1);

        let top_level = js_keys("function Component() {\n  const [v] = useState(0);\n}\n");
        assert_eq!(count_key(&top_level, "javascript:S6440"), 0);
    }

    #[test]
    fn undestructured_use_state_is_flagged() {
        let plain_binding = js_keys("const state = useState(0);\n");
        assert_eq!(count_key(&plain_binding, "javascript:S6442"), 1);

        let destructured = js_keys("const [value, setValue] = useState(0);\n");
        assert_eq!(count_key(&destructured, "javascript:S6442"), 0);
    }

    #[test]
    fn inline_context_values_are_flagged() {
        let object_value = jsx_keys("const el = <Ctx.Provider value={{a: 1}}/>;\n");
        assert_eq!(count_key(&object_value, "javascript:S6481"), 1);

        let array_value = jsx_keys("const el = <Ctx.Provider value={[1]}/>\n;\n");
        assert_eq!(count_key(&array_value, "javascript:S6481"), 1);

        let stable_value = jsx_keys("let memo = {};\nconst el = <Ctx.Provider value={memo}/>\n;\n");
        assert_eq!(count_key(&stable_value, "javascript:S6481"), 0);
    }

    #[test]
    fn nested_component_definitions_are_flagged() {
        let nested = jsx_keys(
            "function Outer() {\n  function Inner() {\n    return <span/>;\n  }\n  return <Inner/>;\n}\n",
        );
        assert_eq!(count_key(&nested, "javascript:S6478"), 1);

        let siblings = jsx_keys(
            "function Outer() {\n  return <span/>;\n}\nfunction Inner() {\n  return <span/>;\n}\n",
        );
        assert_eq!(count_key(&siblings, "javascript:S6478"), 0);
    }

    #[test]
    fn set_state_reading_state_is_flagged() {
        let direct_read = js_keys("this.setState({count: this.state.count + 1});\n");
        assert_eq!(count_key(&direct_read, "javascript:S6756"), 1);

        let updater = js_keys("this.setState((previous) => ({count: previous.count + 1}));\n");
        assert_eq!(count_key(&updater, "javascript:S6756"), 0);
    }

    #[test]
    fn this_in_functional_components_is_flagged() {
        let flagged = jsx_keys(
            "function Component() {\n  return <button onClick={() => this.save()}/>;\n}\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S6757"), 1);

        let class_method = js_keys("class Widget {\n  save() {\n    this.x();\n  }\n}\n");
        assert_eq!(count_key(&class_method, "javascript:S6757"), 0);
    }

    #[test]
    fn collapsing_whitespace_between_inline_siblings_is_flagged() {
        let inline_gap = jsx_keys("const el = <div><span>a</span> <b>c</b></div>;\n");
        assert_eq!(count_key(&inline_gap, "javascript:S6772"), 1);

        let block_elements = jsx_keys("const el = <div><p>a</p> <p>b</p></div>;\n");
        assert_eq!(count_key(&block_elements, "javascript:S6772"), 0);
    }

    #[test]
    fn props_without_prop_types_flagged_javascript_only() {
        let flagged = js_keys("class A {\n  m() {\n    return this.props.x;\n  }\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S6774"), 1);

        let declared = js_keys(
            "class A {\n  static propTypes = {};\n  m() {\n    return this.props.x;\n  }\n}\n",
        );
        assert_eq!(count_key(&declared, "javascript:S6774"), 0);

        let typescript_report = ts("class A {\n  m() {\n    return this.props.x;\n  }\n}\n");
        assert_eq!(
            count_key(&report_keys(&typescript_report), "typescript:S6774"),
            0
        );
    }

    #[test]
    fn default_props_require_matching_required_prop_types() {
        let missing_entry = js_keys(
            "C.propTypes = {a: PropTypes.string.isRequired};\nC.defaultProps = {a: 'x', b: 'y'};\n",
        );
        assert_eq!(count_key(&missing_entry, "javascript:S6775"), 1);

        let optional_entry =
            js_keys("C.propTypes = {a: PropTypes.string};\nC.defaultProps = {a: 'x'};\n");
        assert_eq!(count_key(&optional_entry, "javascript:S6775"), 1);

        let covered = js_keys(
            "C.propTypes = {a: PropTypes.string.isRequired};\nC.defaultProps = {a: 'x'};\n",
        );
        assert_eq!(count_key(&covered, "javascript:S6775"), 0);
    }

    #[test]
    fn unknown_jsx_attributes_are_flagged() {
        let html_spelling = jsx_keys("const el = <div class=\"x\"/>;\n");
        assert_eq!(count_key(&html_spelling, "javascript:S6747"), 1);

        let unknown_name = jsx_keys("const el = <div foo=\"1\"/>;\n");
        assert_eq!(count_key(&unknown_name, "javascript:S6747"), 1);

        let known_names = jsx_keys(
            "const el = <div className=\"x\" tabIndex={0} data-x=\"1\" aria-hidden=\"true\" onClick={f}/>;\n",
        );
        assert_eq!(count_key(&known_names, "javascript:S6747"), 0);

        let rules = RuleOptions {
            jsx_attribute_whitelist: vec!["foo".to_string()],
            ..RuleOptions::default()
        };
        let whitelisted = keys_with_rules("<div foo=\"1\"/>\n", &rules);
        assert_eq!(count_key(&whitelisted, "javascript:S6747"), 0);

        let on_component = jsx_keys("const el = <Widget arbitraryProp=\"1\"/>;\n");
        assert_eq!(count_key(&on_component, "javascript:S6747"), 0);
    }

    // ===== Batch4 group A1 tests: JSX accessibility rules =====

    #[test]
    fn alt_text_is_required_on_replaced_elements() {
        let missing = jsx_keys("const el = <img src=\"a.png\"/>;\n");
        assert_eq!(count_key(&missing, "javascript:S1077"), 1);

        let present = jsx_keys("const el = <img src=\"a.png\" alt=\"Chart\"/>;\n");
        assert_eq!(count_key(&present, "javascript:S1077"), 0);

        let image_input = jsx_keys("const el = <input type=\"image\"/>;\n");
        assert_eq!(count_key(&image_input, "javascript:S1077"), 1);

        let text_input = jsx_keys("const el = <input type=\"text\"/>;\n");
        assert_eq!(count_key(&text_input, "javascript:S1077"), 0);

        let spread_props = jsx_keys("const el = <img {...props}/>;\n");
        assert_eq!(count_key(&spread_props, "javascript:S1077"), 0);
    }

    #[test]
    fn mouse_handlers_need_focus_counterparts() {
        let alone = jsx_keys("const el = <div onMouseOver={hover}/>;\n");
        assert_eq!(count_key(&alone, "javascript:S1082"), 1);

        let paired = jsx_keys("const el = <div onMouseOver={hover} onFocus={focus}/>\n;\n");
        assert_eq!(count_key(&paired, "javascript:S1082"), 0);

        let out_blur = jsx_keys("const el = <div onMouseOut={leave} onBlur={blur}/>\n;\n");
        assert_eq!(count_key(&out_blur, "javascript:S1082"), 0);
    }

    #[test]
    fn iframes_require_titles() {
        let bare = jsx_keys("const el = <iframe/>;\n");
        assert_eq!(count_key(&bare, "javascript:S1090"), 1);

        let titled = jsx_keys("const el = <iframe title=\"Map\"/>\n;\n");
        assert_eq!(count_key(&titled, "javascript:S1090"), 0);
    }

    #[test]
    fn media_elements_need_caption_tracks() {
        let bare_video = jsx_keys("const el = <video src=\"a.mp4\"/>;\n");
        assert_eq!(count_key(&bare_video, "javascript:S4084"), 1);

        let captioned =
            jsx_keys("const el = <video src=\"a.mp4\"><track kind=\"captions\"/></video>;\n");
        assert_eq!(count_key(&captioned, "javascript:S4084"), 0);

        let bare_audio = jsx_keys("const el = <audio src=\"a.mp3\"/>;\n");
        assert_eq!(count_key(&bare_audio, "javascript:S4084"), 1);
    }

    #[test]
    fn html_elements_need_valid_language_tags() {
        let missing = jsx_keys("const el = <html><body/></html>;\n");
        assert_eq!(count_key(&missing, "javascript:S5254"), 1);

        let valid_region = jsx_keys("const el = <html lang=\"de-DE\"><body/></html>;\n");
        assert_eq!(count_key(&valid_region, "javascript:S5254"), 0);

        let numeric_primary = jsx_keys("const el = <html lang=\"123\"><body/></html>;\n");
        assert_eq!(count_key(&numeric_primary, "javascript:S5254"), 1);

        let too_short = jsx_keys("const el = <html lang=\"e\"><body/></html>;\n");
        assert_eq!(count_key(&too_short, "javascript:S5254"), 1);
    }

    #[test]
    fn tables_need_header_cells() {
        let headerless = jsx_keys("const el = <table><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&headerless, "javascript:S5256"), 1);

        let headed = jsx_keys("const el = <table><tr><th>x</th></tr></table>;\n");
        assert_eq!(count_key(&headed, "javascript:S5256"), 0);
    }

    #[test]
    fn layout_tables_need_presentation_role() {
        let plain_layout = jsx_keys("const el = <table><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&plain_layout, "javascript:S5257"), 1);

        let captioned =
            jsx_keys("const el = <table><caption>t</caption><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&captioned, "javascript:S5257"), 0);

        let presentation =
            jsx_keys("const el = <table role=\"presentation\"><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&presentation, "javascript:S5257"), 0);
    }

    #[test]
    fn header_references_must_match_th_ids() {
        let broken_reference = jsx_keys(
            "const el = <table><tr><th id=\"a\"/><td headers=\"a\"/></tr><tr><td headers=\"zzz\"/></tr></table>;\n",
        );
        assert_eq!(count_key(&broken_reference, "javascript:S5260"), 1);

        let valid_references =
            jsx_keys("const el = <table><tr><th id=\"a\"/><td headers=\"a\"/></tr></table>;\n");
        assert_eq!(count_key(&valid_references, "javascript:S5260"), 0);
    }

    #[test]
    fn object_elements_need_text_alternatives() {
        let bare = jsx_keys("const el = <object data=\"x.swf\"/>;\n");
        assert_eq!(count_key(&bare, "javascript:S5264"), 1);

        let text_child = jsx_keys("const el = <object data=\"x.swf\">fallback</object>\n;\n");
        assert_eq!(count_key(&text_child, "javascript:S5264"), 0);

        let labeled = jsx_keys("const el = <object data=\"x.swf\" aria-label=\"movie\"/>\n;\n");
        assert_eq!(count_key(&labeled, "javascript:S5264"), 0);
    }

    #[test]
    fn accesskeys_are_flagged_everywhere() {
        let flagged = jsx_keys("const el = <div accesskey=\"s\"/>;\n");
        assert_eq!(count_key(&flagged, "javascript:S6846"), 1);

        let clean = jsx_keys("const el = <div/>;\n");
        assert_eq!(count_key(&clean, "javascript:S6846"), 0);
    }

    #[test]
    fn tab_indices_are_limited_to_zero_and_minus_one() {
        let positive = jsx_keys("const el = <div tabIndex={3}/>\n;\n");
        assert_eq!(count_key(&positive, "javascript:S6841"), 1);

        let removable = jsx_keys("const el = <div tabIndex={-1}/>\n;\n");
        assert_eq!(count_key(&removable, "javascript:S6841"), 0);

        let string_value = jsx_keys("const el = <div tabIndex=\"2\"/>\n;\n");
        assert_eq!(count_key(&string_value, "javascript:S6841"), 1);

        let dynamic = jsx_keys("let t = 0;\nconst el = <div tabIndex={t}/>\n;\n");
        assert_eq!(count_key(&dynamic, "javascript:S6841"), 0);
    }
    // ===== Batch4 group A2 tests: role and value accessibility rules =====

    #[test]
    fn headings_need_text_content_or_labels() {
        let bare = jsx_keys("const el = <h1/>;\n");
        assert_eq!(count_key(&bare, "javascript:S6850"), 1);

        let textual = jsx_keys("const el = <h2>Quarterly results</h2>;\n");
        assert_eq!(count_key(&textual, "javascript:S6850"), 0);

        let aria_labeled = jsx_keys("const el = <h3 aria-label=\"Summary\"/>;\n");
        assert_eq!(count_key(&aria_labeled, "javascript:S6850"), 0);

        let titled = jsx_keys("const el = <h4 title=\"Status\"/>;\n");
        assert_eq!(count_key(&titled, "javascript:S6850"), 0);

        let nested_text = jsx_keys("const el = <h5><span>Total</span></h5>;\n");
        assert_eq!(count_key(&nested_text, "javascript:S6850"), 0);

        let not_heading = jsx_keys("const el = <p>text</p>;\n");
        assert_eq!(count_key(&not_heading, "javascript:S6850"), 0);
    }

    #[test]
    fn redundant_alt_texts_are_flagged() {
        let filler_word = jsx_keys("const el = <img src=\"report.pdf\" alt=\"Image\"/>;\n");
        assert_eq!(count_key(&filler_word, "javascript:S6851"), 1);

        let file_name = jsx_keys("const el = <img src=\"chart.png\" alt=\"Chart\"/>;\n");
        assert_eq!(count_key(&file_name, "javascript:S6851"), 1);

        let trimmed_and_cased = jsx_keys("const el = <img src=\"LOGO.png\" alt=\"  Logo \"/>;\n");
        assert_eq!(count_key(&trimmed_and_cased, "javascript:S6851"), 1);

        let descriptive =
            jsx_keys("const el = <img src=\"chart.png\" alt=\"Sales by region\"/>;\n");
        assert_eq!(count_key(&descriptive, "javascript:S6851"), 0);

        let different_stem = jsx_keys("const el = <img src=\"team.jpg\" alt=\"Office\"/>;\n");
        assert_eq!(count_key(&different_stem, "javascript:S6851"), 0);
    }

    #[test]
    fn anchors_need_href_or_accessible_text() {
        let bare_anchor = jsx_keys("const el = <a/>;\n");
        assert_eq!(count_key(&bare_anchor, "javascript:S6827"), 1);

        let linked = jsx_keys("const el = <a href=\"/docs\"/>;\n");
        assert_eq!(count_key(&linked, "javascript:S6827"), 0);

        let unlabeled_named = jsx_keys("const el = <a aria-label=\"Open docs\"/>;\n");
        assert_eq!(count_key(&unlabeled_named, "javascript:S6827"), 1);

        let textual = jsx_keys("const el = <a>Documentation</a>;\n");
        assert_eq!(count_key(&textual, "javascript:S6827"), 0);

        let other_tag = jsx_keys("const el = <span/>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S6827"), 0);
    }

    #[test]
    fn duplicate_implicit_roles_are_flagged() {
        let list_role = jsx_keys("const el = <ul role=\"list\"><li>Item</li></ul>;\n");
        assert_eq!(count_key(&list_role, "javascript:S6822"), 1);
        assert_eq!(count_key(&list_role, "javascript:S6819"), 1);

        let nav_role = jsx_keys("const el = <nav role=\"navigation\"/>;\n");
        assert_eq!(count_key(&nav_role, "javascript:S6822"), 1);
        assert_eq!(count_key(&nav_role, "javascript:S6819"), 1);

        let changed_role = jsx_keys("const el = <ul role=\"toolbar\"><li>Item</li></ul>;\n");
        assert_eq!(count_key(&changed_role, "javascript:S6822"), 0);
        assert_eq!(count_key(&changed_role, "javascript:S6819"), 0);

        let plain_list = jsx_keys("const el = <ul><li>Item</li></ul>;\n");
        assert_eq!(count_key(&plain_list, "javascript:S6822"), 0);
        assert_eq!(count_key(&plain_list, "javascript:S6819"), 0);
    }

    #[test]
    fn abstract_roles_are_flagged() {
        let select_role = jsx_keys("const el = <div role=\"select\"/>;\n");
        assert_eq!(count_key(&select_role, "javascript:S6821"), 1);

        let composite_role = jsx_keys("const el = <div role=\"composite\"/>;\n");
        assert_eq!(count_key(&composite_role, "javascript:S6821"), 1);

        let concrete_role = jsx_keys("const el = <div role=\"note\"/>;\n");
        assert_eq!(count_key(&concrete_role, "javascript:S6821"), 0);
    }
    #[test]
    fn aria_values_are_validated_against_tables() {
        let bad_boolean = jsx_keys("const el = <div aria-hidden=\"yes\"/>;\n");
        assert_eq!(count_key(&bad_boolean, "javascript:S6793"), 1);

        let good_boolean = jsx_keys("const el = <div aria-hidden=\"true\"/>;\n");
        assert_eq!(count_key(&good_boolean, "javascript:S6793"), 0);

        let bad_token = jsx_keys("const el = <div aria-live=\"fast\"/>;\n");
        assert_eq!(count_key(&bad_token, "javascript:S6793"), 1);

        let good_token = jsx_keys("const el = <div aria-live=\"polite\"/>;\n");
        assert_eq!(count_key(&good_token, "javascript:S6793"), 0);

        let bad_numeric = jsx_keys("const el = <div aria-level=\"two\"/>;\n");
        assert_eq!(count_key(&bad_numeric, "javascript:S6793"), 1);

        let good_numeric = jsx_keys("const el = <div aria-level=\"2\"/>;\n");
        assert_eq!(count_key(&good_numeric, "javascript:S6793"), 0);

        let dynamic_value = jsx_keys("let mode = 'polite';\nconst el = <div aria-live={mode}/>;\n");
        assert_eq!(count_key(&dynamic_value, "javascript:S6793"), 0);
    }

    #[test]
    fn list_roles_require_owned_listitems() {
        let bare = jsx_keys("const el = <div role=\"list\"/>;\n");
        assert_eq!(count_key(&bare, "javascript:S6807"), 1);

        let implicit_owned = jsx_keys("const el = <div role=\"list\"><li>Item</li></div>;\n");
        assert_eq!(count_key(&implicit_owned, "javascript:S6807"), 0);

        let explicit_owned =
            jsx_keys("const el = <div role=\"list\"><div role=\"listitem\">Item</div></div>;\n");
        assert_eq!(count_key(&explicit_owned, "javascript:S6807"), 0);
    }

    #[test]
    fn unsupported_aria_properties_are_flagged_per_role() {
        let unsupported = jsx_keys("const el = <div role=\"heading\" aria-selected=\"true\"/>;\n");
        assert_eq!(count_key(&unsupported, "javascript:S6811"), 1);

        let supported = jsx_keys("const el = <div role=\"heading\" aria-level=\"2\"/>;\n");
        assert_eq!(count_key(&supported, "javascript:S6811"), 0);

        let global_property =
            jsx_keys("const el = <div role=\"heading\" aria-hidden=\"true\"/>;\n");
        assert_eq!(count_key(&global_property, "javascript:S6811"), 0);
    }

    #[test]
    fn activedescendant_requires_tab_index() {
        let missing = jsx_keys("const el = <div aria-activedescendant=\"opt-1\"/>;\n");
        assert_eq!(count_key(&missing, "javascript:S6823"), 1);

        let camel_case =
            jsx_keys("const el = <div aria-activedescendant=\"opt-1\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&camel_case, "javascript:S6823"), 0);

        let lower_case =
            jsx_keys("const el = <div aria-activedescendant=\"opt-1\" tabindex=\"0\"/>;\n");
        assert_eq!(count_key(&lower_case, "javascript:S6823"), 0);

        let spread_props =
            jsx_keys("const el = <div {...rest} aria-activedescendant=\"opt-1\"/>;\n");
        assert_eq!(count_key(&spread_props, "javascript:S6823"), 0);
    }
    // ===== Batch4 group A3 tests: interaction-matrix accessibility rules =====

    #[test]
    fn roles_must_be_allowed_on_their_elements() {
        let heading_role = jsx_keys("const el = <h1 role=\"button\">Title</h1>;\n");
        assert_eq!(count_key(&heading_role, "javascript:S6824"), 1);

        let cell_role = jsx_keys("const el = <td role=\"link\">x</td>;\n");
        assert_eq!(count_key(&cell_role, "javascript:S6824"), 1);

        let allowed_cell = jsx_keys("const el = <td role=\"cell\">x</td>;\n");
        assert_eq!(count_key(&allowed_cell, "javascript:S6824"), 0);

        let unrestricted_tag = jsx_keys("const el = <div role=\"button\"/>;\n");
        assert_eq!(count_key(&unrestricted_tag, "javascript:S6824"), 0);

        let list_toolbar = jsx_keys("const el = <ul role=\"toolbar\"><li>x</li></ul>;\n");
        assert_eq!(count_key(&list_toolbar, "javascript:S6824"), 0);
    }

    #[test]
    fn aria_hidden_must_not_hide_focusable_elements() {
        let hidden_button = jsx_keys("const el = <button aria-hidden=\"true\">Go</button>;\n");
        assert_eq!(count_key(&hidden_button, "javascript:S6825"), 1);

        let hidden_tabbable = jsx_keys("const el = <div aria-hidden=\"true\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&hidden_tabbable, "javascript:S6825"), 1);

        let hidden_static = jsx_keys("const el = <div aria-hidden=\"true\">text</div>;\n");
        assert_eq!(count_key(&hidden_static, "javascript:S6825"), 0);

        let negative_index = jsx_keys("const el = <div aria-hidden=\"true\" tabIndex={-1}/>;\n");
        assert_eq!(count_key(&negative_index, "javascript:S6825"), 0);

        let visible_button = jsx_keys("const el = <button>Go</button>;\n");
        assert_eq!(count_key(&visible_button, "javascript:S6825"), 0);
    }

    #[test]
    fn autocomplete_values_must_match_input_types() {
        let mismatched_scope =
            jsx_keys("const el = <input type=\"text\" autoComplete=\"email\"/>;\n");
        assert_eq!(count_key(&mismatched_scope, "javascript:S6840"), 1);

        let unknown_token =
            jsx_keys("const el = <input type=\"text\" autoComplete=\"banana\"/>;\n");
        assert_eq!(count_key(&unknown_token, "javascript:S6840"), 1);

        let matching_scope =
            jsx_keys("const el = <input type=\"email\" autoComplete=\"email\"/>;\n");
        assert_eq!(count_key(&matching_scope, "javascript:S6840"), 0);

        let general_token = jsx_keys("const el = <input autoComplete=\"on\"/>;\n");
        assert_eq!(count_key(&general_token, "javascript:S6840"), 0);

        let select_field = jsx_keys("const el = <select autoComplete=\"postal-code\"/>;\n");
        assert_eq!(count_key(&select_field, "javascript:S6840"), 0);

        let textarea_field = jsx_keys("const el = <textarea autoComplete=\"street-address\"/>;\n");
        assert_eq!(count_key(&textarea_field, "javascript:S6840"), 0);

        let other_tag = jsx_keys("const el = <div autoComplete=\"banana\"/>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S6840"), 0);
    }
    #[test]
    fn noninteractive_elements_reject_interactive_roles() {
        let div_button = jsx_keys("const el = <div role=\"button\" tabIndex={0}>OK</div>;\n");
        assert_eq!(count_key(&div_button, "javascript:S6842"), 1);

        let span_link = jsx_keys("const el = <span role=\"link\">x</span>;\n");
        assert_eq!(count_key(&span_link, "javascript:S6842"), 1);

        let native_button = jsx_keys("const el = <button>OK</button>;\n");
        assert_eq!(count_key(&native_button, "javascript:S6842"), 0);

        let structural_div = jsx_keys("const el = <div role=\"note\">x</div>;\n");
        assert_eq!(count_key(&structural_div, "javascript:S6842"), 0);
    }

    #[test]
    fn interactive_elements_reject_structural_roles() {
        let button_list = jsx_keys("const el = <button role=\"list\">x</button>;\n");
        assert_eq!(count_key(&button_list, "javascript:S6843"), 1);

        let link_article = jsx_keys("const el = <a href=\"/docs\" role=\"article\">x</a>;\n");
        assert_eq!(count_key(&link_article, "javascript:S6843"), 1);

        let matching_button = jsx_keys("const el = <button role=\"checkbox\"/>;\n");
        assert_eq!(count_key(&matching_button, "javascript:S6843"), 0);

        let plain_button = jsx_keys("const el = <button/>;\n");
        assert_eq!(count_key(&plain_button, "javascript:S6843"), 0);
    }

    #[test]
    fn interactive_roles_require_focusable_elements() {
        let unfocusable = jsx_keys("const el = <div role=\"button\"/>;\n");
        assert_eq!(count_key(&unfocusable, "javascript:S6852"), 1);

        let tabbable = jsx_keys("const el = <div role=\"button\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&tabbable, "javascript:S6852"), 0);

        let negative_index = jsx_keys("const el = <div role=\"button\" tabIndex={-1}/>;\n");
        assert_eq!(count_key(&negative_index, "javascript:S6852"), 0);

        let native_control = jsx_keys("const el = <button/>;\n");
        assert_eq!(count_key(&native_control, "javascript:S6852"), 0);

        let anchor = jsx_keys("const el = <a href=\"/docs\">docs</a>;\n");
        assert_eq!(count_key(&anchor, "javascript:S6852"), 0);
    }
    #[test]
    fn anchor_clicks_require_href_or_buttons() {
        let click_only = jsx_keys("const el = <a onClick={openMenu}>Menu</a>;\n");
        assert_eq!(count_key(&click_only, "javascript:S6844"), 1);

        let with_href = jsx_keys("const el = <a href=\"/menu\" onClick={openMenu}>Menu</a>;\n");
        assert_eq!(count_key(&with_href, "javascript:S6844"), 0);

        let plain_anchor = jsx_keys("const el = <a href=\"/docs\">docs</a>;\n");
        assert_eq!(count_key(&plain_anchor, "javascript:S6844"), 0);

        let button_click = jsx_keys("const el = <button onClick={openMenu}>Menu</button>;\n");
        assert_eq!(count_key(&button_click, "javascript:S6844"), 0);
    }

    #[test]
    fn positive_tab_indices_need_interactive_elements() {
        let static_div = jsx_keys("const el = <div tabIndex={0}/>;\n");
        assert_eq!(count_key(&static_div, "javascript:S6845"), 1);

        let interactive_button = jsx_keys("const el = <button tabIndex={0}/>;\n");
        assert_eq!(count_key(&interactive_button, "javascript:S6845"), 0);

        let programmatic = jsx_keys("const el = <div tabIndex={-1}/>;\n");
        assert_eq!(count_key(&programmatic, "javascript:S6845"), 0);

        let interactive_role = jsx_keys("const el = <div role=\"button\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&interactive_role, "javascript:S6845"), 0);

        let listbox_container = jsx_keys(
            "const el = <div role=\"listbox\" aria-activedescendant=\"o1\" tabIndex={0}/>;\n",
        );
        assert_eq!(count_key(&listbox_container, "javascript:S6845"), 0);
    }

    #[test]
    fn interaction_handlers_belong_on_interactive_elements() {
        let div_click = jsx_keys("const el = <div onClick={f}/>;\n");
        assert_eq!(count_key(&div_click, "javascript:S6847"), 1);

        let div_change = jsx_keys("const el = <div onChange={f}/>;\n");
        assert_eq!(count_key(&div_change, "javascript:S6847"), 1);

        let two_handlers = jsx_keys("const el = <div onClick={f} onMouseDown={g}/>;\n");
        assert_eq!(count_key(&two_handlers, "javascript:S6847"), 2);

        let button_click = jsx_keys("const el = <button onClick={f}/>;\n");
        assert_eq!(count_key(&button_click, "javascript:S6847"), 0);

        let role_button = jsx_keys("const el = <div role=\"button\" onClick={f}/>;\n");
        assert_eq!(count_key(&role_button, "javascript:S6847"), 0);
    }

    #[test]
    fn click_handlers_need_keyboard_counterparts() {
        let click_only = jsx_keys("const el = <div onClick={f}/>;\n");
        assert_eq!(count_key(&click_only, "javascript:S6848"), 1);

        let with_key = jsx_keys("const el = <div onClick={f} onKeyDown={k}/>;\n");
        assert_eq!(count_key(&with_key, "javascript:S6848"), 0);

        let interactive_button = jsx_keys("const el = <button onClick={f}/>;\n");
        assert_eq!(count_key(&interactive_button, "javascript:S6848"), 0);
    }

    #[test]
    fn labels_need_text_and_control_association() {
        let orphan_label = jsx_keys("const el = <label>Surname</label>;\n");
        assert_eq!(count_key(&orphan_label, "javascript:S6853"), 1);

        let empty_label = jsx_keys("const el = <label htmlFor=\"q\"/>;\n");
        assert_eq!(count_key(&empty_label, "javascript:S6853"), 1);

        let bare_label = jsx_keys("const el = <label/>;\n");
        assert_eq!(count_key(&bare_label, "javascript:S6853"), 1);

        let for_attribute = jsx_keys("const el = <label htmlFor=\"q\">Query</label>;\n");
        assert_eq!(count_key(&for_attribute, "javascript:S6853"), 0);

        let nested_control = jsx_keys("const el = <label>Name<input/></label>;\n");
        assert_eq!(count_key(&nested_control, "javascript:S6853"), 0);
    }
}
