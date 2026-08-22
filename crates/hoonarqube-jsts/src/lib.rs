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
    CallExpression, ClassElement, Declaration, ExportDefaultDeclarationKind, Expression,
    ModuleDeclaration, NewExpression, Statement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_call_expression, walk_new_expression};
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

#[must_use]
pub fn analyze(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        source,
        source_type_for(language, extension_of(&path)),
    )
    .parse();
    let index = LineIndex::new(source);

    let mut issues = Vec::new();
    issues.extend(check_line_length(source, language, options));
    issues.extend(check_one_statement_per_line(
        parsed.program.body.as_slice(),
        &index,
        language,
    ));
    issues.extend(check_eval_usage(&parsed.program, &index, language));
    sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: language.prefix().to_string(),
        issues,
        metrics: file_metrics(parsed.program.body.as_slice(), source, &index),
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
    state: ScanState,
    /// States suspended by `${` inside template literals.
    template_stack: Vec<ScanState>,
    prev_significant: Option<char>,
    prev_word: String,
    rows: Vec<u32>,
    last_pushed_row: u32,
}

impl Scanner {
    fn new(source: &str) -> Self {
        Self {
            chars: source.chars().collect(),
            state: ScanState::Code,
            template_stack: Vec::new(),
            prev_significant: None,
            prev_word: String::new(),
            rows: Vec::new(),
            last_pushed_row: u32::MAX,
        }
    }

    fn run(&mut self) {
        let mut row = 0_u32;
        let mut i = 0;
        while i < self.chars.len() {
            let c = self.chars[i];
            if c == '\n' {
                if self.state == ScanState::LineComment {
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
            self.state = ScanState::LineComment;
            return (2, true);
        }
        if c == '/' && next == Some('*') {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{AnalyzerOptions, JstsLanguage, analyze, language_for_extension};

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
            "const ab = 1;",
            JstsLanguage::JavaScript,
            &options,
        );
        assert!(at_limit.issues.is_empty());

        let over_limit = analyze(
            PathBuf::from("test.js"),
            "const abc = 1;",
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
        let report = js("function {(:\n    ???");
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
}
