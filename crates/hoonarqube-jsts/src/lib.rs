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
//! reports recoverable errors, and those errors surface as
//! `{javascript|typescript}:S2260` issues while the partial AST below is
//! still analyzed tolerantly.
//!
//! # Project context
//!
//! Single-file analysis does not resolve imported symbols or checker-dependent
//! types. [`project_context`] supplies an explicit compiler-backed context for
//! deprecated APIs, internal/unresolved imports, and type-dependent rules.
//! Semicolon checks use parser token boundaries rather than sibling-gap guesses.
use crate::context::{AnalysisContext, RuleOptions};
use crate::support::{
    LineIndex, file_metrics, scan_comments, sort_issues, source_type_for, span_issue,
};

mod context;
mod engine;
mod github_quality;
mod native;
pub mod project_context;
pub use github_quality::analyze_github_quality;

/// Exact `CodeQL` query IDs emitted by [`analyze_github_quality`], in sorted order.
pub const GITHUB_QUALITY_RULE_IDS: &[&str] = &[
    "js/arguments-redefinition",
    "js/assignment-to-constant",
    "js/automatic-semicolon-insertion",
    "js/conditional-comment",
    "js/duplicate-parameter-name",
    "js/duplicate-property",
    "js/duplicate-switch-case",
    "js/inconsistent-loop-direction",
    "js/label-in-switch",
    "js/shift-out-of-range",
    "js/trivial-conditional",
    "js/unused-index-variable",
    "js/useless-assignment-to-local",
    "js/useless-expression",
    "js/whitespace-contradicts-precedence",
    "js/with-statement",
    "js/yield-outside-generator",
];
mod rules;
mod support;
use std::cell::Cell;
use std::path::{Path, PathBuf};

use hoonarqube_ir::Issue;
use oxc_allocator::Allocator;
use oxc_parser::{Parser, config::TokensParserConfig};
use oxc_semantic::SemanticBuilder;

// Oxc's generated visitors recurse once per AST level. Keep that recursion off
// the caller's usually small test/runtime stack to reduce stack-overflow risk
// for deeply nested valid source.
//
// The parser's recursive-descent productions use loops for sibling lists, and
// the crate's own recursive mini-parsers cap pattern nesting at 48. The 16 MiB
// value is a conservative fixed reservation reduction informed by those
// bounded sub-parsers, not an arbitrary AST-depth guarantee: Oxc's general
// parser and visitors remain recursive for deeply nested source.
// It avoids the former 128 MiB reservation on every concurrent file.
const ANALYZER_STACK_SIZE: usize = 16 * 1024 * 1024;

thread_local! {
    static ANALYZER_STACK_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

fn with_analyzer_stack<T>(job: impl FnOnce() -> T) -> T {
    struct RestoreStackMarker(bool);

    impl Drop for RestoreStackMarker {
        fn drop(&mut self) {
            ANALYZER_STACK_ACTIVE.with(|active| active.set(self.0));
        }
    }

    let previous = ANALYZER_STACK_ACTIVE.with(|active| active.replace(true));
    let _restore = RestoreStackMarker(previous);
    job()
}

/// Spawns one bounded analysis worker with enough stack for JSTS parsing.
///
/// This hidden workspace API lets the CLI reuse its file worker for JSTS
/// analysis instead of creating a second thread for every JavaScript or
/// TypeScript file.
#[doc(hidden)]
pub fn spawn_analyzer_worker<'scope, 'env, T, F>(
    scope: &'scope std::thread::Scope<'scope, 'env>,
    name: &str,
    job: F,
) -> std::io::Result<std::thread::ScopedJoinHandle<'scope, T>>
where
    F: FnOnce() -> T + Send + 'scope,
    T: Send + 'scope,
{
    std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(ANALYZER_STACK_SIZE)
        .spawn_scoped(scope, move || with_analyzer_stack(job))
}

pub(crate) fn run_on_analyzer_stack<'scope, 'env, T, F>(
    scope: &'scope std::thread::Scope<'scope, 'env>,
    name: &str,
    start_error: &str,
    job: F,
) -> T
where
    F: FnOnce() -> T + Send + 'scope,
    T: Send + 'scope,
{
    if ANALYZER_STACK_ACTIVE.with(Cell::get) {
        return job();
    }
    let worker = spawn_analyzer_worker(scope, name, job)
        .unwrap_or_else(|error| panic!("{start_error}: {error}"));
    worker
        .join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

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

/// Knobs for the JS/TS analyzer; defaults mirror the frozen catalog
/// `ParameterFact` defaults (`maximumLineLength` default `180` for both
/// `javascript:S103` and `typescript:S103`).
///
/// The struct stays `Eq` because `hoonarqube-core` bundles it in an `Eq`
/// container; the non-`Eq` `randomnessSensibility` for `S6418` (an `f64`)
/// stays on the private `RuleOptions` carrier. These fields are the only
/// catalog parameters surfaced through [`AnalyzerOptions`]. Other implemented
/// parameters, including structural thresholds and style settings, use their
/// frozen catalog defaults. S5693 evaluates the default 2,000,000-byte parser
/// limit; custom size thresholds and multipart file-size checks are not
/// implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: u32,
    /// `javascript:S104` / `typescript:S104` `maximum`.
    pub maximum_lines_of_code: u32,
    /// `S138` `max`.
    pub maximum_function_lines: u32,
    /// `S1451` `headerFormat`; empty disables the file-header check.
    pub header_format: String,
    /// `S1451` `isRegularExpression`.
    pub header_is_regular_expression: bool,
    /// `S139` `pattern`.
    pub comment_pattern: String,
    /// `S2068` `passwordWords`, comma-separated in catalog order.
    pub password_words: Vec<String>,
    /// `S6418` `secretWords`, comma-separated.
    pub secret_words: Vec<String>,
    /// `S100` naming `format` for functions.
    pub format_functions: String,
    /// `S101` naming `format` for classes.
    pub format_classes: String,
    /// `S117` naming `format` for local variables.
    pub format_variables: String,
    /// `S1192` `threshold`.
    pub duplicate_string_threshold: usize,
    /// `S1192` `ignoreStrings`, comma-separated.
    pub ignored_strings: Vec<String>,
    /// `S1441` `singleQuotes`.
    pub single_quotes: bool,
    /// `S6747` `whitelist`, comma-separated.
    pub jsx_attribute_whitelist: Vec<String>,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        // `RuleOptions::default()` is the single source of catalog defaults.
        let rules = RuleOptions::default();
        Self {
            maximum_line_length: 180,
            maximum_lines_of_code: rules.maximum_lines_of_code,
            maximum_function_lines: rules.maximum_function_lines,
            header_format: rules.header_format,
            header_is_regular_expression: rules.header_is_regular_expression,
            comment_pattern: rules.comment_pattern,
            password_words: rules.password_words,
            secret_words: rules.secret_words,
            format_functions: rules.format_functions,
            format_classes: rules.format_classes,
            format_variables: rules.format_variables,
            duplicate_string_threshold: rules.duplicate_string_threshold,
            ignored_strings: rules.ignored_strings,
            single_quotes: rules.single_quotes,
            jsx_attribute_whitelist: rules.jsx_attribute_whitelist,
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
    analyze_with_facts(path, source, language, options, None)
}

/// Runs one file with an optional compiler-backed semantic fact set.
///
/// TypeScript declaration files (`.d.ts`, `.d.mts`, `.d.cts`) describe
/// other files' types; `SonarQube`'s default configuration excludes them
/// from analysis entirely, so hq emits neither issues nor metrics for
/// them and stays inside the reference's file scope.
#[must_use]
pub(crate) fn analyze_with_facts(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
    semantic_facts: Option<&project_context::SemanticFileFacts>,
) -> hoonarqube_ir::FileReport {
    if is_typescript_declaration_path(&path) {
        return unanalyzed_report(path, language);
    }
    let rules = RuleOptions::from(options);
    analyze_on_scoped_stack(path, source, language, options, &rules, semantic_facts)
}

/// Runs independently implemented non-Sonar JS/TS rules on a bounded worker
/// stack, matching the main analyzer's nesting tolerance.
///
/// # Panics
///
/// Panics if the dedicated analyzer thread cannot be started or if its parser
/// worker panics.
#[must_use]
pub fn analyze_native(source: &str, language: JstsLanguage) -> Vec<hoonarqube_ir::Issue> {
    std::thread::scope(|scope| {
        run_on_analyzer_stack(
            scope,
            "hoonarqube-jsts-native",
            "failed to start JS/TS native analyzer worker",
            move || native::analyze(source, language),
        )
    })
}

/// Runs GitHub Code Quality queries without running Sonar rules.
///
/// Metrics retain the path-specific tolerant grammar used by [`analyze`]. The
/// quality queries use their own strict grammar and JSX fallback, so both
/// parses deliberately remain separate, on the same bounded worker stack.
///
/// # Panics
/// Panics if the analyzer worker cannot be started or if analysis panics.
#[must_use]
pub fn analyze_github_quality_report(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
) -> hoonarqube_ir::FileReport {
    if is_typescript_declaration_path(&path) {
        return unanalyzed_report(path, language);
    }
    std::thread::scope(|scope| {
        run_on_analyzer_stack(
            scope,
            "hoonarqube-jsts-github-report",
            "failed to start JS/TS GitHub quality worker",
            move || {
                let metrics = {
                    let allocator = Allocator::default();
                    let parsed =
                        Parser::new(&allocator, source, source_type_for(language, &path)).parse();
                    let index = LineIndex::new(source);
                    file_metrics(
                        parsed.program.body.as_slice(),
                        source,
                        &index,
                        &scan_comments(source),
                    )
                };
                hoonarqube_ir::FileReport {
                    path,
                    language: language.prefix().to_owned(),
                    issues: analyze_github_quality(source, language),
                    metrics,
                }
            },
        )
    })
}

fn analyze_on_scoped_stack(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
    rules: &RuleOptions,
    semantic_facts: Option<&project_context::SemanticFileFacts>,
) -> hoonarqube_ir::FileReport {
    std::thread::scope(|scope| {
        run_on_analyzer_stack(
            scope,
            "hoonarqube-jsts",
            "failed to start JS/TS analyzer worker",
            move || {
                analyze_with_rules_and_facts(path, source, language, options, rules, semantic_facts)
            },
        )
    })
}
/// Analyzes the inline `<script>` bodies of a web template as JavaScript.
///
/// `SonarQube`'s web analyzer feeds every inline script body to the JS
/// analyzer while reporting findings at their original template offsets.
/// The extraction masks all markup to spaces (newlines preserved) so issue
/// positions map one-to-one onto the template, then runs the ordinary JS
/// pipeline. Scripts with a `src` attribute or a non-JavaScript `type`
/// contribute no code, matching browser and reference behavior.
#[must_use]
pub fn analyze_embedded_html(
    path: PathBuf,
    source: &str,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    let (extracted, line_has_code) = extract_inline_scripts(source);
    let mut report = analyze(path, &extracted, JstsLanguage::JavaScript, options);
    // Source-text rules (trailing whitespace, line length, file header)
    // would flag the masked markup; the reference only reports findings on
    // real script lines, so findings on fully masked lines are dropped.
    report.issues.retain(|issue| {
        line_has_code
            .get(issue.range.start.line.saturating_sub(1) as usize)
            .copied()
            .unwrap_or(false)
    });
    "web".clone_into(&mut report.language);
    report
}

fn extract_inline_scripts(source: &str) -> (String, Vec<bool>) {
    let bytes = source.as_bytes();
    let mut masked = vec![b' '; bytes.len()];
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(byte, b'\n' | b'\r') {
            masked[index] = *byte;
        }
    }
    let mut offset = 0;
    while let Some(open) = find_script_open(bytes, offset) {
        let (tag_end, inline) = script_tag_end(bytes, open);
        if !inline {
            offset = tag_end;
            continue;
        }
        let content_end = find_script_close(bytes, tag_end);
        masked[tag_end..content_end].copy_from_slice(&bytes[tag_end..content_end]);
        offset = content_end;
    }
    // The mask only ever replaces bytes with ASCII spaces or copies source
    // slices verbatim, so the result is always valid UTF-8.
    let extracted = String::from_utf8(masked).unwrap_or_default();
    let line_has_code = extracted
        .split('\n')
        .map(|line| !line.trim().is_empty())
        .collect();
    (extracted, line_has_code)
}

/// Finds the next `<script` tag at or after `offset`, requiring a tag
/// boundary (whitespace, `/`, or `>`) so `<scripts>` does not match.
fn find_script_open(bytes: &[u8], offset: usize) -> Option<usize> {
    let mut index = offset;
    while index + 7 <= bytes.len() {
        if bytes[index] == b'<'
            && bytes[index + 1..index + 7].eq_ignore_ascii_case(b"script")
            && bytes.get(index + 7).is_none_or(|byte| {
                matches!(byte, b'>' | b'/' | b'\t' | b'\n' | b'\r' | b' ' | 0x0c)
            })
        {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// Finds the `</script` close tag at or after `offset`; unclosed scripts
/// run to end of input like browser parsing.
fn find_script_close(bytes: &[u8], offset: usize) -> usize {
    let mut index = offset;
    while index + 8 <= bytes.len() {
        if bytes[index] == b'<'
            && bytes[index + 1] == b'/'
            && bytes[index + 2..index + 8].eq_ignore_ascii_case(b"script")
            && bytes.get(index + 8).is_none_or(|byte| {
                matches!(byte, b'>' | b'/' | b'\t' | b'\n' | b'\r' | b' ' | 0x0c)
            })
        {
            return index;
        }
        index += 1;
    }
    bytes.len()
}

/// Returns the offset just past the tag's closing `>` and whether the tag
/// opens an inline JavaScript body.
fn script_tag_end(bytes: &[u8], open: usize) -> (usize, bool) {
    let mut index = open + 1;
    let mut quote = None;
    while index < bytes.len() {
        match (bytes[index], quote) {
            (b'"' | b'\'', None) => quote = Some(bytes[index]),
            (b'>', None) => break,
            (byte, Some(active)) if byte == active => quote = None,
            _ => {}
        }
        index += 1;
    }
    let tag = &bytes[open..index.min(bytes.len())];
    (
        index.saturating_add(1).min(bytes.len()),
        tag_is_inline_javascript(tag),
    )
}

/// Whether a `<script ...>` tag body is inline JavaScript: no `src`
/// attribute and a `type` that is absent, empty, `module`, or a
/// JavaScript MIME type.
fn tag_is_inline_javascript(tag: &[u8]) -> bool {
    if attribute_value(tag, b"src").is_some() {
        return false;
    }
    match attribute_value(tag, b"type") {
        None => true,
        Some(value) => {
            value.is_empty()
                || value.eq_ignore_ascii_case(b"module")
                || contains_ascii_case_insensitive(value, b"javascript")
                || contains_ascii_case_insensitive(value, b"ecmascript")
                || contains_ascii_case_insensitive(value, b"jscript")
        }
    }
}

/// Extracts one attribute value from a tag, quoted or unquoted.
fn attribute_value<'tag>(tag: &'tag [u8], name: &[u8]) -> Option<&'tag [u8]> {
    let mut index = 0;
    while let Some(found) = find_ascii_case_insensitive(tag, name, index) {
        let before_ok = found == 0
            || !matches!(tag[found - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_');
        let mut cursor = found + name.len();
        while cursor < tag.len() && matches!(tag[cursor], b'\t' | b'\n' | b'\r' | b' ' | 0x0c) {
            cursor += 1;
        }
        if before_ok && tag.get(cursor) == Some(&b'=') {
            cursor += 1;
            while cursor < tag.len() && matches!(tag[cursor], b'\t' | b'\n' | b'\r' | b' ' | 0x0c) {
                cursor += 1;
            }
            let (start, end) = if matches!(tag.get(cursor), Some(b'"' | b'\'')) {
                let quote = tag[cursor];
                let start = cursor + 1;
                let end = tag[start..]
                    .iter()
                    .position(|byte| *byte == quote)
                    .map_or(tag.len(), |offset| start + offset);
                (start, end)
            } else {
                let start = cursor;
                let end = tag[start..]
                    .iter()
                    .position(|byte| {
                        matches!(*byte, b'\t' | b'\n' | b'\r' | b' ' | 0x0c | b'>' | b'/')
                    })
                    .map_or(tag.len(), |offset| start + offset);
                (start, end)
            };
            return Some(&tag[start..end]);
        }
        index = found + 1;
    }
    None
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8], offset: usize) -> Option<usize> {
    (offset..=haystack.len().saturating_sub(needle.len()))
        .find(|index| haystack[*index..*index + needle.len()].eq_ignore_ascii_case(needle))
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    find_ascii_case_insensitive(haystack, needle, 0).is_some()
}

/// Whether the path names a TypeScript declaration file. Matched on the
/// file name so directory routers can keep their own conventions; the
/// comparison ignores ASCII case like the repository router.
fn is_typescript_declaration_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            lower.ends_with(".d.ts") || lower.ends_with(".d.mts") || lower.ends_with(".d.cts")
        })
}

/// Empty report for files outside the analyzer's file scope: no issues,
/// no metrics, exactly like a file the reference scanner never indexes.
fn unanalyzed_report(path: PathBuf, language: JstsLanguage) -> hoonarqube_ir::FileReport {
    hoonarqube_ir::FileReport {
        path,
        language: language.prefix().to_owned(),
        issues: Vec::new(),
        metrics: hoonarqube_ir::FileMetrics {
            lines: 0,
            code_lines: 0,
            comment_lines: 0,
        },
    }
}

#[cfg(test)]
fn analyze_with_rules(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
    rules: &RuleOptions,
) -> hoonarqube_ir::FileReport {
    analyze_with_rules_and_facts(path, source, language, options, rules, None)
}

fn analyze_with_rules_and_facts(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
    rules: &RuleOptions,
    semantic_facts: Option<&project_context::SemanticFileFacts>,
) -> hoonarqube_ir::FileReport {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type_for(language, &path))
        .with_config(TokensParserConfig)
        .parse();
    let has_parse_errors = parsed.diagnostics.errors().next().is_some();
    let semantic = if has_parse_errors {
        None
    } else {
        let built = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program);
        if built.diagnostics.has_errors() {
            None
        } else {
            Some(built.semantic)
        }
    };
    let index = LineIndex::new(source);
    // One comment-scan pass shared by every comment-consuming check and by
    // `file_metrics` (previously up to seven identical scans per file).
    let comments = scan_comments(source);
    let body = parsed.program.body.as_slice();
    let ctx = AnalysisContext {
        path: &path,
        source,
        program: &parsed.program,
        semantic: semantic.as_ref(),
        semantic_facts,
        tokens: parsed.tokens.as_slice(),
        index: &index,
        language,
        options,
        rules,
        comments,
    };
    let mut issues = Vec::new();
    // `S2260` (`ParsingError`): recoverable parse errors surface as issues,
    // mirroring the Python family's parsing-error reporting. Only
    // error-severity diagnostics count (parser warnings are not findings),
    // and the partial AST below is still analyzed tolerantly.
    if let Some(diagnostic) = parsed.diagnostics.errors().next() {
        let span = diagnostic
            .labels
            .first()
            .map_or(oxc_span::Span::sized(0, 0), oxc_span::LabeledSpan::span);
        let line_position = index.pos(span.start);
        let line_start = index.line_start(span.start);
        let line_end = source[line_start as usize..]
            .find('\n')
            .map_or(source.len(), |offset| line_start as usize + offset);
        let line = &source[line_start as usize..line_end];
        let indentation = line
            .chars()
            .take_while(|character| character.is_whitespace())
            .count();
        let message = match language {
            JstsLanguage::JavaScript if line.trim_start().starts_with("return") => {
                format!(
                    "Unexpected keyword 'return'. ({}:{indentation})",
                    line_position.line
                )
            }
            JstsLanguage::TypeScript => "':' expected.".to_owned(),
            JstsLanguage::JavaScript => format!("Fix this syntax error: {diagnostic}."),
        };
        issues.push(span_issue(
            &index,
            format!("{}:S2260", language.prefix()),
            message,
            oxc_span::Span::new(line_start, u32::try_from(line_end).unwrap_or(u32::MAX)),
        ));
    }
    issues.extend(rules::run_all(&ctx));
    if let Some(file) = semantic_facts {
        for fallback in rules::semantic_context::run_checker_fallbacks(file, source, language) {
            let duplicate = issues.iter().any(|existing| {
                existing.rule_key == fallback.rule_key && existing.range == fallback.range
            });
            if !duplicate {
                issues.push(fallback);
            }
        }
    }
    rules::quickfix::attach(&ctx, &mut issues);
    sort_issues(&mut issues);
    let metrics = file_metrics(body, source, &index, &ctx.comments);

    hoonarqube_ir::FileReport {
        path,
        language: language.prefix().to_string(),
        issues,
        metrics,
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_support;
