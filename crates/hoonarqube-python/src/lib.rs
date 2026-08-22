//! Tolerant Python analyzer lowering starter-rule findings into `hoonarqube-ir`.
//!
//! The crate parses Python with the embedded Ruff parser and lowers its checks
//! into [`hoonarqube_ir::FileReport`]s. Severity and type always resolve through
//! the frozen `hoonarqube-catalog` catalog via [`hoonarqube_ir::Issue::rule_key`];
//! they are deliberately never duplicated here.

use std::path::PathBuf;

use hoonarqube_ir::Issue;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{ModModule, PySourceType};
use ruff_python_parser::{Parsed, parse_unchecked_source};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

/// Knobs for the Python analyzer; defaults mirror the frozen catalog
/// `ParameterFact` defaults (`maximumLineLength` default `120`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: u32,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_line_length: 120,
        }
    }
}

#[must_use]
pub fn analyze(
    path: PathBuf,
    source: &str,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    let parsed = parse(source);
    let index = LineIndex::from_source_text(source);

    let mut issues = Vec::new();
    issues.extend(check_parsing_errors(&parsed, &index, source));
    issues.extend(check_no_sonar(&parsed, &index, source));
    issues.extend(check_line_length(source, options));
    issues.extend(check_one_statement_per_line(&parsed, &index, source));
    issues.extend(check_call_usage(
        &parsed,
        &index,
        source,
        "exec",
        "python:ExecStatementUsage",
        "Remove this usage of 'exec'.",
    ));
    issues.extend(check_call_usage(
        &parsed,
        &index,
        source,
        "print",
        "python:PrintStatementUsage",
        "Remove this usage of 'print'.",
    ));
    sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: "python".to_string(),
        issues,
        metrics: file_metrics(&parsed, source, &index),
    }
}

fn parse(source: &str) -> Parsed<ModModule> {
    parse_unchecked_source(source, PySourceType::Python)
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn to_pos(offset: TextSize, index: &LineIndex, source: &str) -> hoonarqube_ir::Pos {
    let location = index.line_column(offset, source);
    hoonarqube_ir::Pos {
        line: to_u32(location.line.get()),
        column: to_u32(location.column.to_zero_indexed()),
    }
}

fn to_range(range: TextRange, index: &LineIndex, source: &str) -> hoonarqube_ir::Range {
    hoonarqube_ir::Range {
        start: to_pos(range.start(), index, source),
        end: to_pos(range.end(), index, source),
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

/// Lines whose byte interval intersects `range`; multi-line tokens such as
/// triple-quoted strings legitimately span several lines.
fn covered_lines<'a>(
    range: TextRange,
    index: &'a LineIndex,
    source: &'a str,
) -> impl Iterator<Item = u32> + 'a {
    let first = to_u32(index.line_column(range.start(), source).line.to_zero_indexed());
    let slice = &source[range];
    // A newline transitions to the next line only when characters follow it
    // inside the range; a token ending exactly at a newline stays on its line.
    let mut extra = to_u32(slice.matches('\n').count());
    if slice.ends_with('\n') && extra > 0 {
        extra -= 1;
    }
    first..=first + extra
}

fn file_metrics(
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

fn check_parsing_errors(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    parsed
        .errors()
        .iter()
        .map(|error| Issue {
            rule_key: "python:ParsingError".to_string(),
            message: format!("{}", error.error),
            range: to_range(error.location, index, source),
        })
        .collect()
}

fn check_no_sonar(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    parsed
        .tokens()
        .iter()
        .filter(|token| token.kind().is_comment())
        .filter(|token| source[token.range()].contains("NOSONAR"))
        .map(|token| Issue {
            rule_key: "python:NoSonar".to_string(),
            message: "Remove this usage of 'NOSONAR'.".to_string(),
            range: to_range(token.range(), index, source),
        })
        .collect()
}

fn check_line_length(source: &str, options: &AnalyzerOptions) -> Vec<Issue> {
    let maximum = usize::try_from(options.maximum_line_length).unwrap_or(usize::MAX);
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches(['\r', '\n']);
        let length = line.chars().count();
        if length > maximum {
            let line_number = to_u32(zero_based) + 1;
            issues.push(Issue {
                rule_key: "python:LineLength".to_string(),
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
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    check_suite(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}

fn check_suite(suite: &[ruff_python_ast::Stmt], issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
    let line_of = |stmt: &ruff_python_ast::Stmt| to_pos(stmt.range().start(), index, source).line;

    let mut start = 0;
    while start < suite.len() {
        let first_line = line_of(&suite[start]);
        let mut end = start + 1;
        while end < suite.len() && line_of(&suite[end]) == first_line {
            end += 1;
        }
        for stmt in &suite[start + 1..end] {
            issues.push(Issue {
                rule_key: "python:OneStatementPerLine".to_string(),
                message: "Only one statement per line is allowed.".to_string(),
                range: to_range(stmt.range(), index, source),
            });
        }
        for stmt in &suite[start..end] {
            check_nested_bodies(stmt, issues, index, source);
        }
        start = end;
    }
}

fn check_nested_bodies(
    stmt: &ruff_python_ast::Stmt,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    use ruff_python_ast::{ExceptHandler, Stmt};
    match stmt {
        Stmt::FunctionDef(s) => check_suite(&s.body, issues, index, source),
        Stmt::ClassDef(s) => check_suite(&s.body, issues, index, source),
        Stmt::For(s) => {
            check_suite(&s.body, issues, index, source);
            check_suite(&s.orelse, issues, index, source);
        }
        Stmt::While(s) => {
            check_suite(&s.body, issues, index, source);
            check_suite(&s.orelse, issues, index, source);
        }
        Stmt::If(s) => {
            check_suite(&s.body, issues, index, source);
            for clause in &s.elif_else_clauses {
                check_suite(&clause.body, issues, index, source);
            }
        }
        Stmt::With(s) => check_suite(&s.body, issues, index, source),
        Stmt::Match(s) => {
            for case in &s.cases {
                check_suite(&case.body, issues, index, source);
            }
        }
        Stmt::Try(s) => {
            check_suite(&s.body, issues, index, source);
            for handler in &s.handlers {
                match handler {
                    ExceptHandler::ExceptHandler(handler) => {
                        check_suite(&handler.body, issues, index, source);
                    }
                }
            }
            check_suite(&s.orelse, issues, index, source);
            check_suite(&s.finalbody, issues, index, source);
        }
        _ => {}
    }
}

fn check_call_usage(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    identifier: &str,
    rule_key: &str,
    message: &str,
) -> Vec<Issue> {
    let significant: Vec<&ruff_python_ast::token::Token> = parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia())
        .collect();
    significant
        .windows(2)
        .filter(|pair| {
            pair[0].kind() == TokenKind::Name
                && &source[pair[0].range()] == identifier
                && pair[1].kind() == TokenKind::Lpar
        })
        .map(|pair| Issue {
            rule_key: rule_key.to_string(),
            message: message.to_string(),
            range: to_range(pair[0].range(), index, source),
        })
        .collect()
}


#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{AnalyzerOptions, analyze};

    fn pos(line: u32, column: u32) -> hoonarqube_ir::Pos {
        hoonarqube_ir::Pos { line, column }
    }

    fn issue(rule_key: &str, message: &str, start: (u32, u32), end: (u32, u32)) -> hoonarqube_ir::Issue {
        hoonarqube_ir::Issue {
            rule_key: rule_key.to_string(),
            message: message.to_string(),
            range: hoonarqube_ir::Range {
                start: pos(start.0, start.1),
                end: pos(end.0, end.1),
            },
        }
    }

    #[test]
    fn parsing_errors_are_recovered_from_tolerantly() {
        let report = analyze(
            PathBuf::from("test.py"),
            "def f(:\n    pass",
            &AnalyzerOptions::default(),
        );
        let parsing: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:ParsingError")
            .collect();
        // Ruff 0.0.10 tolerant recovery emits exactly these two errors for
        // this input; the analyzer reports one issue per `errors()` entry.
        assert_eq!(parsing.len(), 2);
        assert!(parsing[0].message.contains("Expected"));
    }

    #[test]
    fn nosonar_comment_is_flagged_case_sensitively() {
        let report = analyze(
            PathBuf::from("test.py"),
            "x = 1  # NOSONAR",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.issues,
            vec![issue(
                "python:NoSonar",
                "Remove this usage of 'NOSONAR'.",
                (1, 7),
                (1, 16),
            )]
        );

        let lowercase = analyze(
            PathBuf::from("test.py"),
            "x = 1  # nosonar",
            &AnalyzerOptions::default(),
        );
        assert!(lowercase.issues.is_empty());
    }

    #[test]
    fn one_statement_per_line_flags_only_second_onwards() {
        let report = analyze(
            PathBuf::from("test.py"),
            "a = 1\nb = 2\nc = 3; d = 4",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.issues,
            vec![issue(
                "python:OneStatementPerLine",
                "Only one statement per line is allowed.",
                (3, 7),
                (3, 12),
            )]
        );
    }
    #[test]
    fn line_length_honors_option() {
        let long_121 = format!("x = {}", "1".repeat(117));
        assert_eq!(long_121.chars().count(), 121);
        let report = analyze(
            PathBuf::from("test.py"),
            &long_121,
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].rule_key, "python:LineLength");
        assert_eq!(report.issues[0].range.start, pos(1, 0));
        assert_eq!(report.issues[0].range.end, pos(1, 121));

        let long_120 = format!("x = {}", "1".repeat(116));
        let clean = analyze(
            PathBuf::from("test.py"),
            &long_120,
            &AnalyzerOptions::default(),
        );
        assert!(clean.issues.is_empty());

        let strict = AnalyzerOptions {
            maximum_line_length: 10,
        };
        let flagged = analyze(PathBuf::from("test.py"), "x = 12345678", &strict);
        assert_eq!(flagged.issues.len(), 1);
        assert_eq!(
            flagged.issues[0].message,
            "This line exceeds the maximum allowed length of 10 characters."
        );
    }

    #[test]
    fn exec_and_print_calls_are_flagged_but_not_attributes() {
        let source = "exec(\"x\")\nprint(\"y\")\nmy_print(\"z\")\nmy_exec(\"w\")";
        let report = analyze(PathBuf::from("test.py"), source, &AnalyzerOptions::default());
        assert_eq!(
            report
                .issues
                .iter()
                .map(|issue| issue.rule_key.as_str())
                .collect::<Vec<_>>(),
            vec!["python:ExecStatementUsage", "python:PrintStatementUsage"]
        );
    }

    #[test]
    fn metrics_count_code_comment_and_blank_lines() {
        let report = analyze(
            PathBuf::from("test.py"),
            "x = 1\n# only a comment\n\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.metrics,
            hoonarqube_ir::FileMetrics {
                lines: 3,
                code_lines: 1,
                comment_lines: 1,
            }
        );
    }

    #[test]
    fn issue_positions_are_one_based_line_zero_based_column() {
        let report = analyze(
            PathBuf::from("test.py"),
            "if x:\n  exec(y)",
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].range.start, pos(2, 2));
    }

    #[test]
    fn integration_assembles_full_report_sorted() {
        let source = concat!(
            "import os\n",
            "\n",
            "def greet(name):\n",
            "    # greeting comment\n",
            "    print(\"hello\")\n",
            "    x = 1; y = 2\n",
            "    if name:\n",
            "        exec(\"z = 1\")\n",
            "\n",
            "greet(\"world\")  # NOSONAR here\n",
        );
        let report = analyze(PathBuf::from("demo.py"), source, &AnalyzerOptions::default());
        assert_eq!(
            report,
            hoonarqube_ir::FileReport {
                path: PathBuf::from("demo.py"),
                language: "python".to_string(),
                issues: vec![
                    issue(
                        "python:PrintStatementUsage",
                        "Remove this usage of 'print'.",
                        (5, 4),
                        (5, 9),
                    ),
                    issue(
                        "python:OneStatementPerLine",
                        "Only one statement per line is allowed.",
                        (6, 11),
                        (6, 16),
                    ),
                    issue(
                        "python:ExecStatementUsage",
                        "Remove this usage of 'exec'.",
                        (8, 8),
                        (8, 12),
                    ),
                    issue(
                        "python:NoSonar",
                        "Remove this usage of 'NOSONAR'.",
                        (10, 16),
                        (10, 30),
                    ),
                ],
                metrics: hoonarqube_ir::FileMetrics {
                    lines: 10,
                    code_lines: 7,
                    comment_lines: 1,
                },
            }
        );
    }
}
