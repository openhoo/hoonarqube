//! Catalog query CLI over the frozen embedded rule catalog.
//!
//! Every subcommand reads exclusively from
//! [`hoonarqube_catalog::embedded`]; no files are read at runtime.

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hoonarqube_catalog::{Catalog, RuleRecord, embedded};

mod analyze;

/// Embedded languages in canonical audit order: `(catalog name, language id)`.
const LANGUAGE_IDS: [(&str, &str); 4] = [
    ("csharp", "cs"),
    ("javascript", "js"),
    ("typescript", "ts"),
    ("python", "py"),
];

#[derive(Parser)]
#[command(name = "hoonarqube", about = "Hoonarqube analyzer command line")]
struct Cli {
    /// Emit machine-readable JSON instead of human text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show frozen capture metadata for the embedded catalog.
    Snapshot,
    Rules {
        #[command(subcommand)]
        cmd: RulesCommand,
    },
    /// Analyze supported sources under the given files or directories.
    Analyze {
        /// Files or directories to analyze.
        #[arg(required = true)]
        paths: Vec<std::path::PathBuf>,
        /// Output format: `text` (default), `json`, or `sonar`
        /// (`SonarQube` Generic Issue Import).
        #[arg(long)]
        format: Option<String>,
    },
    /// Apply safe automatic fixes for mechanical rules in place.
    ///
    /// Currently supported: trailing whitespace, missing final newline, and
    /// leading tab expansion.
    Fix {
        /// Files or directories to fix in place.
        #[arg(required = true)]
        paths: Vec<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum RulesCommand {
    /// List rules of one language, or all languages in canonical order.
    List {
        /// Embedded catalog name (`csharp`) or language id (`cs`).
        #[arg(long)]
        lang: Option<String>,
    },
    /// Case-insensitive substring search over keys, `sys_tags`, and tags.
    Search {
        /// Embedded catalog name (`csharp`) or language id (`cs`).
        #[arg(long)]
        lang: Option<String>,
        query: String,
    },
    /// Show one rule by its full external key (e.g. `python:BackticksUsage`).
    Info { external_key: String },
}

/// Output format of the `analyze` subcommand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnalyzeFormat {
    /// Human-readable text lines (default).
    Text,
    /// Compact [`hoonarqube_ir::AnalysisReport`] JSON; also selected by the
    /// legacy global `--json` flag.
    Json,
    /// `SonarQube` Generic Issue Import JSON.
    Sonar,
}

/// Resolves the analyze output format: an explicit `--format` value wins over
/// the legacy global `--json` flag; without either, text is emitted. Unknown
/// `--format` values are returned as `Err`.
fn analyze_format(format: Option<&str>, json_flag: bool) -> Result<AnalyzeFormat, String> {
    match format {
        Some("text") => Ok(AnalyzeFormat::Text),
        Some("json") => Ok(AnalyzeFormat::Json),
        Some("sonar") => Ok(AnalyzeFormat::Sonar),
        Some(value) => Err(value.to_string()),
        None if json_flag => Ok(AnalyzeFormat::Json),
        None => Ok(AnalyzeFormat::Text),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let catalog = embedded();
    match &cli.command {
        Command::Snapshot => print_snapshot(catalog, cli.json),
        Command::Rules { cmd } => run_rules(catalog, cmd, cli.json),
        Command::Analyze { paths, format } => {
            run_analyze(catalog, paths, format.as_deref(), cli.json)
        }
        Command::Fix { paths } => run_fix(paths),
    }
}

/// Applies safe mechanical fixes for one file; returns the number applied.
fn fix_file(path: &std::path::Path) -> usize {
    let Ok(source) = std::fs::read_to_string(path) else {
        return 0;
    };
    let mut fixed = source.clone();
    let mut applied: Vec<&'static str> = Vec::new();

    let trimmed: String = fixed
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n");
    if trimmed != fixed {
        applied.push("stripped trailing whitespace");
        fixed = trimmed;
    }
    if !fixed.is_empty() && !fixed.ends_with('\n') {
        applied.push("added missing final newline");
        fixed.push('\n');
    }
    if fixed.lines().any(|l| l.starts_with('\t')) {
        applied.push("expanded leading tabs to spaces");
        fixed = fixed
            .lines()
            .map(|l| {
                let tabs = l.len() - l.trim_start_matches('\t').len();
                format!("{}{}", " ".repeat(tabs * 4), l.trim_start_matches('\t'))
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    if !applied.is_empty() {
        std::fs::write(path, &fixed).expect("write back fixed source");
    }
    applied.len()
}

fn run_fix(paths: &[std::path::PathBuf]) -> ExitCode {
    let mut files = Vec::new();
    for p in paths {
        if p.is_dir() {
            if let Ok(entries) = std::fs::read_dir(p) {
                let mut children: Vec<_> = entries.flatten().map(|e| e.path()).collect();
                children.sort();
                for child in children {
                    if child.extension().is_some_and(|e| e == "py") {
                        files.push(child);
                    }
                }
            }
        } else {
            files.push(p.clone());
        }
    }
    let total: usize = files.iter().map(|f| fix_file(f)).sum();
    println!(
        "applied {total} mechanical fix(es) across {} file(s)",
        files.len()
    );
    ExitCode::SUCCESS
}

fn run_rules(catalog: &Catalog, cmd: &RulesCommand, json: bool) -> ExitCode {
    match cmd {
        RulesCommand::List { lang } => match select_language(catalog, lang.as_deref()) {
            Some(languages) => {
                for rule in languages {
                    print_rule_row(rule);
                }
                ExitCode::SUCCESS
            }
            None => unknown_language(lang.as_deref().unwrap_or_default()),
        },
        RulesCommand::Search { lang, query } => {
            let Some(languages) = select_language(catalog, lang.as_deref()) else {
                return unknown_language(lang.as_deref().unwrap_or_default());
            };
            let query_lower = query.to_lowercase();
            let mut printed = false;
            for rule in languages {
                if rule_matches(rule, &query_lower) {
                    print_rule_row(rule);
                    printed = true;
                }
            }
            if !printed {
                println!("no matching rules");
            }
            ExitCode::SUCCESS
        }
        RulesCommand::Info { external_key } => {
            if let Some(rule) = catalog.rule(external_key) {
                if json {
                    print_json(rule);
                } else {
                    print_rule_info(rule);
                }
                ExitCode::SUCCESS
            } else {
                eprintln!("unknown rule: {external_key}");
                ExitCode::from(1)
            }
        }
    }
}

/// Resolves an optional `--lang` value into the selected rules.
///
/// `None` selects every language in canonical order; a value may be a catalog
/// name or a language id. An unknown value yields `None`.
fn select_language<'a>(
    catalog: &'a Catalog,
    lang: Option<&str>,
) -> Option<Box<dyn Iterator<Item = &'a RuleRecord> + 'a>> {
    match lang {
        None => Some(Box::new(
            catalog
                .languages()
                .flat_map(|(_, language)| language.rules()),
        ) as Box<dyn Iterator<Item = &'a RuleRecord> + 'a>),
        Some(lang) => {
            let name = LANGUAGE_IDS
                .iter()
                .find(|(_, id)| *id == lang)
                .map_or(lang, |(name, _)| name);
            let rules = catalog.language(name)?;
            Some(Box::new(rules.rules().iter()) as Box<dyn Iterator<Item = &'a RuleRecord> + 'a>)
        }
    }
}

/// Whether the lowercased query occurs in the key, any `sys_tag`, or any tag.
fn rule_matches(rule: &RuleRecord, query_lower: &str) -> bool {
    rule.external_key.to_lowercase().contains(query_lower)
        || rule
            .sys_tags
            .iter()
            .chain(&rule.tags)
            .any(|tag| tag.to_lowercase().contains(query_lower))
}

fn print_snapshot(catalog: &Catalog, json: bool) -> ExitCode {
    let snapshot = catalog.snapshot();
    if json {
        print_json(snapshot);
        return ExitCode::SUCCESS;
    }
    println!("server_version: {}", snapshot.server_version);
    println!("edition: {}", snapshot.edition);
    println!("instance_mode: {}", snapshot.instance_mode);
    println!("captured_at_utc: {}", snapshot.captured_at_utc);
    println!("total_rules: {}", snapshot.total_rules);
    for (name, language) in catalog.languages() {
        println!("  {name}: {} rules", language.len());
    }
    ExitCode::SUCCESS
}

fn print_rule_row(rule: &RuleRecord) {
    println!(
        "{}  {}  {}",
        rule.external_key, rule.severity, rule.rule_type
    );
}

fn print_rule_info(rule: &RuleRecord) {
    println!("{}", rule.external_key);
    println!("  repository: {}", rule.repository);
    println!("  language: {}", rule.language);
    println!("  status: {}", rule.status);
    println!("  severity: {}", rule.severity);
    println!("  rule_type: {}", rule.rule_type);
    println!(
        "  clean_code_attribute: {}",
        rule.clean_code_attribute.as_deref().unwrap_or("-")
    );
    let impacts: Vec<String> = rule
        .impacts
        .iter()
        .map(|impact| format!("{}/{}", impact.software_quality, impact.severity))
        .collect();
    println!("  impacts: {}", impacts.join(", "));
    if !rule.tags.is_empty() {
        println!("  tags: {}", rule.tags.join(", "));
    }
    if !rule.sys_tags.is_empty() {
        println!("  sys_tags: {}", rule.sys_tags.join(", "));
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer(&mut out, value).expect("serialize catalog data");
    out.write_all(b"\n").expect("write trailing newline");
}

fn unknown_language(value: &str) -> ExitCode {
    eprintln!("unknown language: {value}");
    ExitCode::from(2)
}

/// Strips the `repository:` prefix from a catalog external key for the
/// `SonarQube` Generic Issue Import `ruleId` field (e.g. `python:S103` becomes
/// `S103`); keys without a prefix pass through unchanged.
fn sonar_rule_id(rule_key: &str) -> &str {
    match rule_key.split_once(':') {
        Some((_, rule_id)) => rule_id,
        None => rule_key,
    }
}

/// Renders the human-readable analyze report: one line per finding, then a
/// summary line. Byte-identical to the historical inline printing.
fn render_text_report(reports: &[hoonarqube_ir::FileReport]) -> String {
    let total_issues: usize = reports.iter().map(|report| report.issues.len()).sum();
    let mut out = String::new();
    for report in reports {
        for issue in &report.issues {
            let _ = writeln!(
                out,
                "{}:{}:{}: {}: {}",
                report.path.display(),
                issue.range.start.line,
                issue.range.start.column,
                issue.rule_key,
                issue.message
            );
        }
    }
    let _ = writeln!(
        out,
        "analyzed {} file(s), {} finding(s)",
        reports.len(),
        total_issues
    );
    out
}

/// Builds a `SonarQube` Generic Issue Import document: every finding becomes one
/// issue with `engineId`/`ruleId`/`severity`/`type` and a single
/// `primaryLocation`. Positions reuse the IR convention (1-based lines,
/// 0-based columns); optional fields are omitted rather than emitted as null.
fn sonar_import_value(reports: &[hoonarqube_ir::FileReport]) -> serde_json::Value {
    let issues: Vec<serde_json::Value> = reports
        .iter()
        .flat_map(|report| {
            let file_path = report.path.display().to_string();
            report.issues.iter().map(move |issue| {
                serde_json::json!({
                    "engineId": "hoonarqube",
                    "ruleId": sonar_rule_id(&issue.rule_key),
                    "severity": "INFO",
                    "type": "CODE_SMELL",
                    "primaryLocation": {
                        "message": &issue.message,
                        "filePath": file_path,
                        "textRange": {
                            "startLine": issue.range.start.line,
                            "startColumn": issue.range.start.column,
                            "endLine": issue.range.end.line,
                            "endColumn": issue.range.end.column,
                        },
                    },
                })
            })
        })
        .collect();
    serde_json::json!({ "issues": issues })
}

/// Validates input paths and the requested output format, then walks and
/// analyzes them; issues found are not failures (scanner-style); only missing
/// paths or an unknown format exit nonzero.
fn run_analyze(
    catalog: &Catalog,
    paths: &[std::path::PathBuf],
    format: Option<&str>,
    json_flag: bool,
) -> ExitCode {
    let format = match analyze_format(format, json_flag) {
        Ok(format) => format,
        Err(value) => {
            eprintln!("unknown format: {value}");
            return ExitCode::from(2);
        }
    };

    let mut valid = true;
    for path in paths {
        if !path.exists() {
            eprintln!("path does not exist: {}", path.display());
            valid = false;
        }
    }
    if !valid {
        return ExitCode::from(2);
    }

    let options = analyze::analyzer_options_bundle(catalog);
    let mut warnings = Vec::new();
    let reports = analyze::analyze_paths(paths, &options, &mut warnings);
    for warning in &warnings {
        eprintln!("{warning}");
    }

    match format {
        AnalyzeFormat::Json => {
            print_json(&hoonarqube_ir::AnalysisReport { files: reports });
        }
        AnalyzeFormat::Sonar => print_json(&sonar_import_value(&reports)),
        AnalyzeFormat::Text => print!("{}", render_text_report(&reports)),
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    use hoonarqube_ir::{FileMetrics, FileReport, Issue, Pos, Range};

    fn sample_report(path: &str, language: &str, issues: Vec<Issue>) -> FileReport {
        FileReport {
            path: std::path::PathBuf::from(path),
            language: language.to_string(),
            issues,
            metrics: FileMetrics {
                lines: 2,
                code_lines: 2,
                comment_lines: 0,
            },
        }
    }

    #[test]
    fn sonar_import_maps_findings_to_generic_schema() {
        let reports = vec![
            sample_report(
                "src/bad.js",
                "javascript",
                vec![Issue {
                    rule_key: "javascript:S1523".to_string(),
                    message: "Remove this usage of 'eval'.".to_string(),
                    range: Range {
                        start: Pos { line: 1, column: 0 },
                        end: Pos { line: 1, column: 4 },
                    },
                }],
            ),
            sample_report(
                "src/long.py",
                "python",
                vec![Issue {
                    rule_key: "python:LineLength".to_string(),
                    message: "This line exceeds the maximum allowed length of 120 characters."
                        .to_string(),
                    range: Range {
                        start: Pos { line: 3, column: 0 },
                        end: Pos {
                            line: 3,
                            column: 140,
                        },
                    },
                }],
            ),
        ];

        let value = sonar_import_value(&reports);
        let issues = value["issues"].as_array().expect("issues array");
        assert_eq!(issues.len(), 2);

        let first = &issues[0];
        assert_eq!(first["engineId"], "hoonarqube");
        assert_eq!(first["ruleId"], "S1523");
        assert_eq!(first["severity"], "INFO");
        assert_eq!(first["type"], "CODE_SMELL");
        assert_eq!(
            first["primaryLocation"]["message"],
            "Remove this usage of 'eval'."
        );
        assert_eq!(first["primaryLocation"]["filePath"], "src/bad.js");
        assert_eq!(first["primaryLocation"]["textRange"]["startLine"], 1);
        assert_eq!(first["primaryLocation"]["textRange"]["startColumn"], 0);
        assert_eq!(first["primaryLocation"]["textRange"]["endLine"], 1);
        assert_eq!(first["primaryLocation"]["textRange"]["endColumn"], 4);

        assert_eq!(issues[1]["ruleId"], "LineLength");
        assert_eq!(issues[1]["primaryLocation"]["filePath"], "src/long.py");

        // Generic-import optional fields are omitted, never emitted as null.
        assert!(!value.to_string().contains("null"));
    }

    #[test]
    fn sonar_import_of_clean_report_has_empty_issue_list() {
        let value = sonar_import_value(&[]);
        assert_eq!(value["issues"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn sonar_rule_id_strips_repository_prefix() {
        assert_eq!(sonar_rule_id("typescript:S122"), "S122");
        assert_eq!(sonar_rule_id("python:LineLength"), "LineLength");
        assert_eq!(sonar_rule_id("S103"), "S103");
    }

    #[test]
    fn text_rendering_keeps_historical_line_format() {
        let reports = vec![sample_report(
            "a.js",
            "javascript",
            vec![Issue {
                rule_key: "javascript:S1523".to_string(),
                message: "Remove this usage of 'eval'.".to_string(),
                range: Range {
                    start: Pos {
                        line: 2,
                        column: 10,
                    },
                    end: Pos {
                        line: 2,
                        column: 14,
                    },
                },
            }],
        )];

        assert_eq!(
            render_text_report(&reports),
            "a.js:2:10: javascript:S1523: Remove this usage of 'eval'.\n\
             analyzed 1 file(s), 1 finding(s)\n"
        );
    }

    #[test]
    fn json_rendering_keeps_the_ir_serialization() {
        let report = hoonarqube_ir::AnalysisReport {
            files: vec![sample_report(
                "a.py",
                "python",
                vec![Issue {
                    rule_key: "python:S103".to_string(),
                    message: "Line is too long".to_string(),
                    range: Range {
                        start: Pos { line: 1, column: 0 },
                        end: Pos {
                            line: 1,
                            column: 80,
                        },
                    },
                }],
            )],
        };

        assert_eq!(
            serde_json::to_string(&report).expect("serialize report"),
            "{\"files\":[{\"path\":\"a.py\",\"language\":\"python\",\"issues\":[{\"rule_key\":\"python:S103\",\"message\":\"Line is too long\",\"range\":{\"start\":{\"line\":1,\"column\":0},\"end\":{\"line\":1,\"column\":80}}}],\"metrics\":{\"lines\":2,\"code_lines\":2,\"comment_lines\":0}}]}"
        );
    }

    #[test]
    fn analyze_format_prefers_explicit_format_over_json_flag() {
        assert_eq!(
            analyze_format(Some("sonar"), false),
            Ok(AnalyzeFormat::Sonar)
        );
        assert_eq!(analyze_format(Some("json"), false), Ok(AnalyzeFormat::Json));
        assert_eq!(analyze_format(Some("text"), false), Ok(AnalyzeFormat::Text));
        // The legacy global `--json` flag stays an alias of `json`.
        assert_eq!(analyze_format(None, true), Ok(AnalyzeFormat::Json));
        assert_eq!(analyze_format(None, false), Ok(AnalyzeFormat::Text));
        assert_eq!(analyze_format(Some("text"), true), Ok(AnalyzeFormat::Text));
        assert_eq!(
            analyze_format(Some("sonar"), true),
            Ok(AnalyzeFormat::Sonar)
        );
        assert_eq!(analyze_format(Some("xml"), true), Err("xml".to_string()));
    }
}
