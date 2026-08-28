//! Analyzer and catalog-query CLI over the frozen embedded rule catalog.
//!
//! `snapshot` and `rules` read exclusively from
//! [`hoonarqube_catalog::embedded`]; `analyze` walks the given paths and
//! reads supported sources; `fix` plans quick fixes and rewrites them only
//! under `--apply`.

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hoonarqube_catalog::{Catalog, RuleRecord, embedded};
use hoonarqube_ir::{Range, TextEdit, apply_fixes};

mod analyze;

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
    /// Detect and optionally apply automatic fixes.
    ///
    /// Two categories: catalog-rule quick fixes attached to findings and
    /// safe mechanical whitespace repairs (trailing spaces, missing final
    /// newline, leading tabs). The command runs as a dry run unless
    /// `--apply` is passed; applying re-verifies every targeted finding by
    /// re-analysis. See the README's quick-fix section for the workflow.
    Fix {
        /// Files or directories to fix.
        #[arg(required = true)]
        paths: Vec<std::path::PathBuf>,
        /// Restrict rule fixes to these keys (repeatable or comma-
        /// separated; prefix match, so `python:S17` selects `python:S1721`).
        #[arg(long = "rule", value_delimiter = ',')]
        rule: Vec<String>,
        /// Print unified diffs of the projected or applied rewrites.
        #[arg(long)]
        diff: bool,
        /// Write fixed files back; without this flag nothing is written.
        #[arg(long)]
        apply: bool,
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
        Command::Fix {
            paths,
            rule,
            diff,
            apply,
        } => run_fix(paths, rule, *diff, *apply, cli.json),
    }
}

/// Applies safe mechanical whitespace repairs to one source string: strips
/// trailing spaces and tabs, adds a missing final newline, and expands
/// leading tabs. Line terminators (LF or CRLF) are preserved verbatim.
/// Returns the repaired text and the number of repairs, or `None` when the
/// source is already clean.
fn mechanical_fixed(source: &str) -> Option<(String, usize)> {
    let mut fixed = source.to_string();
    let mut applied = 0_usize;

    // Split on '\n' only so a '\r' stays attached to its line: CRLF
    // terminators survive the round trip. The '\r' is terminator, not
    // content, so it is peeled off before trimming spaces/tabs and
    // re-attached afterwards; LF files keep the plain fast path shape.
    let trimmed: String = fixed
        .split('\n')
        .map(|line| {
            let (content, terminator) = match line.strip_suffix('\r') {
                Some(content) => (content, "\r"),
                None => (line, ""),
            };
            format!("{}{terminator}", content.trim_end_matches([' ', '\t']))
        })
        .collect::<Vec<_>>()
        .join("\n");
    if trimmed != fixed {
        applied += 1;
        fixed = trimmed;
    }
    if !fixed.is_empty() && !fixed.ends_with('\n') {
        applied += 1;
        fixed.push('\n');
    }
    if fixed.split('\n').any(|line| line.starts_with('\t')) {
        applied += 1;
        fixed = fixed
            .split('\n')
            .map(|line| {
                let tabs = line.len() - line.trim_start_matches('\t').len();
                format!("{}{}", " ".repeat(tabs * 4), line.trim_start_matches('\t'))
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    (applied > 0).then_some((fixed, applied))
}

/// One catalog-rule quick fix selected for a single file.
struct PlannedFix {
    rule_key: String,
    message: String,
    range: Range,
    edits: Vec<TextEdit>,
}

/// Per-file fix plan gathered from analysis plus the mechanical repair count.
struct FileFixPlan {
    path: std::path::PathBuf,
    source: String,
    fixes: Vec<PlannedFix>,
    mechanical: usize,
}

/// Result of applying one plan under `--apply`.
struct ApplyOutcome {
    /// Whether the rewritten content differed and was written back.
    written: bool,
    /// Fully-applied rule fixes (every edit survived conflict resolution).
    applied: usize,
    /// Whole rule fixes skipped because any of their edits conflicted.
    skipped: usize,
    /// Mechanical repairs folded into the written content.
    mechanical: usize,
    verified: usize,
    unverified: usize,
    /// New findings by rule-key count after re-analysis.
    regressions: usize,
    /// The projected final content (also used for `--diff` rendering).
    content: String,
}

/// Safe projection of one file plan. Conflict resolution is atomic per fix:
/// either every edit belonging to a fix appears in `content`, or none do.
struct FixProjection {
    content: String,
    applied_fix_indices: Vec<usize>,
    skipped: usize,
    mechanical: usize,
}

/// Whether any `--rule` filter selects `rule_key`: a filter matches by
/// prefix (`python:S17` selects `python:S1721`) and an empty filter list
/// selects everything.
fn rule_selected(rule_key: &str, filters: &[String]) -> bool {
    filters.is_empty() || filters.iter().any(|key| rule_key.starts_with(key.as_str()))
}

/// Deterministically resolves conflicts between complete rule fixes. Fixes
/// are ordered by their first edit, then rule key; earlier candidates win.
/// A conflict drops the entire later fix, never only one edit from a
/// multi-edit remedy. Adjacent edits remain compatible.
fn resolve_fix_conflicts(fixes: &[PlannedFix]) -> (Vec<usize>, usize) {
    let mut candidates: Vec<usize> = (0..fixes.len()).collect();
    candidates.sort_by(|&a, &b| {
        let a_start = fixes[a]
            .edits
            .first()
            .map_or(fixes[a].range.start, |edit| edit.range.start);
        let b_start = fixes[b]
            .edits
            .first()
            .map_or(fixes[b].range.start, |edit| edit.range.start);
        (a_start, fixes[a].rule_key.as_str()).cmp(&(b_start, fixes[b].rule_key.as_str()))
    });

    let mut kept: Vec<usize> = Vec::new();
    let mut dropped = 0_usize;
    for candidate in candidates {
        let conflicts = fixes[candidate].edits.is_empty()
            || kept.iter().copied().any(|winner| {
                fixes[candidate].edits.iter().any(|candidate_edit| {
                    fixes[winner]
                        .edits
                        .iter()
                        .any(|winner_edit| winner_edit.overlaps(candidate_edit))
                })
            });
        if conflicts {
            dropped += 1;
        } else {
            kept.push(candidate);
        }
    }
    (kept, dropped)
}

/// Projects a plan's would-be fixed content: surviving rule edits first
/// (dropped losers excluded), then the mechanical whitespace repair on top.
///
/// # Errors
/// Returns the IR engine's error when an edit cannot be applied to the
/// analyzed source (out-of-bounds or overlapping after resolution).
fn project_fixes(plan: &FileFixPlan) -> Result<FixProjection, hoonarqube_ir::FixApplyError> {
    let (applied_fix_indices, skipped) = resolve_fix_conflicts(&plan.fixes);
    let edits: Vec<&TextEdit> = applied_fix_indices
        .iter()
        .flat_map(|&index| plan.fixes[index].edits.iter())
        .collect();
    let mut content = apply_fixes(&plan.source, &edits)?;
    let mechanical = mechanical_fixed(&content).map_or(0, |(repaired, count)| {
        content = repaired;
        count
    });
    Ok(FixProjection {
        content,
        applied_fix_indices,
        skipped,
        mechanical,
    })
}

/// Counts issues by rule key for position-independent before/after checks.
fn issue_counts(issues: &[hoonarqube_ir::Issue]) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for issue in issues {
        *counts.entry(issue.rule_key.clone()).or_default() += 1;
    }
    counts
}

/// Verifies targeted fixes by requiring their rule's finding count to fall
/// by the number applied. This remains correct when earlier edits shift a
/// later finding's range. Also returns every rule whose count increased.
fn verify_analysis(
    targeted: &[&PlannedFix],
    before: &[hoonarqube_ir::Issue],
    after: &[hoonarqube_ir::Issue],
) -> (usize, usize, Vec<(String, usize)>) {
    let mut targets_by_rule = std::collections::BTreeMap::<String, usize>::new();
    for fix in targeted {
        *targets_by_rule.entry(fix.rule_key.clone()).or_default() += 1;
    }
    let before_counts = issue_counts(before);
    let after_counts = issue_counts(after);
    let mut verified = 0_usize;
    let mut unverified = 0_usize;
    for (rule_key, targeted_count) in &targets_by_rule {
        let before_count = before_counts.get(rule_key).copied().unwrap_or_default();
        let after_count = after_counts.get(rule_key).copied().unwrap_or_default();
        let resolved = before_count
            .saturating_sub(after_count)
            .min(*targeted_count);
        verified += resolved;
        unverified += targeted_count - resolved;
    }
    let regressions = after_counts
        .into_iter()
        .filter_map(|(rule_key, after_count)| {
            let before_count = before_counts.get(&rule_key).copied().unwrap_or_default();
            (after_count > before_count).then_some((rule_key, after_count - before_count))
        })
        .collect();
    (verified, unverified, regressions)
}

/// Applies one plan under `--apply`: writes the projected content when it
/// differs from the source, then re-analyzes and verifies every targeted
/// finding; unverified targets become warnings.
fn apply_plan(
    plan: &FileFixPlan,
    options: &analyze::AnalyzerOptionsBundle,
    warnings: &mut Vec<String>,
) -> Option<ApplyOutcome> {
    let projection = match project_fixes(plan) {
        Ok(projected) => projected,
        Err(error) => {
            warnings.push(format!("cannot fix {}: {error}", plan.path.display()));
            return None;
        }
    };
    let applied = projection.applied_fix_indices.len();
    let mut outcome = ApplyOutcome {
        written: false,
        applied,
        skipped: projection.skipped,
        mechanical: projection.mechanical,
        verified: 0,
        unverified: 0,
        regressions: 0,
        content: projection.content,
    };
    if outcome.skipped > 0 {
        warnings.push(format!(
            "{}: skipped {} conflicting rule fix(es)",
            plan.path.display(),
            outcome.skipped
        ));
    }

    let current = match std::fs::read_to_string(&plan.path) {
        Ok(current) => current,
        Err(error) => {
            warnings.push(format!("cannot re-read {}: {error}", plan.path.display()));
            return None;
        }
    };
    if current != plan.source {
        warnings.push(format!(
            "cannot fix {}: file changed after analysis",
            plan.path.display()
        ));
        return None;
    }

    let targeted: Vec<&PlannedFix> = projection
        .applied_fix_indices
        .iter()
        .map(|&index| &plan.fixes[index])
        .collect();
    let before = if targeted.is_empty() {
        Vec::new()
    } else {
        let Some(report) = hoonarqube_core::analyze(&plan.path, &plan.source, options) else {
            warnings.push(format!(
                "cannot verify fixes for {}: source is not analyzable",
                plan.path.display()
            ));
            return None;
        };
        report.issues
    };

    if outcome.content != plan.source {
        if let Err(error) = std::fs::write(&plan.path, &outcome.content) {
            warnings.push(format!("cannot write {}: {error}", plan.path.display()));
            return None;
        }
        outcome.written = true;
    }

    if targeted.is_empty() {
        return Some(outcome);
    }
    let Some(report) = hoonarqube_core::analyze(&plan.path, &outcome.content, options) else {
        outcome.unverified = targeted.len();
        warnings.push(format!(
            "cannot verify fixes for {}: rewritten source is not analyzable",
            plan.path.display()
        ));
        return Some(outcome);
    };
    let (verified, unverified, regressions) = verify_analysis(&targeted, &before, &report.issues);
    outcome.verified = verified;
    outcome.unverified = unverified;
    outcome.regressions = regressions.iter().map(|(_, count)| count).sum();
    if unverified > 0 {
        warnings.push(format!(
            "{}: {unverified} of {} applied rule fix(es) did not remove their findings",
            plan.path.display(),
            targeted.len()
        ));
    }
    for (rule_key, count) in regressions {
        warnings.push(format!(
            "{}: re-analysis found {count} new {rule_key} finding(s)",
            plan.path.display()
        ));
    }
    Some(outcome)
}

/// Serializes one plan's stable identity for JSON output.
fn file_plan_json(plan: &FileFixPlan) -> serde_json::Value {
    serde_json::json!({
        "path": plan.path.display().to_string(),
        "fixes": plan
            .fixes
            .iter()
            .map(|fix| {
                serde_json::json!({
                    "rule_key": fix.rule_key,
                    "message": fix.message,
                    "range": fix.range,
                    "edits": fix.edits,
                })
            })
            .collect::<Vec<_>>(),
        "mechanical": plan.mechanical,
    })
}

/// Renders a unified diff between `old` and `new` with three context lines.
///
/// Deliberately hand-rolled and minimal: one hunk built by trimming the
/// common line prefix and suffix, which keeps the renderer dependency-free
/// while producing correct headers and `\ No newline at end of file`
/// markers. Empty output means both texts are identical.
fn unified_diff(path: &std::path::Path, old: &str, new: &str) -> String {
    /// Splits into newline-inclusive lines so the trailing-newline state is
    /// part of line equality; an empty text has no lines.
    fn terminated_lines(text: &str) -> Vec<&str> {
        if text.is_empty() {
            Vec::new()
        } else {
            text.split_inclusive('\n').collect()
        }
    }

    /// Emits one diff body line; a line without its `\n` gets the standard
    /// missing-newline marker.
    fn emit_line(out: &mut String, tag: char, line: &str) {
        if let Some(content) = line.strip_suffix('\n') {
            let _ = writeln!(out, "{tag}{content}");
        } else {
            let _ = writeln!(out, "{tag}{line}");
            let _ = writeln!(out, "\\ No newline at end of file");
        }
    }

    const CONTEXT: usize = 3;
    let old_lines = terminated_lines(old);
    let new_lines = terminated_lines(new);
    let mut prefix = 0_usize;
    while prefix < old_lines.len()
        && prefix < new_lines.len()
        && old_lines[prefix] == new_lines[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0_usize;
    while suffix < old_lines.len() - prefix
        && suffix < new_lines.len() - prefix
        && old_lines[old_lines.len() - 1 - suffix] == new_lines[new_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }
    if prefix + suffix == old_lines.len() && prefix + suffix == new_lines.len() {
        return String::new();
    }

    let first_context = prefix.saturating_sub(CONTEXT);
    let old_body_end = old_lines.len() - suffix;
    let new_body_end = new_lines.len() - suffix;
    let old_hunk_end = (old_body_end + CONTEXT).min(old_lines.len());
    let new_hunk_end = (new_body_end + CONTEXT).min(new_lines.len());

    let mut out = String::new();
    let label = path.display().to_string();
    let label = label.trim_start_matches('/');
    let _ = writeln!(out, "--- a/{label}");
    let _ = writeln!(out, "+++ b/{label}");
    // An empty side uses the conventional zero-based start position.
    let old_start = if old_hunk_end == first_context {
        first_context
    } else {
        first_context + 1
    };
    let new_start = if new_hunk_end == first_context {
        first_context
    } else {
        first_context + 1
    };
    let _ = writeln!(
        out,
        "@@ -{},{} +{},{} @@",
        old_start,
        old_hunk_end - first_context,
        new_start,
        new_hunk_end - first_context
    );
    for line in &old_lines[first_context..prefix] {
        emit_line(&mut out, ' ', line);
    }
    for line in &old_lines[prefix..old_body_end] {
        emit_line(&mut out, '-', line);
    }
    for line in &new_lines[prefix..new_body_end] {
        emit_line(&mut out, '+', line);
    }
    for line in &new_lines[new_body_end..new_hunk_end] {
        emit_line(&mut out, ' ', line);
    }
    out
}

/// Plans fixes for every explicitly passed file plus, for directories,
/// every supported source file found by the same recursive walk the
/// `analyze` command uses. Unreadable paths become warnings; non-source
/// files stay eligible for mechanical repairs only.
fn fix_plans(
    paths: &[std::path::PathBuf],
    rules: &[String],
    options: &analyze::AnalyzerOptionsBundle,
    warnings: &mut Vec<String>,
) -> Vec<FileFixPlan> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for path in paths {
        if path.is_dir() {
            analyze::collect_files(path, &mut files, warnings);
        } else {
            files.push(path.clone());
        }
    }
    files.sort();
    files.dedup();

    let mut plans = Vec::new();
    for path in &files {
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) => {
                warnings.push(format!("cannot read {}: skipped ({error})", path.display()));
                continue;
            }
        };
        let planned: Vec<PlannedFix> = hoonarqube_core::analyze(path, &source, options)
            .map(|report| {
                report
                    .issues
                    .into_iter()
                    .filter_map(|issue| {
                        let fix = issue.fix?;
                        if !rule_selected(&issue.rule_key, rules) {
                            return None;
                        }
                        Some(PlannedFix {
                            rule_key: issue.rule_key,
                            message: fix.message,
                            range: issue.range,
                            edits: fix.edits,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mechanical = mechanical_fixed(&source).map_or(0, |(_, count)| count);
        if planned.is_empty() && mechanical == 0 {
            continue;
        }
        plans.push(FileFixPlan {
            path: path.clone(),
            source,
            fixes: planned,
            mechanical,
        });
    }
    plans
}

/// Runs the `fix` subcommand: dry-run reporting by default, unified diffs
/// under `--diff`, write-and-verify under `--apply`. Exits nonzero on any
/// warning or unverified finding.
fn run_fix(
    paths: &[std::path::PathBuf],
    rules: &[String],
    diff: bool,
    apply: bool,
    json: bool,
) -> ExitCode {
    let mut warnings = Vec::new();
    let options = analyze::analyzer_options_bundle(embedded());
    let plans = fix_plans(paths, rules, &options, &mut warnings);
    if apply {
        run_fix_apply(&plans, &options, diff, json, &mut warnings)
    } else {
        run_fix_dry_run(&plans, diff, json, &mut warnings)
    }
}

/// Prints warnings on stderr and maps them to the command exit code.
fn exit_with_warnings(warnings: &[String]) -> ExitCode {
    for warning in warnings {
        eprintln!("{warning}");
    }
    if warnings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Dry-run reporting: lists planned rule fixes and mechanical repairs and
/// writes nothing.
fn run_fix_dry_run(
    plans: &[FileFixPlan],
    diff: bool,
    json: bool,
    warnings: &mut Vec<String>,
) -> ExitCode {
    let mut rows = Vec::with_capacity(plans.len());
    let mut applicable_total = 0_usize;
    let mut skipped_total = 0_usize;
    let mut mechanical_total = 0_usize;
    for plan in plans {
        let mut row = file_plan_json(plan);
        match project_fixes(plan) {
            Ok(projection) => {
                let applicable = projection.applied_fix_indices.len();
                applicable_total += applicable;
                skipped_total += projection.skipped;
                mechanical_total += projection.mechanical;
                if projection.skipped > 0 {
                    warnings.push(format!(
                        "{}: would skip {} conflicting rule fix(es)",
                        plan.path.display(),
                        projection.skipped
                    ));
                }
                let rendered_diff =
                    diff.then(|| unified_diff(&plan.path, &plan.source, &projection.content));

                if !json {
                    println!(
                        "{}: {} applicable rule fix(es), {} mechanical fix(es), {} skipped",
                        plan.path.display(),
                        applicable,
                        projection.mechanical,
                        projection.skipped
                    );
                    for fix in &plan.fixes {
                        println!(
                            "  {} at {}:{}-{}:{}: {}",
                            fix.rule_key,
                            fix.range.start.line,
                            fix.range.start.column,
                            fix.range.end.line,
                            fix.range.end.column,
                            fix.message
                        );
                    }
                    if let Some(rendered_diff) = &rendered_diff {
                        print!("{rendered_diff}");
                    }
                }

                if let Some(object) = row.as_object_mut() {
                    object.insert("applicable".into(), serde_json::Value::from(applicable));
                    object.insert(
                        "skipped".into(),
                        serde_json::Value::from(projection.skipped),
                    );
                    object.insert(
                        "mechanical".into(),
                        serde_json::Value::from(projection.mechanical),
                    );
                    if let Some(rendered_diff) = rendered_diff {
                        object.insert("diff".into(), serde_json::Value::String(rendered_diff));
                    }
                }
            }
            Err(error) => {
                warnings.push(format!("cannot fix {}: {error}", plan.path.display()));
                skipped_total += plan.fixes.len();
                if let Some(object) = row.as_object_mut() {
                    object.insert("applicable".into(), serde_json::Value::from(0));
                    object.insert("skipped".into(), serde_json::Value::from(plan.fixes.len()));
                }
            }
        }
        rows.push(row);
    }

    if json {
        print_json(&serde_json::json!({
            "files": rows,
            "planned": plans.iter().map(|plan| plan.fixes.len()).sum::<usize>(),
            "applicable": applicable_total,
            "skipped": skipped_total,
            "mechanical": mechanical_total,
            "applied": 0,
            "verified": 0,
            "unverified": 0,
            "warnings": warnings,
        }));
    } else {
        println!(
            "would apply {applicable_total} rule fix(es) across {} file(s), \
             {mechanical_total} mechanical fix(es), skip {skipped_total}; dry run, \
             pass --apply to write",
            plans.len()
        );
    }
    exit_with_warnings(warnings)
}

/// Apply mode: writes each projected rewrite once, re-analyzes the written
/// file, and verifies every targeted finding disappeared without increasing
/// any rule's finding count. Warnings fail the run.
fn run_fix_apply(
    plans: &[FileFixPlan],
    options: &analyze::AnalyzerOptionsBundle,
    diff: bool,
    json: bool,
    warnings: &mut Vec<String>,
) -> ExitCode {
    let mut applied_total = 0_usize;
    let mut skipped_total = 0_usize;
    let mut verified_total = 0_usize;
    let mut unverified_total = 0_usize;
    let mut regression_total = 0_usize;
    let mut mechanical_total = 0_usize;
    let mut written_files = 0_usize;
    let mut rows = Vec::with_capacity(plans.len());
    for plan in plans {
        let mut row = file_plan_json(plan);
        let Some(outcome) = apply_plan(plan, options, warnings) else {
            if let Some(object) = row.as_object_mut() {
                object.insert("written".into(), serde_json::Value::Bool(false));
                object.insert("applied".into(), serde_json::Value::from(0));
                object.insert("skipped".into(), serde_json::Value::from(0));
                object.insert("verified".into(), serde_json::Value::from(0));
                object.insert("unverified".into(), serde_json::Value::from(0));
                object.insert("regressions".into(), serde_json::Value::from(0));
                object.insert("mechanical".into(), serde_json::Value::from(0));
            }
            rows.push(row);
            continue;
        };
        skipped_total += outcome.skipped;
        verified_total += outcome.verified;
        unverified_total += outcome.unverified;
        regression_total += outcome.regressions;
        if outcome.written {
            written_files += 1;
            applied_total += outcome.applied;
            mechanical_total += outcome.mechanical;
        }
        let rendered_diff = (diff && outcome.written)
            .then(|| unified_diff(&plan.path, &plan.source, &outcome.content));
        if !json && outcome.written {
            println!(
                "{}: wrote {} rule fix(es), {} mechanical fix(es), verified {}, unverified {}, skipped {}",
                plan.path.display(),
                outcome.applied,
                outcome.mechanical,
                outcome.verified,
                outcome.unverified,
                outcome.skipped
            );
            if let Some(rendered_diff) = &rendered_diff {
                print!("{rendered_diff}");
            }
        }
        if let Some(object) = row.as_object_mut() {
            let applied = if outcome.written { outcome.applied } else { 0 };
            object.insert("written".into(), serde_json::Value::Bool(outcome.written));
            object.insert("applied".into(), serde_json::Value::from(applied));
            object.insert("skipped".into(), serde_json::Value::from(outcome.skipped));
            object.insert("verified".into(), serde_json::Value::from(outcome.verified));
            object.insert(
                "unverified".into(),
                serde_json::Value::from(outcome.unverified),
            );
            object.insert(
                "regressions".into(),
                serde_json::Value::from(outcome.regressions),
            );
            object.insert(
                "mechanical".into(),
                serde_json::Value::from(outcome.mechanical),
            );
            if let Some(rendered_diff) = rendered_diff {
                object.insert("diff".into(), serde_json::Value::String(rendered_diff));
            }
        }
        rows.push(row);
    }
    for warning in &*warnings {
        eprintln!("{warning}");
    }
    if json {
        print_json(&serde_json::json!({
            "files": rows,
            "applied": applied_total,
            "skipped": skipped_total,
            "mechanical": mechanical_total,
            "verified": verified_total,
            "unverified": unverified_total,
            "regressions": regression_total,
            "warnings": warnings,
        }));
    } else {
        println!(
            "applied {applied_total} rule fix(es) across {written_files} file(s), \
             {mechanical_total} mechanical fix(es), verified {verified_total}, \
             unverified {unverified_total}, skipped {skipped_total}, \
             regressions {regression_total}"
        );
    }
    if warnings.is_empty() && unverified_total == 0 && regression_total == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_rules(catalog: &Catalog, cmd: &RulesCommand, json: bool) -> ExitCode {
    match cmd {
        RulesCommand::List { lang } => match select_language(catalog, lang.as_deref()) {
            Some(languages) => {
                let rules: Vec<&RuleRecord> = languages.collect();
                if json {
                    print_json(&rules);
                } else {
                    for rule in rules {
                        print_rule_row(rule);
                    }
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
            let matched: Vec<&RuleRecord> = languages
                .into_iter()
                .filter(|rule| rule_matches(rule, &query_lower))
                .collect();
            if json {
                print_json(&matched);
            } else if matched.is_empty() {
                println!("no matching rules");
            } else {
                for rule in &matched {
                    print_rule_row(rule);
                }
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
            let rules = catalog
                .languages()
                .find(|(_, language)| language.name() == lang || language.language_id() == lang)
                .map(|(_, language)| language.rules())?;
            Some(Box::new(rules.iter()) as Box<dyn Iterator<Item = &'a RuleRecord> + 'a>)
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
    println!("oracle_edition: {}", snapshot.oracle_edition);
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

/// Keeps the repository-qualified catalog key as the Generic Issue Import rule
/// id. A single report can contain Python, JS/TS, and C#; stripping the prefix
/// would collapse distinct rules such as `python:S112` and `csharpsquid:S112`.
fn sonar_rule_id(rule_key: &str) -> &str {
    rule_key
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

/// Builds the current `SonarQube` Generic Issue Import document. Every used rule
/// is defined once in the top-level `rules` array; findings reference it by the
/// repository-qualified `ruleId`. Catalog classification and impacts remain the
/// single metadata source. Positions reuse the IR convention (1-based lines,
/// 0-based columns); optional fields are omitted rather than emitted as null.
fn sonar_import_value(
    catalog: &Catalog,
    reports: &[hoonarqube_ir::FileReport],
) -> serde_json::Value {
    let mut rules = std::collections::BTreeMap::new();
    let mut issues = Vec::new();
    for report in reports {
        let file_path = report.path.display().to_string();
        for issue in &report.issues {
            let rule_id = sonar_rule_id(&issue.rule_key);
            rules.entry(rule_id.to_string()).or_insert_with(|| {
                let (clean_code_attribute, rule_type, severity, impacts) =
                    match catalog.rule(&issue.rule_key) {
                        Some(record) => (
                            record
                                .clean_code_attribute
                                .as_deref()
                                .unwrap_or("CONVENTIONAL"),
                            record.rule_type.as_str(),
                            record.severity.as_str(),
                            record
                                .impacts
                                .iter()
                                .map(|impact| {
                                    serde_json::json!({
                                        "softwareQuality": impact.software_quality,
                                        "severity": impact.severity,
                                    })
                                })
                                .collect::<Vec<_>>(),
                        ),
                        None => (
                            "CONVENTIONAL",
                            "CODE_SMELL",
                            "INFO",
                            vec![serde_json::json!({
                                "softwareQuality": "MAINTAINABILITY",
                                "severity": "MEDIUM",
                            })],
                        ),
                    };
                serde_json::json!({
                    "id": rule_id,
                    "name": issue.rule_key,
                    "description": format!("Hoonarqube finding for `{}`.", issue.rule_key),
                    "engineId": "hoonarqube",
                    "cleanCodeAttribute": clean_code_attribute,
                    "type": rule_type,
                    "severity": severity,
                    "impacts": impacts,
                })
            });
            let mut primary_location = serde_json::json!({
                "message": &issue.message,
                "filePath": file_path,
            });
            if !issue.range.is_file_level() {
                primary_location["textRange"] = serde_json::json!({
                    "startLine": issue.range.start.line,
                    "startColumn": issue.range.start.column,
                    "endLine": issue.range.end.line,
                    "endColumn": issue.range.end.column,
                });
            }
            issues.push(serde_json::json!({
                "ruleId": rule_id,
                "primaryLocation": primary_location,
            }));
        }
    }
    serde_json::json!({
        "rules": rules.into_values().collect::<Vec<_>>(),
        "issues": issues,
    })
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
        AnalyzeFormat::Sonar => print_json(&sonar_import_value(catalog, &reports)),
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
                    fix: None,
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
                    fix: None,
                }],
            ),
        ];

        let value = sonar_import_value(embedded(), &reports);
        let rules = value["rules"].as_array().expect("rules array");
        let issues = value["issues"].as_array().expect("issues array");
        assert_eq!(rules.len(), 2);
        assert_eq!(issues.len(), 2);

        let first_rule = &rules[0];
        assert_eq!(first_rule["id"], "javascript:S1523");
        assert_eq!(first_rule["engineId"], "hoonarqube");
        assert_eq!(first_rule["severity"], "CRITICAL");
        assert_eq!(first_rule["type"], "SECURITY_HOTSPOT");
        assert!(first_rule["cleanCodeAttribute"].is_string());
        assert!(first_rule["impacts"].is_array());

        let first = &issues[0];
        assert_eq!(first["ruleId"], "javascript:S1523");
        assert!(first.get("engineId").is_none());
        assert!(first.get("severity").is_none());
        assert!(first.get("type").is_none());
        assert_eq!(
            first["primaryLocation"]["message"],
            "Remove this usage of 'eval'."
        );
        assert_eq!(first["primaryLocation"]["filePath"], "src/bad.js");
        assert_eq!(first["primaryLocation"]["textRange"]["startLine"], 1);
        assert_eq!(first["primaryLocation"]["textRange"]["startColumn"], 0);
        assert_eq!(first["primaryLocation"]["textRange"]["endLine"], 1);
        assert_eq!(first["primaryLocation"]["textRange"]["endColumn"], 4);

        assert_eq!(issues[1]["ruleId"], "python:LineLength");
        assert_eq!(issues[1]["primaryLocation"]["filePath"], "src/long.py");

        // Generic-import optional fields are omitted, never emitted as null.
        assert!(!value.to_string().contains("null"));
    }

    #[test]
    fn sonar_import_of_clean_report_has_empty_issue_list() {
        let value = sonar_import_value(embedded(), &[]);
        assert_eq!(value["rules"].as_array().map(Vec::len), Some(0));
        assert_eq!(value["issues"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn sonar_import_omits_text_range_for_file_level_issues() {
        let reports = vec![sample_report(
            "src/no-newline.py",
            "python",
            vec![Issue {
                rule_key: "python:S113".to_string(),
                message: "Add a new line at the end of this file \"no-newline.py\".".to_string(),
                range: Range::file_level(),
                fix: None,
            }],
        )];
        let value = sonar_import_value(embedded(), &reports);
        let primary = &value["issues"][0]["primaryLocation"];
        assert_eq!(primary["filePath"], "src/no-newline.py");
        assert!(primary.get("textRange").is_none());
    }

    #[test]
    fn sonar_import_falls_back_to_info_for_unknown_rule_keys() {
        let reports = vec![sample_report(
            "src/unknown.py",
            "python",
            vec![Issue {
                rule_key: "python:S999999".to_string(),
                message: "not in the catalog".to_string(),
                range: Range {
                    start: Pos { line: 1, column: 0 },
                    end: Pos { line: 1, column: 1 },
                },
                fix: None,
            }],
        )];

        let value = sonar_import_value(embedded(), &reports);
        let rule = &value["rules"][0];
        assert_eq!(rule["id"], "python:S999999");
        assert_eq!(rule["severity"], "INFO");
        assert_eq!(rule["type"], "CODE_SMELL");
        assert_eq!(rule["cleanCodeAttribute"], "CONVENTIONAL");
        assert_eq!(rule["impacts"][0]["softwareQuality"], "MAINTAINABILITY");
        assert_eq!(value["issues"][0]["ruleId"], "python:S999999");
    }

    #[test]
    fn sonar_import_keeps_same_numeric_key_distinct_across_languages() {
        let issue = |rule_key: &str| Issue {
            rule_key: rule_key.to_string(),
            message: "generic exception".to_string(),
            range: Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 1 },
            },
            fix: None,
        };
        let reports = vec![
            sample_report("src/a.py", "python", vec![issue("python:S112")]),
            sample_report("src/a.cs", "csharp", vec![issue("csharpsquid:S112")]),
        ];

        let value = sonar_import_value(embedded(), &reports);
        let ids = value["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .map(|rule| rule["id"].as_str().expect("id"))
            .collect::<Vec<_>>();
        assert_eq!(ids, ["csharpsquid:S112", "python:S112"]);
        assert_eq!(value["issues"][0]["ruleId"], "python:S112");
        assert_eq!(value["issues"][1]["ruleId"], "csharpsquid:S112");
    }

    /// Unique temp path for `fix_file` tests; callers clean up after use.
    fn temp_fix_path(label: &str) -> std::path::PathBuf {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "hoonarqube-cli-fix-{label}-{}-{id}",
            std::process::id()
        ))
    }

    #[test]
    fn mechanical_fixing_preserves_crlf_and_strips_trailing_whitespace() {
        let (fixed, applied) = mechanical_fixed("alpha \r\nbeta\t\r\ngamma  ").expect("repairs");

        assert_eq!(applied, 2);
        assert_eq!(fixed, "alpha\r\nbeta\r\ngamma\n");
    }

    #[test]
    fn mechanical_fixing_leaves_clean_sources_untouched() {
        assert!(mechanical_fixed("x = 1\ny = 2\n").is_none());
    }

    #[test]
    fn fix_plans_report_unreadable_paths_as_warnings() {
        let missing = temp_fix_path("missing").join("nope.py");
        let options = analyze::analyzer_options_bundle(embedded());
        let mut warnings = Vec::new();

        assert!(fix_plans(std::slice::from_ref(&missing), &[], &options, &mut warnings).is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("cannot read "));
    }

    /// Creates a temporary directory holding one Python file with `source`;
    /// callers clean up the returned directory after use.
    fn temp_python_fixture(label: &str, source: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = temp_fix_path(label);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("find.py");
        std::fs::write(&file, source).expect("write fixture");
        (dir, file)
    }

    /// Builds a `TextEdit` from `(line, column)` tuples for compact tests.
    fn cli_edit(start: (u32, u32), end: (u32, u32), replacement: &str) -> TextEdit {
        TextEdit {
            range: Range {
                start: Pos {
                    line: start.0,
                    column: start.1,
                },
                end: Pos {
                    line: end.0,
                    column: end.1,
                },
            },
            replacement: replacement.to_string(),
        }
    }

    fn cli_fix(rule_key: &str, edits: Vec<TextEdit>) -> PlannedFix {
        let range = Range {
            start: edits.first().expect("at least one edit").range.start,
            end: edits.last().expect("at least one edit").range.end,
        };
        PlannedFix {
            rule_key: rule_key.to_string(),
            message: "test fix".to_string(),
            range,
            edits,
        }
    }

    const S1721_SOURCE: &str = "def f():\n    return(1)\n";

    #[test]
    fn dry_run_plans_s1721_without_touching_files() {
        let (dir, file) = temp_python_fixture("dry", S1721_SOURCE);
        let options = analyze::analyzer_options_bundle(embedded());
        let mut warnings = Vec::new();

        let plans = fix_plans(std::slice::from_ref(&file), &[], &options, &mut warnings);

        assert!(warnings.is_empty());
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].fixes.len(), 1);
        assert_eq!(plans[0].fixes[0].rule_key, "python:S1721");
        assert_eq!(plans[0].mechanical, 0);
        assert_eq!(
            std::fs::read_to_string(&file).expect("read back"),
            S1721_SOURCE,
            "dry run must not write"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rule_filter_matches_rule_key_prefixes() {
        let (dir, file) = temp_python_fixture("filter", S1721_SOURCE);
        let options = analyze::analyzer_options_bundle(embedded());
        let mut warnings = Vec::new();

        let matched = fix_plans(
            std::slice::from_ref(&file),
            &["python:S17".to_string()],
            &options,
            &mut warnings,
        );
        assert_eq!(matched[0].fixes.len(), 1);

        let other_language = fix_plans(
            std::slice::from_ref(&file),
            &["javascript:".to_string()],
            &options,
            &mut warnings,
        );
        assert!(other_language.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_resolves_seeded_s1721_finding_end_to_end() {
        let (dir, file) = temp_python_fixture("e2e", S1721_SOURCE);
        let options = analyze::analyzer_options_bundle(embedded());
        let mut warnings = Vec::new();

        let plans = fix_plans(std::slice::from_ref(&file), &[], &options, &mut warnings);
        assert_eq!(plans[0].fixes.len(), 1);

        let outcome = apply_plan(&plans[0], &options, &mut warnings).expect("applies");

        assert!(outcome.written);
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.verified, 1);
        assert_eq!(outcome.unverified, 0);
        assert!(warnings.is_empty());
        assert_eq!(
            std::fs::read_to_string(&file).expect("read back"),
            "def f():\n    return 1\n"
        );
        // The re-analysis the verification relied on really is clean.
        let fixed_source = "def f():\n    return 1\n";
        let report = hoonarqube_core::analyze(&file, fixed_source, &options).expect("analyzable");
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.rule_key != "python:S1721")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_flags_a_fix_that_does_not_resolve_its_finding() {
        let (dir, file) = temp_python_fixture("stuck", S1721_SOURCE);
        let options = analyze::analyzer_options_bundle(embedded());

        // Hypothetical broken fixer: rewrites the argument instead of
        // dropping the parentheses, so the finding survives re-analysis.
        let plan = FileFixPlan {
            path: file.clone(),
            source: S1721_SOURCE.to_string(),
            fixes: vec![PlannedFix {
                rule_key: "python:S1721".to_string(),
                message: "broken".to_string(),
                range: Range {
                    start: Pos { line: 2, column: 4 },
                    end: Pos {
                        line: 2,
                        column: 10,
                    },
                },
                edits: vec![cli_edit((2, 11), (2, 12), " 2 ")],
            }],
            mechanical: 0,
        };
        let mut warnings = Vec::new();
        let outcome = apply_plan(&plan, &options, &mut warnings).expect("applies");

        assert!(outcome.written);
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.verified, 0);
        assert_eq!(outcome.unverified, 1);
        assert_eq!(warnings.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conflict_resolution_is_deterministic_and_atomic_per_fix() {
        let fixes = vec![
            cli_fix("zz:Early", vec![cli_edit((1, 0), (1, 5), "A")]),
            cli_fix("aa:Late", vec![cli_edit((1, 3), (1, 7), "B")]),
        ];
        let (kept, dropped) = resolve_fix_conflicts(&fixes);
        assert_eq!(dropped, 1);
        assert_eq!(kept, vec![0]);

        let fixes = vec![
            cli_fix("python:B", vec![cli_edit((1, 2), (1, 6), "Y")]),
            cli_fix("python:A", vec![cli_edit((1, 2), (1, 4), "X")]),
        ];
        let (kept, dropped) = resolve_fix_conflicts(&fixes);
        assert_eq!(dropped, 1);
        assert_eq!(kept, vec![1]);

        let fixes = vec![
            cli_fix("p:X", vec![cli_edit((1, 0), (1, 3), "L")]),
            cli_fix("p:Y", vec![cli_edit((1, 3), (1, 6), "R")]),
        ];
        let (kept, dropped) = resolve_fix_conflicts(&fixes);
        assert_eq!(dropped, 0);
        assert_eq!(kept, vec![0, 1]);

        // Winner overlaps only the first edit of the later fix. The later
        // fix must lose both edits; applying only its second edit would
        // corrupt a paired-parenthesis remedy.
        let fixes = vec![
            cli_fix(
                "p:Paired",
                vec![cli_edit((1, 2), (1, 3), ""), cli_edit((1, 8), (1, 9), "")],
            ),
            cli_fix("p:Winner", vec![cli_edit((1, 0), (1, 5), "W")]),
        ];
        let (kept, dropped) = resolve_fix_conflicts(&fixes);
        assert_eq!(dropped, 1);
        assert_eq!(kept, vec![1]);
    }

    #[test]
    fn verification_uses_count_reduction_and_detects_regressions() {
        let resolved = cli_fix("python:S1", vec![cli_edit((1, 0), (1, 1), "")]);
        let stuck = cli_fix("python:S2", vec![cli_edit((2, 0), (2, 1), "")]);
        let issue = |rule_key: &str, line: u32, column: u32| Issue {
            rule_key: rule_key.to_string(),
            message: "finding".to_string(),
            range: Range {
                start: Pos { line, column },
                end: Pos {
                    line,
                    column: column + 1,
                },
            },
            fix: None,
        };
        let before = vec![issue("python:S1", 1, 0), issue("python:S2", 2, 0)];
        // S2 moved because of an earlier edit, but its unchanged count still
        // proves that fix did not resolve it. S3 is a new regression.
        let after = vec![issue("python:S2", 2, 3), issue("python:S3", 3, 0)];

        assert_eq!(
            verify_analysis(&[&resolved, &stuck], &before, &after),
            (1, 1, vec![("python:S3".to_string(), 1)])
        );
    }

    #[test]
    fn unified_diff_marks_missing_trailing_newlines() {
        assert_eq!(
            unified_diff(std::path::Path::new("t.py"), "a\nb", "a\nb\n"),
            "--- a/t.py\n+++ b/t.py\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n"
        );
        assert_eq!(
            unified_diff(std::path::Path::new("t.py"), "", "x = 1\n"),
            "--- a/t.py\n+++ b/t.py\n@@ -0,0 +1,1 @@\n+x = 1\n"
        );
    }

    #[test]
    fn sonar_rule_id_preserves_repository_prefix() {
        assert_eq!(sonar_rule_id("typescript:S122"), "typescript:S122");
        assert_eq!(sonar_rule_id("python:LineLength"), "python:LineLength");
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
                fix: None,
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
                    fix: None,
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

    #[test]
    fn select_language_accepts_catalog_names_and_ids() {
        let catalog = embedded();
        let by_id = select_language(catalog, Some("py")).expect("id resolves");
        let by_name = select_language(catalog, Some("python")).expect("name resolves");
        assert_eq!(by_id.count(), by_name.count());
        assert!(select_language(catalog, Some("zz")).is_none());
    }
}
