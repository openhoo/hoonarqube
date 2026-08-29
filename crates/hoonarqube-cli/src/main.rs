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
#[command(
    name = "hoonarqube",
    version,
    about = "Hoonarqube analyzer command line"
)]
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
        /// Expected literal Go license header (`go:S1451`); empty keeps the
        /// catalog-default disabled behavior.
        #[arg(long, default_value = "")]
        go_header_format: String,
    },
    /// Detect and optionally apply automatic fixes.
    ///
    /// Two categories: catalog-rule quick fixes attached to findings and a
    /// safe mechanical repair for a missing final newline. The command runs
    /// as a dry run unless
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
        Command::Analyze {
            paths,
            format,
            go_header_format,
        } => run_analyze(
            catalog,
            paths,
            format.as_deref(),
            go_header_format,
            cli.json,
        ),
        Command::Fix {
            paths,
            rule,
            diff,
            apply,
        } => run_fix(paths, rule, *diff, *apply, cli.json),
    }
}

/// Adds a missing final newline without touching source-content whitespace.
///
/// Leading tabs and trailing spaces can be data inside multiline/raw string
/// literals, so a language-agnostic fixer cannot safely rewrite them. The
/// existing final line-ending style is retained when one can be observed.
/// Returns the repaired text and one repair, or `None` when no repair applies.
fn mechanical_fixed(source: &str) -> Option<(String, usize)> {
    if source.is_empty() || source.ends_with('\n') {
        return None;
    }
    let uses_crlf = source
        .as_bytes()
        .iter()
        .rposition(|byte| *byte == b'\n')
        .is_some_and(|newline| newline > 0 && source.as_bytes()[newline - 1] == b'\r');
    let mut fixed = String::with_capacity(source.len() + usize::from(uses_crlf) + 1);
    fixed.push_str(source);
    if uses_crlf && !source.ends_with('\r') {
        fixed.push('\r');
    }
    fixed.push('\n');
    Some((fixed, 1))
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
/// (dropped losers excluded), then the final-newline repair on top.
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

/// Verifies one rule fix in isolation against the original analysis. Batch
/// count reductions alone can hide a broken fix when another same-rule fix
/// removes more findings than intended, so every remedy must also reduce its
/// own rule count without introducing any other finding.
fn fix_verifies_independently(
    plan: &FileFixPlan,
    fix: &PlannedFix,
    before: &[hoonarqube_ir::Issue],
    options: &analyze::AnalyzerOptionsBundle,
) -> bool {
    let edits: Vec<&TextEdit> = fix.edits.iter().collect();
    let Ok(content) = apply_fixes(&plan.source, &edits) else {
        return false;
    };
    let Some(report) = hoonarqube_core::analyze(&plan.path, &content, options) else {
        return false;
    };
    let (_, unverified, regressions) = verify_analysis(&[fix], before, &report.issues);
    unverified == 0 && regressions.is_empty()
}

fn verify_projected_rewrite(
    plan: &FileFixPlan,
    targeted: &[&PlannedFix],
    options: &analyze::AnalyzerOptionsBundle,
    outcome: &mut ApplyOutcome,
    warnings: &mut Vec<String>,
) -> bool {
    let Some(before) = hoonarqube_core::analyze(&plan.path, &plan.source, options) else {
        if targeted.is_empty() {
            return true;
        }
        outcome.unverified = targeted.len();
        warnings.push(format!(
            "cannot verify fixes for {}: source is not analyzable",
            plan.path.display()
        ));
        return false;
    };
    let independently_verified = targeted
        .iter()
        .filter(|fix| fix_verifies_independently(plan, fix, &before.issues, options))
        .count();
    if independently_verified != targeted.len() {
        outcome.verified = independently_verified;
        outcome.unverified = targeted.len() - independently_verified;
        warnings.push(format!(
            "{}: {} of {} projected rule fix(es) do not independently remove their findings",
            plan.path.display(),
            outcome.unverified,
            targeted.len()
        ));
        return false;
    }
    let Some(after) = hoonarqube_core::analyze(&plan.path, &outcome.content, options) else {
        outcome.unverified = targeted.len();
        warnings.push(format!(
            "cannot verify rewrite for {}: projected source is not analyzable",
            plan.path.display()
        ));
        return false;
    };
    let (verified, unverified, regressions) =
        verify_analysis(targeted, &before.issues, &after.issues);
    outcome.verified = verified;
    outcome.unverified = unverified;
    outcome.regressions = regressions.iter().map(|(_, count)| count).sum();
    if unverified > 0 {
        warnings.push(format!(
            "{}: {unverified} of {} projected rule fix(es) did not remove their findings",
            plan.path.display(),
            targeted.len()
        ));
    }
    for (rule_key, count) in regressions {
        warnings.push(format!(
            "{}: projected source has {count} new {rule_key} finding(s)",
            plan.path.display()
        ));
    }
    outcome.unverified == 0 && outcome.regressions == 0
}

fn source_matches_plan(plan: &FileFixPlan, warnings: &mut Vec<String>) -> bool {
    let current = match std::fs::read_to_string(&plan.path) {
        Ok(current) => current,
        Err(error) => {
            warnings.push(format!("cannot re-read {}: {error}", plan.path.display()));
            return false;
        }
    };
    if current == plan.source {
        return true;
    }
    warnings.push(format!(
        "cannot fix {}: file changed after analysis",
        plan.path.display()
    ));
    false
}

/// Applies one plan under `--apply`: verifies the projected content in memory,
/// then writes it only when every targeted finding disappears without a
/// regression. Broken rule fixes therefore fail closed and leave the file
/// untouched.
fn apply_plan(
    plan: &FileFixPlan,
    options: &analyze::AnalyzerOptionsBundle,
    warnings: &mut Vec<String>,
) -> Option<ApplyOutcome> {
    if !apply_path_is_regular_file(&plan.path, warnings) {
        return None;
    }
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

    if !source_matches_plan(plan, warnings) {
        return None;
    }

    let targeted: Vec<&PlannedFix> = projection
        .applied_fix_indices
        .iter()
        .map(|&index| &plan.fixes[index])
        .collect();
    if !verify_projected_rewrite(plan, &targeted, options, &mut outcome, warnings) {
        return Some(outcome);
    }

    if !write_applied_content(plan, &mut outcome, warnings) {
        return None;
    }
    Some(outcome)
}

fn write_applied_content(
    plan: &FileFixPlan,
    outcome: &mut ApplyOutcome,
    warnings: &mut Vec<String>,
) -> bool {
    if outcome.content == plan.source {
        return true;
    }
    if !apply_path_is_regular_file(&plan.path, warnings) {
        return false;
    }
    if !source_matches_plan(plan, warnings) {
        return false;
    }
    if let Err(error) = replace_file(
        &plan.path,
        plan.source.as_bytes(),
        outcome.content.as_bytes(),
    ) {
        warnings.push(format!("cannot write {}: {error}", plan.path.display()));
        return false;
    }
    outcome.written = true;
    true
}

/// Writes a complete sibling temporary file, preserves the original mode, and
/// renames it over `path`. Readers therefore see either complete old content or
/// complete new content. A hard-linked input gets its own rewritten inode, so
/// applying a fix cannot unexpectedly mutate another path outside the target.
///
#[cfg(windows)]
fn replace_file(path: &std::path::Path, expected: &[u8], content: &[u8]) -> std::io::Result<()> {
    use atomicwrites::{AllowOverwrite, AtomicFile};

    let metadata = std::fs::symlink_metadata(path)?;
    AtomicFile::new(path, AllowOverwrite)
        .write(|temporary| {
            // The callback completes before atomicwrites publishes with
            // MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH). Recheck the
            // source after the temporary write to close the same race as the
            // Unix implementation.
            temporary.write_all(content)?;
            temporary.set_permissions(metadata.permissions())?;
            temporary.sync_all()?;
            ensure_regular_source_matches(path, expected)
        })
        .map_err(std::io::Error::from)
}

#[cfg(not(windows))]
fn replace_file(path: &std::path::Path, expected: &[u8], content: &[u8]) -> std::io::Result<()> {
    replace_file_by_rename(path, expected, content)
}

#[cfg(not(windows))]
fn replace_file_by_rename(
    path: &std::path::Path,
    expected: &[u8],
    content: &[u8],
) -> std::io::Result<()> {
    let mut cleanup = prepare_replacement_temp(path, content)?;
    // Keep the expensive temporary-file write outside the final
    // compare/rename window. This recheck also rejects a late symlink swap.
    ensure_regular_source_matches(path, expected)?;
    std::fs::rename(cleanup.path(), path)?;
    cleanup.disarm();
    Ok(())
}

#[cfg(not(windows))]
fn prepare_replacement_temp(
    path: &std::path::Path,
    content: &[u8],
) -> std::io::Result<TempFileCleanup> {
    use std::io::ErrorKind;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    const ATTEMPTS: usize = 100;

    let metadata = std::fs::symlink_metadata(path)?;
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut last_collision = None;
    for _ in 0..ATTEMPTS {
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(".hoonarqube-{}-{nonce}.tmp", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut temp = match options.open(&temp_path) {
            Ok(temp) => temp,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                last_collision = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        let cleanup = TempFileCleanup::new(temp_path);
        temp.write_all(content)?;
        temp.set_permissions(metadata.permissions())?;
        temp.sync_all()?;
        drop(temp);
        return Ok(cleanup);
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            ErrorKind::AlreadyExists,
            "could not allocate a temporary rewrite file",
        )
    }))
}

fn ensure_regular_source_matches(path: &std::path::Path, expected: &[u8]) -> std::io::Result<()> {
    use std::io::ErrorKind;

    if first_symlinked_ancestor(path)?.is_some() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "path has a symlinked directory ancestor",
        ));
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "path is no longer a regular file",
        ));
    }
    if std::fs::read(path)? != expected {
        return Err(std::io::Error::other("file changed after analysis"));
    }
    Ok(())
}

/// Finds the nearest lexically named parent that is currently a symlink.
/// Empty relative-path ancestors are skipped; inspection errors fail closed.
fn first_symlinked_ancestor(path: &std::path::Path) -> std::io::Result<Option<std::path::PathBuf>> {
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if std::fs::symlink_metadata(ancestor)?
            .file_type()
            .is_symlink()
        {
            return Ok(Some(ancestor.to_path_buf()));
        }
    }
    Ok(None)
}

#[cfg(not(windows))]
struct TempFileCleanup {
    path: std::path::PathBuf,
    armed: bool,
}

#[cfg(not(windows))]
impl TempFileCleanup {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(not(windows))]
impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Rejects path replacement between planning and writing. Collection already
/// excludes symlinks in fix mode; this second check closes the ordinary
/// plan/apply gap and prevents writes through a path replaced with a symlink.
fn apply_path_is_regular_file(path: &std::path::Path, warnings: &mut Vec<String>) -> bool {
    match first_symlinked_ancestor(path) {
        Ok(Some(ancestor)) => {
            warnings.push(format!(
                "cannot fix {}: directory {} is a symbolic link",
                path.display(),
                ancestor.display()
            ));
            return false;
        }
        Ok(None) => {}
        Err(error) => {
            warnings.push(format!(
                "cannot inspect ancestors of {}: {error}",
                path.display()
            ));
            return false;
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            warnings.push(format!(
                "cannot fix {}: path is a symbolic link",
                path.display()
            ));
            false
        }
        Ok(metadata) if metadata.is_file() => true,
        Ok(_) => {
            warnings.push(format!(
                "cannot fix {}: path is not a regular file",
                path.display()
            ));
            false
        }
        Err(error) => {
            warnings.push(format!("cannot inspect {}: {error}", path.display()));
            false
        }
    }
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
/// files stay eligible for the final-newline repair only.
fn fix_plans(
    paths: &[std::path::PathBuf],
    rules: &[String],
    options: &analyze::AnalyzerOptionsBundle,
    warnings: &mut Vec<String>,
) -> Vec<FileFixPlan> {
    let files = analyze::collect_input_files(paths, analyze::InputMode::Fix, warnings);

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

#[derive(Default)]
struct DryRunTotals {
    applicable: usize,
    skipped: usize,
    mechanical: usize,
}

struct DryRunPlanResult {
    row: serde_json::Value,
    applicable: usize,
    skipped: usize,
    mechanical: usize,
}

impl DryRunTotals {
    fn record(&mut self, result: &DryRunPlanResult) {
        self.applicable += result.applicable;
        self.skipped += result.skipped;
        self.mechanical += result.mechanical;
    }
}

fn dry_run_plan(
    plan: &FileFixPlan,
    diff: bool,
    json: bool,
    warnings: &mut Vec<String>,
) -> DryRunPlanResult {
    match project_fixes(plan) {
        Ok(projection) => projected_dry_run_plan(plan, &projection, diff, json, warnings),
        Err(error) => {
            warnings.push(format!("cannot fix {}: {error}", plan.path.display()));
            let mut row = file_plan_json(plan);
            insert_json_field(&mut row, "applicable", 0);
            insert_json_field(&mut row, "skipped", plan.fixes.len());
            DryRunPlanResult {
                row,
                applicable: 0,
                skipped: plan.fixes.len(),
                mechanical: 0,
            }
        }
    }
}

fn projected_dry_run_plan(
    plan: &FileFixPlan,
    projection: &FixProjection,
    diff: bool,
    json: bool,
    warnings: &mut Vec<String>,
) -> DryRunPlanResult {
    let applicable = projection.applied_fix_indices.len();
    if projection.skipped > 0 {
        warnings.push(format!(
            "{}: would skip {} conflicting rule fix(es)",
            plan.path.display(),
            projection.skipped
        ));
    }
    let rendered_diff = diff.then(|| unified_diff(&plan.path, &plan.source, &projection.content));
    if !json {
        print_dry_run_plan(plan, projection, rendered_diff.as_deref());
    }
    let mut row = file_plan_json(plan);
    insert_json_field(&mut row, "applicable", applicable);
    insert_json_field(&mut row, "skipped", projection.skipped);
    insert_json_field(&mut row, "mechanical", projection.mechanical);
    if let Some(rendered_diff) = rendered_diff {
        insert_json_string(&mut row, "diff", rendered_diff);
    }
    DryRunPlanResult {
        row,
        applicable,
        skipped: projection.skipped,
        mechanical: projection.mechanical,
    }
}

fn print_dry_run_plan(plan: &FileFixPlan, projection: &FixProjection, diff: Option<&str>) {
    println!(
        "{}: {} applicable rule fix(es), {} mechanical fix(es), {} skipped",
        plan.path.display(),
        projection.applied_fix_indices.len(),
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
    if let Some(diff) = diff {
        print!("{diff}");
    }
}

fn insert_json_field(row: &mut serde_json::Value, key: &str, value: usize) {
    if let Some(object) = row.as_object_mut() {
        object.insert(key.to_string(), serde_json::Value::from(value));
    }
}

fn insert_json_string(row: &mut serde_json::Value, key: &str, value: String) {
    if let Some(object) = row.as_object_mut() {
        object.insert(key.to_string(), serde_json::Value::String(value));
    }
}

/// Dry-run reporting: lists planned rule fixes and final-newline repairs and
/// writes nothing.
fn run_fix_dry_run(
    plans: &[FileFixPlan],
    diff: bool,
    json: bool,
    warnings: &mut Vec<String>,
) -> ExitCode {
    let mut rows = Vec::with_capacity(plans.len());
    let mut totals = DryRunTotals::default();
    for plan in plans {
        let result = dry_run_plan(plan, diff, json, warnings);
        totals.record(&result);
        rows.push(result.row);
    }

    let output_ok = if json {
        print_json(&serde_json::json!({
            "files": rows,
            "planned": plans.iter().map(|plan| plan.fixes.len()).sum::<usize>(),
            "applicable": totals.applicable,
            "skipped": totals.skipped,
            "mechanical": totals.mechanical,
            "applied": 0,
            "verified": 0,
            "unverified": 0,
            "warnings": warnings,
        }))
    } else {
        println!(
            "would apply {} rule fix(es) across {} file(s), \
             {} mechanical fix(es), skip {}; dry run, \
             pass --apply to write",
            totals.applicable,
            plans.len(),
            totals.mechanical,
            totals.skipped
        );
        true
    };
    if output_ok {
        exit_with_warnings(warnings)
    } else {
        ExitCode::FAILURE
    }
}

#[derive(Default)]
struct ApplyTotals {
    applied: usize,
    skipped: usize,
    verified: usize,
    unverified: usize,
    regressions: usize,
    mechanical: usize,
    written_files: usize,
}

struct ApplyPlanResult {
    row: serde_json::Value,
    outcome: Option<ApplyOutcome>,
    rejected: usize,
}

impl ApplyTotals {
    fn record(&mut self, result: &ApplyPlanResult) {
        self.skipped += result.rejected;
        let Some(outcome) = &result.outcome else {
            return;
        };
        self.skipped += outcome.skipped;
        self.verified += outcome.verified;
        self.unverified += outcome.unverified;
        self.regressions += outcome.regressions;
        if outcome.written {
            self.written_files += 1;
            self.applied += outcome.applied;
            self.mechanical += outcome.mechanical;
        }
    }
}

fn apply_one_plan(
    plan: &FileFixPlan,
    options: &analyze::AnalyzerOptionsBundle,
    diff: bool,
    json: bool,
    warnings: &mut Vec<String>,
) -> ApplyPlanResult {
    let Some(outcome) = apply_plan(plan, options, warnings) else {
        let mut row = file_plan_json(plan);
        insert_apply_fields(&mut row, None);
        insert_json_field(&mut row, "skipped", plan.fixes.len());
        return ApplyPlanResult {
            row,
            outcome: None,
            rejected: plan.fixes.len(),
        };
    };
    let rendered_diff =
        (diff && outcome.written).then(|| unified_diff(&plan.path, &plan.source, &outcome.content));
    if !json && outcome.written {
        print_apply_outcome(plan, &outcome, rendered_diff.as_deref());
    }
    let mut row = file_plan_json(plan);
    insert_apply_fields(&mut row, Some(&outcome));
    if let Some(rendered_diff) = rendered_diff {
        insert_json_string(&mut row, "diff", rendered_diff);
    }
    ApplyPlanResult {
        row,
        outcome: Some(outcome),
        rejected: 0,
    }
}

fn insert_apply_fields(row: &mut serde_json::Value, outcome: Option<&ApplyOutcome>) {
    let written = outcome.is_some_and(|outcome| outcome.written);
    let value = |field: fn(&ApplyOutcome) -> usize| {
        outcome.filter(|outcome| outcome.written).map_or(0, field)
    };
    if let Some(object) = row.as_object_mut() {
        object.insert("written".into(), serde_json::Value::Bool(written));
    }
    insert_json_field(row, "applied", value(|outcome| outcome.applied));
    insert_json_field(row, "skipped", outcome.map_or(0, |outcome| outcome.skipped));
    insert_json_field(
        row,
        "verified",
        outcome.map_or(0, |outcome| outcome.verified),
    );
    insert_json_field(
        row,
        "unverified",
        outcome.map_or(0, |outcome| outcome.unverified),
    );
    insert_json_field(
        row,
        "regressions",
        outcome.map_or(0, |outcome| outcome.regressions),
    );
    insert_json_field(row, "mechanical", value(|outcome| outcome.mechanical));
}

fn print_apply_outcome(plan: &FileFixPlan, outcome: &ApplyOutcome, diff: Option<&str>) {
    println!(
        "{}: wrote {} rule fix(es), {} mechanical fix(es), verified {}, unverified {}, skipped {}",
        plan.path.display(),
        outcome.applied,
        outcome.mechanical,
        outcome.verified,
        outcome.unverified,
        outcome.skipped
    );
    if let Some(diff) = diff {
        print!("{diff}");
    }
}

/// Apply mode: verifies each projected rewrite in memory before writing it.
/// Every targeted finding must disappear without increasing any rule's
/// finding count. Warnings fail the run.
fn run_fix_apply(
    plans: &[FileFixPlan],
    options: &analyze::AnalyzerOptionsBundle,
    diff: bool,
    json: bool,
    warnings: &mut Vec<String>,
) -> ExitCode {
    let mut totals = ApplyTotals::default();
    let mut rows = Vec::with_capacity(plans.len());
    for plan in plans {
        let result = apply_one_plan(plan, options, diff, json, warnings);
        totals.record(&result);
        rows.push(result.row);
    }
    for warning in &*warnings {
        eprintln!("{warning}");
    }
    let output_ok = if json {
        print_json(&serde_json::json!({
            "files": rows,
            "applied": totals.applied,
            "skipped": totals.skipped,
            "mechanical": totals.mechanical,
            "verified": totals.verified,
            "unverified": totals.unverified,
            "regressions": totals.regressions,
            "warnings": warnings,
        }))
    } else {
        println!(
            "applied {} rule fix(es) across {} file(s), \
             {} mechanical fix(es), verified {}, unverified {}, skipped {}, \
             regressions {}",
            totals.applied,
            totals.written_files,
            totals.mechanical,
            totals.verified,
            totals.unverified,
            totals.skipped,
            totals.regressions
        );
        true
    };
    if output_ok && warnings.is_empty() && totals.unverified == 0 && totals.regressions == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_rules(catalog: &Catalog, cmd: &RulesCommand, json: bool) -> ExitCode {
    match cmd {
        RulesCommand::List { lang } => run_rules_list(catalog, lang.as_deref(), json),
        RulesCommand::Search { lang, query } => {
            run_rules_search(catalog, lang.as_deref(), query, json)
        }
        RulesCommand::Info { external_key } => run_rules_info(catalog, external_key, json),
    }
}

fn run_rules_list(catalog: &Catalog, lang: Option<&str>, json: bool) -> ExitCode {
    let Some(languages) = select_language(catalog, lang) else {
        return unknown_language(lang.unwrap_or_default());
    };
    let rules: Vec<&RuleRecord> = languages.collect();
    if json {
        if !print_json(&rules) {
            return ExitCode::FAILURE;
        }
    } else {
        for rule in rules {
            print_rule_row(rule);
        }
    }
    ExitCode::SUCCESS
}

fn run_rules_search(catalog: &Catalog, lang: Option<&str>, query: &str, json: bool) -> ExitCode {
    let Some(languages) = select_language(catalog, lang) else {
        return unknown_language(lang.unwrap_or_default());
    };
    let query_lower = query.to_lowercase();
    let matched: Vec<&RuleRecord> = languages
        .filter(|rule| rule_matches(rule, &query_lower))
        .collect();
    if json {
        if !print_json(&matched) {
            return ExitCode::FAILURE;
        }
    } else if matched.is_empty() {
        println!("no matching rules");
    } else {
        for rule in &matched {
            print_rule_row(rule);
        }
    }
    ExitCode::SUCCESS
}

fn run_rules_info(catalog: &Catalog, external_key: &str, json: bool) -> ExitCode {
    let Some(rule) = catalog.rule(external_key) else {
        eprintln!("unknown rule: {external_key}");
        return ExitCode::from(1);
    };
    if json {
        if !print_json(rule) {
            return ExitCode::FAILURE;
        }
    } else {
        print_rule_info(rule);
    }
    ExitCode::SUCCESS
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
        return if print_json(snapshot) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
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

fn json_line<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut serialized = serde_json::to_vec(value)?;
    serialized.push(b'\n');
    Ok(serialized)
}

/// Emits one complete JSON document. Serialization happens before stdout is
/// touched, so unsupported values such as non-UTF-8 paths cannot leave a
/// truncated document or panic the process.
fn print_json<T: serde::Serialize>(value: &T) -> bool {
    let serialized = match json_line(value) {
        Ok(serialized) => serialized,
        Err(error) => {
            eprintln!("cannot serialize JSON output: {error}");
            return false;
        }
    };
    if let Err(error) = std::io::stdout().lock().write_all(&serialized) {
        eprintln!("cannot write JSON output: {error}");
        return false;
    }
    true
}

fn unknown_language(value: &str) -> ExitCode {
    eprintln!("unknown language: {value}");
    ExitCode::from(2)
}

/// Keeps the repository-qualified catalog key as the Generic Issue Import rule
/// id. A single report can contain Python, JS/TS, C#, Go, and Rust; stripping the prefix
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
    go_header_format: &str,
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

    let mut options = analyze::analyzer_options_bundle(catalog);
    options.go.header_format = go_header_format.to_string();
    let mut warnings = Vec::new();
    let reports = analyze::analyze_paths(paths, &options, &mut warnings);
    for warning in &warnings {
        eprintln!("{warning}");
    }

    let output_ok = match format {
        AnalyzeFormat::Json => print_json(&hoonarqube_ir::AnalysisReport { files: reports }),
        AnalyzeFormat::Sonar => print_json(&sonar_import_value(catalog, &reports)),
        AnalyzeFormat::Text => {
            print!("{}", render_text_report(&reports));
            true
        }
    };
    if output_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
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
    fn mechanical_fixing_preserves_crlf_for_the_final_newline() {
        let (fixed, applied) = mechanical_fixed("alpha \r\nbeta\t\r\ngamma  ").expect("repair");

        assert_eq!(applied, 1);
        assert_eq!(fixed, "alpha \r\nbeta\t\r\ngamma  \r\n");
    }

    #[test]
    fn mechanical_fixing_completes_a_dangling_cr_without_duplicating_it() {
        let (fixed, applied) = mechanical_fixed("alpha\r\nbeta\r").expect("repair");

        assert_eq!(applied, 1);
        assert_eq!(fixed, "alpha\r\nbeta\r\n");
    }

    #[test]
    fn mechanical_fixing_leaves_clean_sources_untouched() {
        assert!(mechanical_fixed("x = 1\ny = 2\n").is_none());
    }

    #[test]
    fn mechanical_fixing_never_changes_literal_whitespace() {
        let source = "TEXT = \"\"\"value  \n\tindented\n\"\"\"";
        let (fixed, applied) = mechanical_fixed(source).expect("final newline repair");

        assert_eq!(applied, 1);
        assert_eq!(fixed, format!("{source}\n"));
        assert!(mechanical_fixed("TEXT = \"\"\"value  \n\tindented\n\"\"\"\n").is_none());
    }

    #[test]
    fn fix_plans_report_missing_paths_as_warnings() {
        let missing = temp_fix_path("missing").join("nope.py");
        let options = analyze::analyzer_options_bundle(embedded());
        let mut warnings = Vec::new();

        assert!(fix_plans(std::slice::from_ref(&missing), &[], &options, &mut warnings).is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("path does not exist: "));
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

    #[cfg(unix)]
    #[test]
    fn apply_replaces_a_hard_link_without_mutating_its_alias_and_preserves_mode() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = temp_fix_path("hard-link");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let alias = dir.join("outside.py");
        let file = dir.join("find.py");
        std::fs::write(&alias, "value = 1").expect("write alias");
        std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o751)).expect("set mode");
        std::fs::hard_link(&alias, &file).expect("hard link");
        let options = analyze::analyzer_options_bundle(embedded());
        let mut warnings = Vec::new();
        let plans = fix_plans(std::slice::from_ref(&file), &[], &options, &mut warnings);

        let outcome = apply_plan(&plans[0], &options, &mut warnings).expect("applies");

        assert!(outcome.written);
        assert!(warnings.is_empty());
        assert_eq!(
            std::fs::read_to_string(&file).expect("fixed"),
            "value = 1\n"
        );
        assert_eq!(std::fs::read_to_string(&alias).expect("alias"), "value = 1");
        let fixed_metadata = std::fs::metadata(&file).expect("fixed metadata");
        let alias_metadata = std::fs::metadata(&alias).expect("alias metadata");
        assert_ne!(fixed_metadata.ino(), alias_metadata.ino());
        assert_eq!(fixed_metadata.permissions().mode() & 0o777, 0o751);
        assert_eq!(
            std::fs::read_dir(&dir).expect("read fixture").count(),
            2,
            "temporary rewrite file must be removed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn apply_rejects_file_replaced_with_symlink_after_planning() {
        let (dir, file) = temp_python_fixture("symlink-swap", S1721_SOURCE);
        let outside = temp_fix_path("symlink-target");
        std::fs::write(&outside, S1721_SOURCE).expect("write outside target");
        let options = analyze::analyzer_options_bundle(embedded());
        let mut warnings = Vec::new();
        let plans = fix_plans(std::slice::from_ref(&file), &[], &options, &mut warnings);
        assert!(warnings.is_empty());

        std::fs::remove_file(&file).expect("remove planned file");
        std::os::unix::fs::symlink(&outside, &file).expect("replace with symlink");
        let outcome = apply_plan(&plans[0], &options, &mut warnings);

        assert!(outcome.is_none());
        assert_eq!(
            std::fs::read_to_string(&outside).expect("read target"),
            S1721_SOURCE
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].ends_with("path is a symbolic link"));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn apply_rejects_parent_directory_replaced_with_symlink_after_planning() {
        let root = temp_fix_path("parent-symlink-swap");
        let original_parent = root.join("original");
        let outside_parent = root.join("outside");
        std::fs::create_dir_all(&original_parent).expect("create original parent");
        std::fs::create_dir_all(&outside_parent).expect("create outside parent");
        let file = original_parent.join("find.py");
        let outside = outside_parent.join("find.py");
        std::fs::write(&file, S1721_SOURCE).expect("write planned source");
        std::fs::write(&outside, S1721_SOURCE).expect("write outside target");
        let options = analyze::analyzer_options_bundle(embedded());
        let mut warnings = Vec::new();
        let plans = fix_plans(std::slice::from_ref(&file), &[], &options, &mut warnings);
        assert!(warnings.is_empty());

        std::fs::remove_file(&file).expect("remove planned file");
        std::fs::remove_dir(&original_parent).expect("remove planned parent");
        std::os::unix::fs::symlink(&outside_parent, &original_parent)
            .expect("replace parent with symlink");
        let outcome = apply_plan(&plans[0], &options, &mut warnings);

        assert!(outcome.is_none());
        assert_eq!(
            std::fs::read_to_string(&outside).expect("read outside"),
            S1721_SOURCE
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("is a symbolic link"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_rechecks_content_after_verification() {
        let (dir, file) = temp_python_fixture("late-content-change", S1721_SOURCE);
        let foreign = "def foreign():\n    return 99\n";
        let plan = FileFixPlan {
            path: file.clone(),
            source: S1721_SOURCE.to_string(),
            fixes: Vec::new(),
            mechanical: 0,
        };
        let mut outcome = ApplyOutcome {
            written: false,
            applied: 0,
            skipped: 0,
            mechanical: 0,
            verified: 0,
            unverified: 0,
            regressions: 0,
            content: "def f():\n    return 1\n".to_string(),
        };
        std::fs::write(&file, foreign).expect("external edit");
        let mut warnings = Vec::new();

        assert!(!write_applied_content(&plan, &mut outcome, &mut warnings));
        assert!(!outcome.written);
        assert!(warnings[0].ends_with("file changed after analysis"));
        assert_eq!(std::fs::read_to_string(&file).expect("read back"), foreign);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_rejects_a_fix_that_does_not_resolve_its_finding() {
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

        assert!(!outcome.written);
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.verified, 0);
        assert_eq!(outcome.unverified, 1);
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            std::fs::read_to_string(&file).expect("read back"),
            S1721_SOURCE,
            "failed verification must leave the source untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_rejects_broken_fix_masked_by_an_overeffective_same_rule_fix() {
        const SOURCE: &str = "def f():\n    return(1)\ndef g():\n    return(2)\n";
        let (dir, file) = temp_python_fixture("masked-broken-fix", SOURCE);
        let options = analyze::analyzer_options_bundle(embedded());
        let plan = FileFixPlan {
            path: file.clone(),
            source: SOURCE.to_string(),
            fixes: vec![
                PlannedFix {
                    rule_key: "python:S1721".to_string(),
                    message: "broken no-op".to_string(),
                    range: Range {
                        start: Pos { line: 2, column: 4 },
                        end: Pos {
                            line: 2,
                            column: 13,
                        },
                    },
                    edits: vec![cli_edit((5, 0), (5, 0), " ")],
                },
                PlannedFix {
                    rule_key: "python:S1721".to_string(),
                    message: "overeffective".to_string(),
                    range: Range {
                        start: Pos { line: 4, column: 4 },
                        end: Pos {
                            line: 4,
                            column: 13,
                        },
                    },
                    edits: vec![
                        cli_edit((2, 10), (2, 11), " "),
                        cli_edit((2, 12), (2, 13), ""),
                        cli_edit((4, 10), (4, 11), " "),
                        cli_edit((4, 12), (4, 13), ""),
                    ],
                },
            ],
            mechanical: 0,
        };
        let mut warnings = Vec::new();

        let outcome = apply_plan(&plan, &options, &mut warnings).expect("evaluated");

        assert!(!outcome.written);
        assert_eq!(outcome.verified, 1);
        assert_eq!(outcome.unverified, 1);
        assert!(warnings[0].contains("do not independently remove"));
        assert_eq!(std::fs::read_to_string(&file).expect("read back"), SOURCE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_only_adds_the_final_newline_to_literal_heavy_source() {
        let source = "TEXT = \"\"\"value  \n\tindented\n\"\"\"";
        let expected = format!("{source}\n");
        let (dir, file) = temp_python_fixture("mechanical-literal", source);
        let options = analyze::analyzer_options_bundle(embedded());
        let mut warnings = Vec::new();
        let plans = fix_plans(std::slice::from_ref(&file), &[], &options, &mut warnings);
        assert!(warnings.is_empty());
        assert_eq!(plans.len(), 1);
        assert!(plans[0].fixes.is_empty());
        assert_eq!(plans[0].mechanical, 1);

        let outcome = apply_plan(&plans[0], &options, &mut warnings).expect("evaluated");

        assert!(outcome.written);
        assert_eq!(outcome.mechanical, 1);
        assert_eq!(outcome.regressions, 0);
        assert!(warnings.is_empty());
        assert_eq!(std::fs::read_to_string(&file).expect("read back"), expected);
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

    #[cfg(unix)]
    #[test]
    fn json_serialization_rejects_non_utf8_paths_without_partial_output() {
        use std::os::unix::ffi::OsStringExt as _;

        let report = hoonarqube_ir::AnalysisReport {
            files: vec![FileReport {
                path: std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![
                    0xff, b'.', b'p', b'y',
                ])),
                language: "python".to_string(),
                issues: Vec::new(),
                metrics: FileMetrics {
                    lines: 0,
                    code_lines: 0,
                    comment_lines: 0,
                },
            }],
        };

        let error = json_line(&report).expect_err("invalid path must fail serialization");
        assert!(error.to_string().contains("invalid UTF-8"));
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
