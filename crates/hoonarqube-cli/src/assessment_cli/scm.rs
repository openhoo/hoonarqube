//! Date-based Community branch periods. All Git reads are pinned to immutable
//! objects; neither the staged index nor a changed worktree supplies blame.
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use hoonarqube_core::assessment::compare_reports;
use hoonarqube_ir::assessment::{
    AssessmentReport, AssessmentStatus, FindingMatch, FindingStatus, NewCodeLines, NewCodeReport,
    SourceSnapshot, SpecificAnalysis, normalize_path,
};
use hoonarqube_ir::{AnalysisReport, FileReport, Issue, Range};

use super::{MAX_ASSESSMENT_INPUT_BYTES, load_reference_report, read_bounded_text};

pub(super) fn classify(
    descriptor: &Path,
    baseline: &Path,
    assessment: &AssessmentReport,
    report: &AnalysisReport,
) -> Result<NewCodeReport, String> {
    let period = load_period(descriptor)?;
    let reference = load_reference_report(baseline)?;
    if !reference.project.complete {
        return Err("SCM period baseline analysis is incomplete".into());
    }
    let base = reference
        .assessment
        .as_ref()
        .ok_or("SCM period baseline assessment missing")?;
    if base.context.source_revision.as_ref() != Some(&period.revision)
        || !base.context.compatible_with(&assessment.context)
    {
        return Err("SCM period does not match the baseline revision or analysis context".into());
    }
    let head = assessment
        .context
        .source_revision
        .as_deref()
        .ok_or("SCM candidate revision missing")?;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = PathBuf::from(git_text(&cwd, &["rev-parse", "--show-toplevel"])?);
    if git_text(&root, &["rev-parse", "--is-shallow-repository"])? != "false" {
        return Err("SCM period requires full Git history; this repository is shallow".into());
    }
    git(
        &root,
        &["merge-base", "--is-ancestor", &period.revision, head],
        0,
    )?;
    if base.sources.len().max(assessment.sources.len()) > 16_384 {
        return Err("SCM source inventory exceeds the file limit".into());
    }
    verify_base(&root, &cwd, &period, base)?;
    let files: BTreeMap<_, _> = report
        .files
        .iter()
        .map(|f| Ok((normalize_path(&f.path).map_err(|e| e.to_string())?, f)))
        .collect::<Result<_, String>>()?;
    let mut comparison = compare_reports(assessment, Some(base));
    let mut findings = comparison.findings.iter_mut();
    let mut membership = Vec::new();
    let mut total = 0usize;
    for source in &assessment.sources {
        let (path, bytes) = verified_blob(&root, &cwd, head, source)?;
        let dates = blame(&root, head, &path, &bytes, source.line_digests.len())?;
        let lines = dated_lines(&dates, period.timestamp_ms);
        total = total
            .checked_add(lines.len())
            .filter(|n| *n <= 4_000_000)
            .ok_or("SCM period exceeds the changed line limit")?;
        classify_findings(
            source,
            files.get(&source.path).copied(),
            &mut findings,
            &lines,
            dates.len(),
        )?;
        if !lines.is_empty() {
            membership.push(NewCodeLines {
                path: source.path.clone(),
                lines,
            });
        }
    }
    if findings.next().is_some() {
        return Err("SCM finding inventory mismatch".into());
    }
    comparison.diagnostics.clear();
    comparison.status = if comparison
        .findings
        .iter()
        .any(|f| f.status == FindingStatus::Uncertain)
    {
        comparison
            .diagnostics
            .push("one or more SCM-period finding identities or dates are uncertain".into());
        AssessmentStatus::Incomplete
    } else {
        AssessmentStatus::Complete
    };
    comparison.lines.clone_from(&membership);
    comparison.changed_source_lines = Some(membership);
    comparison.specific_analysis = Some(period);
    Ok(comparison)
}

fn classify_findings(
    source: &SourceSnapshot,
    file: Option<&FileReport>,
    findings: &mut std::slice::IterMut<'_, FindingMatch>,
    lines: &[u32],
    line_count: usize,
) -> Result<(), String> {
    for finding in &source.findings {
        let matched = findings
            .next()
            .filter(|m| {
                m.path == source.path
                    && m.issue_index == finding.issue_index
                    && m.identity == finding.identity
            })
            .ok_or("SCM period has an incomplete baseline finding inventory")?;
        let issue = file
            .and_then(|f| f.issues.get(finding.issue_index))
            .ok_or("SCM finding has no matching native issue")?;
        if matched.status != FindingStatus::Existing {
            match touches_period(issue, &source.path, lines, line_count) {
                Some(false) => matched.status = FindingStatus::Existing,
                None => matched.status = FindingStatus::Uncertain,
                Some(true) => (),
            }
        }
    }
    Ok(())
}

fn verify_base(
    root: &Path,
    cwd: &Path,
    period: &SpecificAnalysis,
    base: &AssessmentReport,
) -> Result<(), String> {
    for source in &base.sources {
        let (path, bytes) = verified_blob(root, cwd, &period.revision, source)?;
        // Matched findings normally predate this analysis. A future-dated
        // baseline can violate that assumption; their original creation dates
        // are not in a native snapshot.
        if !source.findings.is_empty()
            && blame(
                root,
                &period.revision,
                &path,
                &bytes,
                source.line_digests.len(),
            )?
            .iter()
            .any(|&date| date > period.timestamp_ms / 1000)
        {
            return Err(format!(
                "SCM changes after selected analysis in baseline file {path}; finding history unavailable"
            ));
        }
    }
    Ok(())
}

fn load_period(descriptor: &Path) -> Result<SpecificAnalysis, String> {
    let period: SpecificAnalysis =
        serde_json::from_str(&read_bounded_text(descriptor, "SCM period")?)
            .map_err(|e| format!("invalid specific-analysis descriptor: {e}"))?;
    if !period.is_valid() {
        return Err("invalid specific-analysis ID, timestamp or full revision".into());
    }
    Ok(period)
}

fn verified_blob(
    root: &Path,
    cwd: &Path,
    revision: &str,
    source: &SourceSnapshot,
) -> Result<(String, Vec<u8>), String> {
    let absolute = cwd.join(&source.path);
    let path = absolute
        .strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .ok_or("SCM source outside repository")?;
    let path = path.replace(std::path::MAIN_SEPARATOR, "/");
    let tree = git(root, &["ls-tree", "-z", revision, "--", &path], 16 * 1024)?;
    let (entry, actual) = tree
        .strip_suffix(&[0])
        .and_then(|s| {
            s.iter()
                .position(|b| *b == b'\t')
                .map(|i| (&s[..i], &s[i + 1..]))
        })
        .ok_or_else(|| format!("source is not tracked at {revision}: {path}"))?;
    if actual != path.as_bytes() {
        return Err(format!("SCM tree path differs: {path}"));
    }
    let meta = std::str::from_utf8(entry).map_err(|e| e.to_string())?;
    let mut fields = meta.split(' ');
    if !matches!(fields.next(), Some("100644" | "100755")) || fields.next() != Some("blob") {
        return Err(format!("SCM source is not a regular Git blob: {path}"));
    }
    let oid = fields.next().ok_or("missing blob ID")?;
    let bytes = git(root, &["cat-file", "blob", oid], MAX_ASSESSMENT_INPUT_BYTES)?;
    if !source.matches_content(&bytes) {
        return Err(format!(
            "analyzed bytes differ from Git at {revision}: {path}"
        ));
    }
    Ok((path, bytes))
}

fn blame(
    root: &Path,
    revision: &str,
    path: &str,
    bytes: &[u8],
    physical: usize,
) -> Result<Vec<i64>, String> {
    let count = bytes.split_inclusive(|b| *b == b'\n').count();
    if count != physical || count > 4_000_000 {
        return Err(format!("unsupported SCM source line mapping: {path}"));
    }
    let raw = git(
        root,
        &[
            "blame",
            "--no-textconv",
            "--line-porcelain",
            "-w",
            revision,
            "--",
            path,
        ],
        MAX_ASSESSMENT_INPUT_BYTES,
    )?;
    let mut dates = Vec::with_capacity(count);
    let mut date = None;
    for line in raw.split(|b| *b == b'\n') {
        if let Some(s) = line.strip_prefix(b"committer-time ") {
            date = Some(
                std::str::from_utf8(s)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                    .ok_or("invalid Git committer date")?,
            );
        } else if line.starts_with(b"\t") {
            dates.push(
                date.take()
                    .ok_or("Git attribution missing a committer date")?,
            );
        }
    }
    if dates.len() != count {
        return Err(format!("incomplete SCM blame for {path}"));
    }
    if bytes.ends_with(b"\n")
        && let Some(&last) = dates.last()
    {
        dates.push(last);
    }
    Ok(dates)
}

fn dated_lines(dates: &[i64], millis: i64) -> Vec<u32> {
    dates
        .iter()
        .enumerate()
        .filter(|(_, date)| **date > millis / 1000)
        .map(|(i, _)| u32::try_from(i + 1).expect("bounded SCM line count"))
        .collect()
}

fn touches_period(issue: &Issue, path: &Path, new_lines: &[u32], count: usize) -> Option<bool> {
    if count == 0 {
        return None;
    }
    let mut located = false;
    let mut in_period = |range: &Range| {
        let start = range.start.line.max(1);
        if range.is_file_level() || start as usize > count {
            return false;
        }
        located = true;
        let i = new_lines.partition_point(|n| *n < start);
        new_lines.get(i).is_some_and(|line| *line <= range.end.line)
    };
    if in_period(&issue.range)
        || issue
            .flows
            .iter()
            .flat_map(|flow| &flow.locations)
            .filter(|loc| {
                loc.path
                    .as_ref()
                    .is_none_or(|p| normalize_path(p).ok().as_deref() == Some(path))
            })
            .any(|loc| in_period(&loc.range))
    {
        return Some(true);
    }
    Some(!located && !new_lines.is_empty())
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    let bytes = git(root, args, 16 * 1024)?;
    String::from_utf8(bytes)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|e| e.to_string())
}

fn git(root: &Path, args: &[&str], limit: u64) -> Result<Vec<u8>, String> {
    let operation = args[0];
    let mut child = Command::new("git")
        .current_dir(root)
        .args([
            "--no-replace-objects",
            "--literal-pathspecs",
            "-c",
            "blame.ignoreRevsFile=",
            "-c",
            "core.fsmonitor=false",
        ])
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run Git {operation}: {e}"))?;
    let mut data = Vec::new();
    let read = child
        .stdout
        .take()
        .expect("piped")
        .take(limit + 1)
        .read_to_end(&mut data);
    if read.is_err() || data.len() as u64 > limit {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "Git {operation} output unavailable or exceeds size limit"
        ));
    }
    if !child.wait().map_err(|e| e.to_string())?.success() {
        return Err(format!(
            "Git {operation} failed; cannot verify local SCM history"
        ));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::touches_period;
    use hoonarqube_ir::{FlowLocation, Issue, Pos, Range};
    use std::path::{Path, PathBuf};

    #[test]
    fn issue_period_uses_primary_and_same_file_flow_lines_then_file_fallback() {
        let range = |line| Range {
            start: Pos { line, column: 0 },
            end: Pos { line, column: 1 },
        };
        let file = Path::new("src.js");
        let mut issue = Issue::new("test:S1", "example", range(2));
        issue = issue.with_flow(vec![FlowLocation {
            path: Some(PathBuf::from("other.js")),
            message: "other".into(),
            range: range(7),
        }]);
        assert_eq!(touches_period(&issue, file, &[7], 8), Some(false));
        issue = issue.with_flow(vec![FlowLocation::in_primary_file("same file", range(7))]);
        assert_eq!(touches_period(&issue, file, &[7], 8), Some(true));
        assert_eq!(touches_period(&issue, file, &[2], 8), Some(true));
        let file_level = Issue::new("test:S1", "file", Range::file_level());
        assert_eq!(touches_period(&file_level, file, &[4], 8), Some(true));
        assert_eq!(touches_period(&file_level, file, &[], 8), Some(false));
        assert_eq!(touches_period(&file_level, file, &[], 0), None);
    }
}
