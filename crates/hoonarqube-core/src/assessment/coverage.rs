//! Deterministic `LCOV` and `OpenCover` coverage import.
//!
//! Coverage is deliberately joined to the exact source snapshots supplied by
//! the caller.  The importer never opens source files and never infers a
//! missing line from a report.  A report line is eligible only once it has a
//! valid, unambiguous source-path and an in-range source line number.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use hoonarqube_ir::FileClassification;
use hoonarqube_ir::assessment::{
    AssessmentStatus, CoverageCounter, CoverageInput, CoverageReport, FileCoverage, LineCoverage,
};
use md5::{Digest as Md5Digest, Md5};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use sha2::{Digest as ShaDigest, Sha256};
const COVERAGE_SCHEMA_VERSION: u32 = 1;
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_XML_DEPTH: usize = 256;
const MAX_XML_TEXT: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 1_000_000;
const MAX_MEASUREMENTS: usize = 4_000_000;

/// A supported coverage format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoverageFormat {
    /// The line-oriented `LCOV` format used by JavaScript/TypeScript tooling.
    Lcov,
    /// The XML `OpenCover` format used by .NET tooling.
    OpenCover,
}

impl CoverageFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lcov => "lcov",
            Self::OpenCover => "opencover",
        }
    }
}

/// One coverage artifact.  `content` is the exact text captured by the
/// caller; the importer does not re-read its path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageSource {
    pub path: PathBuf,
    pub format: CoverageFormat,
    pub content: String,
}

/// One exact source snapshot from the same analysis run as the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageFile<'a> {
    pub path: &'a Path,
    pub source: &'a str,
    pub classification: FileClassification,
}

/// Import all supplied coverage artifacts against the supplied source
/// inventory.
///
/// `root` is the canonical checkout root selected by the caller.  Every
/// source and report path is normalized lexically against that root; no
/// filesystem access is performed.  Source paths outside the root, report
/// paths outside the root, unknown paths, and ambiguous normalized paths are
/// diagnostics and make the result invalid.  Duplicate line and branch
/// records are merged by identity, so repeated test runs cannot inflate
/// denominators.
#[must_use]
pub fn import_coverage(
    root: &Path,
    inputs: &[CoverageSource],
    sources: &[CoverageFile<'_>],
) -> CoverageReport {
    let mut diagnostics = Vec::new();
    let source_index = SourceIndex::new(root, sources, &mut diagnostics);
    let mut aggregate = CoverageAggregate::default();
    let mut saw_record = false;
    let mut invalid = !source_index.valid;
    let mut incomplete = false;
    let mut report_inputs = Vec::with_capacity(inputs.len());

    for (input_index, input) in inputs.iter().enumerate() {
        report_inputs.push(CoverageInput {
            path: input_path(root, &input.path),
            format: input.format.as_str().to_string(),
            content_digest: sha256_hex(input.content.as_bytes()),
        });
        let flags = import_coverage_input(
            input,
            input_index,
            &source_index,
            &mut aggregate,
            &mut diagnostics,
        );
        invalid |= flags.invalid;
        incomplete |= flags.incomplete;
        saw_record |= flags.saw_record;
    }

    sort_dedup(&mut diagnostics);
    report_inputs.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.format.cmp(&right.format))
            .then_with(|| left.content_digest.cmp(&right.content_digest))
    });
    let files = aggregate.files();
    let lines = aggregate.line_counter();
    let branches = aggregate.branch_counter();
    let status = if inputs.is_empty() {
        AssessmentStatus::Missing
    } else if invalid {
        AssessmentStatus::Invalid
    } else if incomplete || !saw_record {
        AssessmentStatus::Incomplete
    } else {
        AssessmentStatus::Complete
    };

    CoverageReport {
        schema_version: COVERAGE_SCHEMA_VERSION,
        status,
        files,
        inputs: report_inputs,
        lines,
        branches,
        diagnostics,
    }
}

#[derive(Debug, Default)]
struct CoverageImportFlags {
    invalid: bool,
    incomplete: bool,
    saw_record: bool,
}

fn import_coverage_input(
    input: &CoverageSource,
    input_index: usize,
    source_index: &SourceIndex<'_>,
    aggregate: &mut CoverageAggregate,
    diagnostics: &mut Vec<String>,
) -> CoverageImportFlags {
    if input.path.as_os_str().is_empty() {
        diagnostics.push("coverage input path must not be empty".to_owned());
        return CoverageImportFlags {
            invalid: true,
            ..CoverageImportFlags::default()
        };
    }
    if input.content.len() > MAX_INPUT_BYTES {
        diagnostics.push(format!(
            "coverage input '{}' exceeds the bounded importer limit",
            input.path.display()
        ));
        return CoverageImportFlags {
            invalid: true,
            ..CoverageImportFlags::default()
        };
    }
    let parsed = match input.format {
        CoverageFormat::Lcov => parse_lcov(&input.content, diagnostics),
        CoverageFormat::OpenCover => parse_opencover(&input.content, diagnostics),
    };
    let measurement_count = coverage_measurement_count(&parsed);
    if parsed.records.len() > MAX_RECORDS || measurement_count > MAX_MEASUREMENTS {
        diagnostics.push(format!(
            "coverage input '{}' exceeds the bounded record or measurement limit",
            input.path.display()
        ));
        return CoverageImportFlags {
            invalid: true,
            ..CoverageImportFlags::default()
        };
    }

    let mut flags = CoverageImportFlags {
        invalid: parsed.invalid,
        incomplete: parsed.incomplete,
        saw_record: parsed.saw_record,
    };
    for record in parsed.records {
        let Some(path) = source_index.resolve(&record.path, diagnostics) else {
            flags.invalid = true;
            continue;
        };
        let Some(source) = source_index.entries.get(path) else {
            flags.invalid = true;
            continue;
        };
        if source.classification != FileClassification::Source {
            diagnostics.push(format!(
                "coverage path '{}' is outside the source scope ({})",
                path,
                classification_name(source.classification)
            ));
            continue;
        }
        let record_flags =
            import_coverage_record(record, path, source, input_index, aggregate, diagnostics);
        flags.invalid |= record_flags.invalid;
        flags.saw_record |= record_flags.saw_record;
    }
    flags
}

fn coverage_measurement_count(parsed: &ParsedCoverage) -> usize {
    parsed.records.iter().fold(0_usize, |total, record| {
        total.saturating_add(record.lines.len().saturating_add(record.branches.len()))
    })
}

fn import_coverage_record(
    record: ParsedFile,
    path: &str,
    source: &SourceEntry<'_>,
    input_index: usize,
    aggregate: &mut CoverageAggregate,
    diagnostics: &mut Vec<String>,
) -> CoverageImportFlags {
    let mut flags = CoverageImportFlags::default();
    if record
        .file_hash
        .as_deref()
        .is_some_and(|file_hash| !verify_file_hash(file_hash, source.digest.as_str()))
    {
        flags.invalid = true;
        diagnostics.push(format!("coverage source hash mismatch for '{path}'"));
    }
    for line in &record.lines {
        let result = import_coverage_line(line, path, source, input_index, aggregate, diagnostics);
        flags.invalid |= result.invalid;
        flags.saw_record |= result.saw_record;
    }
    for branch in record.branches {
        let result =
            import_coverage_branch(branch, path, source, input_index, aggregate, diagnostics);
        flags.invalid |= result.invalid;
        flags.saw_record |= result.saw_record;
    }
    flags
}

#[derive(Debug, Default)]
struct CoverageMeasurementFlags {
    invalid: bool,
    saw_record: bool,
}

fn import_coverage_line(
    line: &ParsedLine,
    path: &str,
    source: &SourceEntry<'_>,
    input_index: usize,
    aggregate: &mut CoverageAggregate,
    diagnostics: &mut Vec<String>,
) -> CoverageMeasurementFlags {
    if !source_contains_line(source, line.line) {
        diagnostics.push(format!(
            "coverage line {} for '{}' does not exist in the analyzed source",
            line.line, path
        ));
        return CoverageMeasurementFlags {
            invalid: true,
            ..CoverageMeasurementFlags::default()
        };
    }
    let mut invalid = false;
    if let Some(reported_checksum) = line.checksum.as_deref() {
        let checksum_matches = source_line_checksum(source.source, line.line)
            .is_some_and(|expected| expected == reported_checksum);
        if !checksum_matches {
            invalid = true;
            diagnostics.push(format!(
                "LCOV checksum mismatch for line {} of '{}'",
                line.line, path
            ));
        }
    }
    aggregate.add_line(path, line.line, line.covered, input_index, diagnostics);
    CoverageMeasurementFlags {
        invalid,
        saw_record: true,
    }
}

fn import_coverage_branch(
    branch: ParsedBranch,
    path: &str,
    source: &SourceEntry<'_>,
    input_index: usize,
    aggregate: &mut CoverageAggregate,
    diagnostics: &mut Vec<String>,
) -> CoverageMeasurementFlags {
    if !source_contains_line(source, branch.line) {
        diagnostics.push(format!(
            "coverage branch line {} for '{}' does not exist in the analyzed source",
            branch.line, path
        ));
        return CoverageMeasurementFlags {
            invalid: true,
            ..CoverageMeasurementFlags::default()
        };
    }
    aggregate.add_branch(
        path,
        branch.line,
        branch.identity,
        branch.covered,
        input_index,
        diagnostics,
    );
    CoverageMeasurementFlags {
        invalid: false,
        saw_record: true,
    }
}

fn source_contains_line(source: &SourceEntry<'_>, line: u32) -> bool {
    line != 0 && usize::try_from(line).is_ok_and(|number| number <= source.line_count)
}
#[derive(Debug)]
struct SourceEntry<'a> {
    path: String,
    source: &'a str,
    classification: FileClassification,
    line_count: usize,
    digest: String,
}

#[derive(Debug)]
struct SourceIndex<'a> {
    root: String,
    root_windows: bool,
    entries: BTreeMap<String, SourceEntry<'a>>,
    folded: BTreeMap<String, BTreeSet<String>>,
    valid: bool,
}

impl<'a> SourceIndex<'a> {
    fn new(root: &Path, sources: &[CoverageFile<'a>], diagnostics: &mut Vec<String>) -> Self {
        let root_text = lexical_path(root);
        let root_windows = is_windows_absolute(&root_text);
        let mut index = Self {
            root: root_text,
            root_windows,
            entries: BTreeMap::new(),
            folded: BTreeMap::new(),
            valid: true,
        };
        for source in sources {
            let Some(path) = normalize_source_path(&index.root, index.root_windows, source.path)
            else {
                index.valid = false;
                diagnostics.push(format!(
                    "source path '{}' is outside the explicit coverage root",
                    source.path.display()
                ));
                continue;
            };
            let entry = SourceEntry {
                path: path.clone(),
                source: source.source,
                classification: source.classification,
                line_count: source_line_count(source.source),
                digest: sha256_hex(source.source.as_bytes()),
            };
            if index.entries.contains_key(&path) {
                index.valid = false;
                diagnostics.push(format!("ambiguous analyzed source path '{path}'"));
                continue;
            }
            index
                .folded
                .entry(path_key(&path))
                .or_default()
                .insert(path.clone());
            index.entries.insert(path, entry);
        }
        index
    }

    fn resolve(&self, reported: &str, diagnostics: &mut Vec<String>) -> Option<&str> {
        let reported_path = PathBuf::from(reported);
        let normalized = normalize_report_path(&self.root, self.root_windows, &reported_path);
        let Some(path) = normalized else {
            diagnostics.push(format!(
                "coverage path '{reported}' is outside the explicit coverage root"
            ));
            return None;
        };
        if !self.root_windows {
            if let Some(entry) = self.entries.get(&path) {
                return Some(entry.path.as_str());
            }
            diagnostics.push(format!("unknown analyzed source path '{path}'"));
            return None;
        }
        let key = path_key(&path);
        let Some(candidates) = self.folded.get(&key) else {
            diagnostics.push(format!("unknown analyzed source path '{path}'"));
            return None;
        };
        if candidates.len() != 1 {
            diagnostics.push(format!("ambiguous analyzed source path '{path}'"));
            return None;
        }
        let only = candidates.iter().next().expect("non-empty candidates");
        if path != *only {
            diagnostics.push(format!(
                "coverage path '{path}' matched analyzed source '{only}' case-insensitively"
            ));
        }
        self.entries.get(only).map(|entry| entry.path.as_str())
    }
}

#[derive(Debug, Default)]
struct CoverageAggregate {
    files: BTreeMap<String, FileAggregate>,
}

#[derive(Debug, Default)]
struct FileAggregate {
    lines: BTreeMap<u32, LineAggregate>,
}

#[derive(Debug, Default)]
struct LineAggregate {
    line_seen: bool,
    covered: bool,
    run_values: BTreeMap<usize, bool>,
    branches: BTreeMap<String, BranchAggregate>,
}

#[derive(Debug, Default)]
struct BranchAggregate {
    covered: bool,
    run_values: BTreeMap<usize, bool>,
}
impl CoverageAggregate {
    fn add_line(
        &mut self,
        path: &str,
        line: u32,
        covered: bool,
        run: usize,
        diagnostics: &mut Vec<String>,
    ) {
        let line_entry = self
            .files
            .entry(path.to_owned())
            .or_default()
            .lines
            .entry(line)
            .or_default();
        let contradiction = line_entry
            .run_values
            .values()
            .any(|previous| *previous != covered);
        line_entry.run_values.insert(run, covered);
        if contradiction {
            diagnostics.push(format!(
                "coverage line {line} for '{path}' has contradictory run values; unioning coverage"
            ));
        }
        line_entry.line_seen = true;
        line_entry.covered |= covered;
    }

    fn add_branch(
        &mut self,
        path: &str,
        line: u32,
        identity: String,
        covered: bool,
        run: usize,
        diagnostics: &mut Vec<String>,
    ) {
        let line_entry = self
            .files
            .entry(path.to_owned())
            .or_default()
            .lines
            .entry(line)
            .or_default();
        let contradiction = line_entry.branches.get(&identity).is_some_and(|branch| {
            branch
                .run_values
                .values()
                .any(|previous| *previous != covered)
        });
        if contradiction {
            diagnostics.push(format!(
                "coverage branch '{identity}' at line {line} for '{path}' has contradictory run values; unioning coverage"
            ));
        }
        let branch = line_entry.branches.entry(identity).or_default();
        branch.run_values.insert(run, covered);
        branch.covered |= covered;
    }

    fn line_counter(&self) -> CoverageCounter {
        let eligible = self
            .files
            .values()
            .flat_map(|file| file.lines.values())
            .filter(|line| line.line_seen)
            .count();
        let covered = self
            .files
            .values()
            .flat_map(|file| file.lines.values())
            .filter(|line| line.line_seen && line.covered)
            .count();
        CoverageCounter {
            eligible: eligible as u64,
            covered: covered as u64,
        }
    }

    fn branch_counter(&self) -> CoverageCounter {
        let branches = self
            .files
            .values()
            .flat_map(|file| file.lines.values())
            .flat_map(|line| line.branches.values());
        let mut eligible = 0_u64;
        let mut covered = 0_u64;
        for branch in branches {
            eligible += 1;
            if branch.covered {
                covered += 1;
            }
        }
        CoverageCounter { eligible, covered }
    }

    fn files(&self) -> Vec<FileCoverage> {
        self.files
            .iter()
            .filter_map(|(path, file)| {
                let lines = file
                    .lines
                    .iter()
                    .filter(|(_, line)| line.line_seen || !line.branches.is_empty())
                    .map(|(line_number, line)| LineCoverage {
                        line: *line_number,
                        covered: line.line_seen.then_some(line.covered),
                        branches: if line.branches.is_empty() {
                            None
                        } else {
                            let eligible = line.branches.len() as u64;
                            let covered = line
                                .branches
                                .values()
                                .filter(|branch| branch.covered)
                                .count() as u64;
                            Some(CoverageCounter { eligible, covered })
                        },
                    })
                    .collect::<Vec<_>>();
                if lines.is_empty() {
                    None
                } else {
                    Some(FileCoverage {
                        path: PathBuf::from(path),
                        lines,
                    })
                }
            })
            .collect()
    }
}

#[derive(Debug, Default)]
struct ParsedCoverage {
    records: Vec<ParsedFile>,
    invalid: bool,
    incomplete: bool,
    saw_record: bool,
}

#[derive(Debug, Default)]
struct ParsedFile {
    path: String,
    lines: Vec<ParsedLine>,
    branches: Vec<ParsedBranch>,
    file_hash: Option<String>,
}

#[derive(Debug)]
struct ParsedLine {
    line: u32,
    covered: bool,
    checksum: Option<String>,
}

#[derive(Debug)]
struct ParsedBranch {
    line: u32,
    identity: String,
    covered: bool,
}

fn parse_lcov(content: &str, diagnostics: &mut Vec<String>) -> ParsedCoverage {
    LcovParser::new(diagnostics).parse(content)
}

struct LcovParser<'a> {
    parsed: ParsedCoverage,
    current: Option<ParsedFile>,
    saw_end: bool,
    line_summary: Option<(u64, u64)>,
    branch_summary: Option<(u64, u64)>,
    diagnostics: &'a mut Vec<String>,
}

impl<'a> LcovParser<'a> {
    fn new(diagnostics: &'a mut Vec<String>) -> Self {
        Self {
            parsed: ParsedCoverage::default(),
            current: None,
            saw_end: false,
            line_summary: None,
            branch_summary: None,
            diagnostics,
        }
    }

    fn parse(mut self, content: &str) -> ParsedCoverage {
        for (line_index, raw_line) in content.lines().enumerate() {
            let text = raw_line.strip_suffix('\r').unwrap_or(raw_line).trim();
            if text.is_empty() {
                continue;
            }
            self.parse_line(text, line_index);
        }
        self.finish(content);
        self.parsed
    }

    fn parse_line(&mut self, text: &str, line_index: usize) {
        if text == "end_of_record" {
            self.end_record(line_index);
            return;
        }
        let Some((tag, value)) = text.split_once(':') else {
            self.parsed.invalid = true;
            self.diagnostics
                .push(format!("malformed LCOV line {}", line_index + 1));
            return;
        };
        match tag {
            "TN" => {}
            "SF" => self.start_file(value, line_index),
            "DA" => self.parse_line_measurement(value, line_index),
            "BRDA" => self.parse_branch_measurement(value, line_index),
            "LF" | "LH" => self.parse_line_summary(tag, value, line_index),
            "BRF" | "BRH" => self.parse_branch_summary(tag, value, line_index),
            "FN" => self.parse_function(value, line_index),
            "FNDA" => self.parse_function_data(value, line_index),
            "FNF" | "FNH" => self.parse_function_summary(tag, value, line_index),
            _ => {
                self.parsed.invalid = true;
                self.diagnostics.push(format!(
                    "unsupported LCOV record tag '{tag}' at line {}",
                    line_index + 1
                ));
            }
        }
    }

    fn start_file(&mut self, value: &str, line_index: usize) {
        if self.current.is_some() {
            self.parsed.incomplete = true;
            self.diagnostics.push(format!(
                "truncated LCOV record before line {} (missing end_of_record)",
                line_index + 1
            ));
            self.parsed.records.extend(self.current.take());
        }
        if value.trim().is_empty() {
            self.parsed.invalid = true;
            self.diagnostics
                .push(format!("empty LCOV source path at line {}", line_index + 1));
            return;
        }
        self.current = Some(ParsedFile {
            path: value.trim().to_owned(),
            ..ParsedFile::default()
        });
        self.line_summary = None;
        self.branch_summary = None;
        self.saw_end = false;
    }

    fn end_record(&mut self, line_index: usize) {
        let Some(file) = self.current.take() else {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV end_of_record without SF at line {}",
                line_index + 1
            ));
            return;
        };
        self.validate_line_summary(&file);
        self.validate_branch_summary(&file);
        if file.lines.is_empty()
            && file.branches.is_empty()
            && self.line_summary.is_none()
            && self.branch_summary.is_none()
        {
            self.parsed.incomplete = true;
            self.diagnostics.push(format!(
                "LCOV record for '{}' contains no line or branch measurement",
                file.path
            ));
        }
        self.parsed.saw_record = true;
        self.parsed.records.push(file);
        self.saw_end = true;
        self.line_summary = None;
        self.branch_summary = None;
    }

    fn validate_line_summary(&mut self, file: &ParsedFile) {
        let Some((eligible, covered)) = self.line_summary else {
            return;
        };
        let actual_eligible = file
            .lines
            .iter()
            .map(|line| line.line)
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let actual_covered = file
            .lines
            .iter()
            .filter(|line| line.covered)
            .map(|line| line.line)
            .collect::<BTreeSet<_>>()
            .len() as u64;
        if eligible != actual_eligible || covered != actual_covered {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV line summary contradicts records for '{}'",
                file.path
            ));
        }
    }

    fn validate_branch_summary(&mut self, file: &ParsedFile) {
        let Some((eligible, covered)) = self.branch_summary else {
            return;
        };
        let actual_eligible = file
            .branches
            .iter()
            .map(|branch| (branch.line, branch.identity.as_str()))
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let actual_covered = file
            .branches
            .iter()
            .filter(|branch| branch.covered)
            .map(|branch| (branch.line, branch.identity.as_str()))
            .collect::<BTreeSet<_>>()
            .len() as u64;
        if eligible != actual_eligible || covered != actual_covered {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV branch summary contradicts records for '{}'",
                file.path
            ));
        }
    }

    fn parse_line_measurement(&mut self, value: &str, line_index: usize) {
        let Some(file) = self.current.as_mut() else {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV DA outside source record at line {}",
                line_index + 1
            ));
            return;
        };
        let fields = value.split(',').collect::<Vec<_>>();
        if fields.len() < 2 || fields.len() > 3 {
            self.parsed.invalid = true;
            self.diagnostics
                .push(format!("malformed LCOV DA at line {}", line_index + 1));
            return;
        }
        let Some(line) = parse_u32(fields[0]) else {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "invalid LCOV line number at line {}",
                line_index + 1
            ));
            return;
        };
        let Some(count) = parse_nonnegative_u64(fields[1]) else {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "invalid LCOV line count at line {}",
                line_index + 1
            ));
            return;
        };
        let checksum = if fields.len() == 3 {
            let value = fields[2].trim();
            if !is_lcov_checksum(value) {
                self.parsed.invalid = true;
                self.diagnostics.push(format!(
                    "invalid LCOV line checksum at line {}",
                    line_index + 1
                ));
                return;
            }
            Some(value.to_owned())
        } else {
            None
        };
        file.lines.push(ParsedLine {
            line,
            covered: count > 0,
            checksum,
        });
    }

    fn parse_branch_measurement(&mut self, value: &str, line_index: usize) {
        let Some(file) = self.current.as_mut() else {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV BRDA outside source record at line {}",
                line_index + 1
            ));
            return;
        };
        let fields = value.split(',').collect::<Vec<_>>();
        if fields.len() < 4
            || fields[0].trim().is_empty()
            || fields[1].trim().is_empty()
            || fields[2].trim().is_empty()
        {
            self.parsed.invalid = true;
            self.diagnostics
                .push(format!("malformed LCOV BRDA at line {}", line_index + 1));
            return;
        }
        let Some(line) = parse_u32(fields[0]) else {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "invalid LCOV branch line at line {}",
                line_index + 1
            ));
            return;
        };
        let taken = fields[3].trim();
        let covered = if taken == "-" {
            false
        } else {
            let Some(count) = parse_nonnegative_u64(taken) else {
                self.parsed.invalid = true;
                self.diagnostics.push(format!(
                    "invalid LCOV branch count at line {}",
                    line_index + 1
                ));
                return;
            };
            count > 0
        };
        let identity = format!("{}:{}", fields[1].trim(), fields[2].trim());
        file.branches.push(ParsedBranch {
            line,
            identity,
            covered,
        });
    }

    fn parse_line_summary(&mut self, tag: &str, value: &str, line_index: usize) {
        if self.current.is_none() {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV {tag} outside source record at line {}",
                line_index + 1
            ));
            return;
        }
        let Some(value) = parse_nonnegative_u64(value) else {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "invalid LCOV line summary at line {}",
                line_index + 1
            ));
            return;
        };
        let summary = self.line_summary.get_or_insert((0, 0));
        if tag == "LF" {
            summary.0 = value;
        } else {
            summary.1 = value;
        }
    }

    fn parse_branch_summary(&mut self, tag: &str, value: &str, line_index: usize) {
        if self.current.is_none() {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV {tag} outside source record at line {}",
                line_index + 1
            ));
            return;
        }
        let Some(value) = parse_nonnegative_u64(value) else {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "invalid LCOV branch summary at line {}",
                line_index + 1
            ));
            return;
        };
        let summary = self.branch_summary.get_or_insert((0, 0));
        if tag == "BRF" {
            summary.0 = value;
        } else {
            summary.1 = value;
        }
    }

    fn parse_function(&mut self, value: &str, line_index: usize) {
        if self.current.is_none() {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV FN outside source record at line {}",
                line_index + 1
            ));
            return;
        }
        let Some((line_number, _name)) = value.split_once(',') else {
            self.parsed.invalid = true;
            self.diagnostics
                .push(format!("malformed LCOV FN at line {}", line_index + 1));
            return;
        };
        if parse_u32(line_number).is_none() {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "invalid LCOV function line at line {}",
                line_index + 1
            ));
        }
    }

    fn parse_function_data(&mut self, value: &str, line_index: usize) {
        if self.current.is_none() {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV FNDA outside source record at line {}",
                line_index + 1
            ));
            return;
        }
        let Some((count, _name)) = value.split_once(',') else {
            self.parsed.invalid = true;
            self.diagnostics
                .push(format!("malformed LCOV FNDA at line {}", line_index + 1));
            return;
        };
        if parse_nonnegative_u64(count).is_none() {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "invalid LCOV function count at line {}",
                line_index + 1
            ));
        }
    }

    fn parse_function_summary(&mut self, tag: &str, value: &str, line_index: usize) {
        if self.current.is_none() {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "LCOV {tag} outside source record at line {}",
                line_index + 1
            ));
            return;
        }
        if parse_nonnegative_u64(value).is_none() {
            self.parsed.invalid = true;
            self.diagnostics.push(format!(
                "invalid LCOV function summary at line {}",
                line_index + 1
            ));
        }
    }

    fn finish(&mut self, content: &str) {
        if let Some(file) = self.current.take() {
            self.parsed.incomplete = true;
            self.diagnostics
                .push(format!("truncated LCOV record for '{}'", file.path));
            self.parsed.records.push(file);
        }
        if !content.trim().is_empty()
            && !self.saw_end
            && self.parsed.records.is_empty()
            && !self.parsed.invalid
        {
            self.parsed.incomplete = true;
            self.diagnostics
                .push("LCOV contains no complete source record".to_owned());
        }
    }
}

fn parse_opencover(content: &str, diagnostics: &mut Vec<String>) -> ParsedCoverage {
    if content.trim().is_empty() {
        let parsed = ParsedCoverage {
            incomplete: true,
            ..ParsedCoverage::default()
        };
        diagnostics.push("OpenCover report is empty".to_owned());
        return parsed;
    }
    OpenCoverParser::new(diagnostics).parse(content)
}

struct OpenCoverParser<'a> {
    parsed: ParsedCoverage,
    diagnostics: &'a mut Vec<String>,
    depth: usize,
    stack: Vec<String>,
    files: BTreeMap<String, (String, Option<String>)>,
    method_file: Option<String>,
    method_uid: Option<String>,
    method_anchor_line: Option<u32>,
    method_child: Option<String>,
    method_child_text: String,
    records: BTreeMap<String, ParsedFile>,
    summary: Option<(u64, u64, u64, u64)>,
    root_seen: bool,
    root_closed: bool,
    sequence_count: u64,
    visited_sequence_count: u64,
    branch_count: u64,
    visited_branch_count: u64,
}

impl<'a> OpenCoverParser<'a> {
    fn new(diagnostics: &'a mut Vec<String>) -> Self {
        Self {
            parsed: ParsedCoverage::default(),
            diagnostics,
            depth: 0,
            stack: Vec::new(),
            files: BTreeMap::new(),
            method_file: None,
            method_uid: None,
            method_anchor_line: None,
            method_child: None,
            method_child_text: String::new(),
            records: BTreeMap::new(),
            summary: None,
            root_seen: false,
            root_closed: false,
            sequence_count: 0,
            visited_sequence_count: 0,
            branch_count: 0,
            visited_branch_count: 0,
        }
    }

    fn parse(mut self, content: &str) -> ParsedCoverage {
        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);
        let mut buffer = Vec::new();
        loop {
            let event = match reader.read_event_into(&mut buffer) {
                Ok(event) => event,
                Err(error) => {
                    let message = error.to_string();
                    if message.to_ascii_lowercase().contains("unexpected eof") {
                        self.parsed.incomplete = true;
                        self.diagnostics
                            .push(format!("truncated OpenCover XML: {message}"));
                    } else {
                        self.parsed.invalid = true;
                        self.diagnostics
                            .push(format!("malformed OpenCover XML: {message}"));
                    }
                    break;
                }
            };
            let is_empty = matches!(&event, Event::Empty(_));
            if matches!(&event, Event::Eof) {
                break;
            }
            self.handle_event(event, is_empty);
            buffer.clear();
        }
        self.finish()
    }

    fn handle_event(&mut self, event: Event<'_>, is_empty: bool) {
        match event {
            Event::Decl(_) | Event::Comment(_) | Event::CData(_) | Event::PI(_) | Event::Eof => {}
            Event::Text(text) => self.handle_text(text.as_ref()),
            Event::DocType(_) | Event::GeneralRef(_) => {
                self.parsed.invalid = true;
                self.diagnostics
                    .push("OpenCover DTD and entity references are not supported".to_owned());
            }
            Event::Start(start) | Event::Empty(start) => self.handle_start(&start, is_empty),
            Event::End(end) => self.handle_end(&end),
        }
    }

    fn handle_text(&mut self, text: &str) {
        if text.len() > MAX_XML_TEXT {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover XML text node exceeds the bounded importer limit".to_owned());
        }
        if self.depth == 0 && !text.is_empty() {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover XML has text outside its document root".to_owned());
        }
        if self.method_child.is_some() {
            self.method_child_text.push_str(text);
        }
    }

    fn handle_start(&mut self, start: &BytesStart<'_>, is_empty: bool) {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_XML_DEPTH {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover XML nesting exceeds the bounded importer limit".to_owned());
        }
        let name = xml_name(start.name().as_ref());
        self.handle_root(&name);
        if !is_empty {
            self.stack.push(name.clone());
        }
        self.start_method_child(&name, is_empty);
        let attrs = xml_attributes(start, self.diagnostics, &mut self.parsed.invalid);
        match name.as_str() {
            "file" => self.handle_file(&attrs),
            "fileref" => self.handle_file_ref(&attrs),
            "method" => self.handle_method(&attrs),
            "sequencepoint" => {
                self.handle_sequence_point(&attrs);
            }
            "branchpoint" | "branch" => {
                self.handle_branch_point(&attrs);
            }
            "summary" if self.depth == 2 && self.summary.is_none() => {
                self.handle_summary(&attrs);
            }
            _ => {}
        }
        if is_empty {
            self.close_empty(&name);
        }
    }

    fn handle_root(&mut self, name: &str) {
        if self.depth != 1 {
            return;
        }
        if self.root_closed {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover XML contains multiple document roots".to_owned());
        }
        self.root_seen |= name == "coveragesession";
        if name != "coveragesession" {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover document root must be CoverageSession".to_owned());
        }
    }

    fn start_method_child(&mut self, name: &str, is_empty: bool) {
        if !is_empty
            && matches!(name, "name" | "metadatatoken")
            && self.stack.iter().any(|element| element == "method")
        {
            self.method_child = Some(name.to_owned());
            self.method_child_text.clear();
        }
    }

    fn handle_file(&mut self, attrs: &BTreeMap<String, String>) {
        let uid = attr(attrs, "uid");
        let path = attr_any(attrs, &["fullpath", "path"]);
        match (uid, path) {
            (Some(uid), Some(path)) if !uid.is_empty() && !path.is_empty() => {
                let hash = attr_any(attrs, &["hash", "checksum"]).map(ToOwned::to_owned);
                if hash.as_deref().is_some_and(|hash| hash.len() != 64) {
                    self.diagnostics.push(format!(
                        "OpenCover file hash for '{path}' uses an unsupported algorithm; source mismatch cannot be verified"
                    ));
                }
                self.files.insert(uid.to_owned(), (path.to_owned(), hash));
            }
            _ => {
                self.parsed.invalid = true;
                self.diagnostics
                    .push("OpenCover File requires uid and fullPath".to_owned());
            }
        }
    }

    fn handle_file_ref(&mut self, attrs: &BTreeMap<String, String>) {
        if let Some(uid) = attr(attrs, "uid") {
            self.method_file = self.files.get(uid).map(|(path, _)| path.clone());
            if self.method_file.is_none() {
                self.parsed.invalid = true;
                self.diagnostics
                    .push(format!("OpenCover FileRef references unknown uid '{uid}'"));
            }
        } else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover FileRef requires uid".to_owned());
        }
    }

    fn handle_method(&mut self, attrs: &BTreeMap<String, String>) {
        let identity = [
            "uid",
            "id",
            "fullname",
            "name",
            "signature",
            "metadatatoken",
            "declaringtype",
        ]
        .iter()
        .filter_map(|key| attr(attrs, key).map(|value| format!("{key}={value}")))
        .collect::<Vec<_>>()
        .join("|");
        self.method_uid = (!identity.is_empty()).then_some(identity);
        self.method_anchor_line = None;
        self.method_file = attr_any(attrs, &["fileid", "fileuid"])
            .and_then(|uid| self.files.get(uid).map(|(path, _)| path.clone()));
    }

    fn handle_sequence_point(&mut self, attrs: &BTreeMap<String, String>) {
        let line_start = attr_any(attrs, &["sl", "startline"]).and_then(parse_u32);
        let line_end = attr_any(attrs, &["el", "endline"]).map_or(line_start, parse_u32);
        let visits = attr_any(attrs, &["vc", "visitcount"]).and_then(parse_nonnegative_u64);
        let Some(line_start) = line_start else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover SequencePoint requires sl".to_owned());
            return;
        };
        let Some(line_end) = line_end else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover SequencePoint requires el".to_owned());
            return;
        };
        let Some(visits) = visits else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover SequencePoint requires vc".to_owned());
            return;
        };
        let path = attr_any(attrs, &["fileid", "fileuid"])
            .and_then(|uid| self.files.get(uid).map(|(path, _)| path.clone()))
            .or_else(|| self.method_file.clone());
        let Some(path) = path else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover SequencePoint has no resolvable file".to_owned());
            return;
        };
        let Some(span) = line_end.checked_sub(line_start) else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover SequencePoint end line precedes start line".to_owned());
            return;
        };
        if span > 100_000 {
            self.parsed.invalid = true;
            self.diagnostics.push(
                "OpenCover SequencePoint line span exceeds the bounded importer limit".to_owned(),
            );
        } else {
            self.method_anchor_line = Some(
                self.method_anchor_line
                    .map_or(line_start, |anchor| anchor.min(line_start)),
            );
            let file_hash = self.file_hash_for_path(&path);
            let file = self
                .records
                .entry(path.clone())
                .or_insert_with(|| ParsedFile {
                    path,
                    file_hash,
                    ..ParsedFile::default()
                });
            for line in line_start..=line_end {
                file.lines.push(ParsedLine {
                    line,
                    covered: visits > 0,
                    checksum: None,
                });
            }
        }
        self.sequence_count = self.sequence_count.saturating_add(1);
        if visits > 0 {
            self.visited_sequence_count = self.visited_sequence_count.saturating_add(1);
        }
    }

    fn handle_branch_point(&mut self, attrs: &BTreeMap<String, String>) {
        let line = attr_any(attrs, &["sl", "line"]).and_then(parse_u32);
        let visits = attr_any(attrs, &["vc", "visitcount"]).and_then(parse_nonnegative_u64);
        let Some(line) = line else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover branch point requires sl or line".to_owned());
            return;
        };
        let Some(visits) = visits else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover branch point requires vc".to_owned());
            return;
        };
        let path = attr_any(attrs, &["fileid", "fileuid"])
            .and_then(|uid| self.files.get(uid).map(|(path, _)| path.clone()))
            .or_else(|| self.method_file.clone());
        let Some(path) = path else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover branch point has no resolvable file".to_owned());
            return;
        };
        let branch_identity = [
            "uspid",
            "ordinal",
            "path",
            "offset",
            "offsetend",
            "sl",
            "el",
        ]
        .iter()
        .filter_map(|key| attr(attrs, key).map(|value| format!("{key}={value}")))
        .collect::<Vec<_>>();
        if branch_identity.is_empty() {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover branch point has no stable identity attributes".to_owned());
            return;
        }
        let method_key = self.method_uid.clone().unwrap_or_else(|| {
            format!(
                "file={}|anchor={}",
                self.method_file.as_deref().unwrap_or(""),
                self.method_anchor_line.map_or(line, |anchor| anchor)
            )
        });
        let identity = format!(
            "method={method_key}|line={line}|{}",
            branch_identity.join("|")
        );
        let file_hash = self.file_hash_for_path(&path);
        let file = self
            .records
            .entry(path.clone())
            .or_insert_with(|| ParsedFile {
                path,
                file_hash,
                ..ParsedFile::default()
            });
        file.branches.push(ParsedBranch {
            line,
            identity,
            covered: visits > 0,
        });
        self.branch_count = self.branch_count.saturating_add(1);
        if visits > 0 {
            self.visited_branch_count = self.visited_branch_count.saturating_add(1);
        }
    }

    fn handle_summary(&mut self, attrs: &BTreeMap<String, String>) {
        let values = (
            attr_any(attrs, &["numsequencepoints", "sequencepoints"])
                .and_then(parse_nonnegative_u64),
            attr_any(attrs, &["visitedsequencepoints"]).and_then(parse_nonnegative_u64),
            attr_any(attrs, &["numbranchpoints", "branchpoints"]).and_then(parse_nonnegative_u64),
            attr_any(attrs, &["visitedbranchpoints", "visitedbranches"])
                .and_then(parse_nonnegative_u64),
        );
        if let (Some(a), Some(b), Some(c), Some(d)) = values {
            self.summary = Some((a, b, c, d));
        } else {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover Summary has incomplete counters".to_owned());
        }
    }

    fn file_hash_for_path(&self, path: &str) -> Option<String> {
        self.files
            .values()
            .find(|(candidate, _)| candidate == path)
            .and_then(|(_, hash)| hash.clone())
    }

    fn close_empty(&mut self, name: &str) {
        if self.depth == 1 && name == "coveragesession" {
            self.root_closed = true;
        }
        self.depth = self.depth.saturating_sub(1);
    }

    fn handle_end(&mut self, end: &quick_xml::events::BytesEnd<'_>) {
        let name = xml_name(end.name().as_ref());
        if self.method_child.as_deref() == Some(name.as_str()) {
            let value = self.method_child_text.trim();
            if !value.is_empty() {
                let component = format!("child={name}={value}");
                self.method_uid = Some(match self.method_uid.take() {
                    Some(existing) => format!("{existing}|{component}"),
                    None => component,
                });
            }
            self.method_child = None;
            self.method_child_text.clear();
        }
        match self.stack.pop() {
            Some(expected) if expected == name => {}
            _ => {
                self.parsed.invalid = true;
                self.diagnostics
                    .push(format!("mismatched OpenCover XML closing tag '{name}'"));
            }
        }
        if name == "method" {
            self.method_file = None;
            self.method_uid = None;
            self.method_anchor_line = None;
        }
        if name == "coveragesession" && self.depth == 1 {
            self.root_closed = true;
        }
        self.depth = self.depth.saturating_sub(1);
    }

    fn finish(mut self) -> ParsedCoverage {
        if !self.root_seen {
            self.parsed.invalid = true;
            self.diagnostics
                .push("OpenCover document root must be CoverageSession".to_owned());
        }
        if self.depth != 0 || !self.stack.is_empty() {
            self.parsed.incomplete = true;
            self.diagnostics
                .push("truncated OpenCover XML document".to_owned());
        }
        if let Some((
            expected_sequences,
            expected_visited_sequences,
            expected_branches,
            expected_visited_branches,
        )) = self.summary
            && (expected_sequences != self.sequence_count
                || expected_visited_sequences != self.visited_sequence_count
                || expected_branches != self.branch_count
                || expected_visited_branches != self.visited_branch_count)
        {
            self.parsed.invalid = true;
            self.diagnostics.push(
                "OpenCover Summary counters contradict sequence or branch records".to_owned(),
            );
        }
        self.parsed.records = self.records.into_values().collect();
        self.parsed.saw_record = !self.parsed.records.is_empty();
        if self.parsed.records.is_empty() && !self.parsed.invalid && !self.parsed.incomplete {
            self.parsed.incomplete = true;
            self.diagnostics
                .push("OpenCover document contains no coverage records".to_owned());
        }
        self.parsed
    }
}

fn normalize_source_path(root: &str, root_windows: bool, path: &Path) -> Option<String> {
    normalize_path_text(root, root_windows, &lexical_path(path), true)
}

fn normalize_report_path(root: &str, root_windows: bool, path: &Path) -> Option<String> {
    normalize_path_text(root, root_windows, &lexical_path(path), false)
}

fn normalize_path_text(
    root: &str,
    root_windows: bool,
    raw: &str,
    source_path: bool,
) -> Option<String> {
    let text = raw.replace('\\', "/");
    let root_text = root.replace('\\', "/");
    let text_windows = is_windows_absolute(&text);
    let root_components = path_components(&root_text);
    let components =
        normalized_path_components(&text, text_windows, &root_components, root_windows)?;
    let clean = clean_path_components(components)?;
    if source_path && clean.is_empty() {
        return None;
    }
    Some(clean.join("/"))
}

fn normalized_path_components(
    text: &str,
    text_windows: bool,
    root_components: &[String],
    root_windows: bool,
) -> Option<Vec<String>> {
    if !is_absolute_like(text) {
        return Some(path_components(text));
    }
    let text_components = path_components(text);
    if text_windows != root_windows {
        // A report generated on Windows may use a drive prefix while the
        // caller's canonical root is represented by a Unix path.  Only
        // accept it when its path components end in the exact root
        // components; this avoids basename-only matching while permitting
        // cross-platform artifact transfer.
        if text_components.len() < root_components.len()
            || !components_match(
                &text_components[text_components.len() - root_components.len()..],
                root_components,
                text_windows || root_windows,
            )
        {
            return None;
        }
        return Some(text_components[text_components.len() - root_components.len()..].to_vec());
    }
    if text_components.len() < root_components.len()
        || !components_match(
            &text_components[..root_components.len()],
            root_components,
            root_windows,
        )
    {
        return None;
    }
    Some(text_components[root_components.len()..].to_vec())
}

fn clean_path_components(components: Vec<String>) -> Option<Vec<String>> {
    let mut clean = Vec::with_capacity(components.len());
    for component in components {
        match component.as_str() {
            "" | "." => {}
            ".." => {
                clean.pop()?;
            }
            _ => clean.push(component),
        }
    }
    Some(clean)
}

fn path_components(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .map(ToOwned::to_owned)
        .collect()
}

fn lexical_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
fn components_match(left: &[String], right: &[String], case_insensitive: bool) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            if case_insensitive {
                left.eq_ignore_ascii_case(right)
            } else {
                left == right
            }
        })
}

fn is_absolute_like(path: &str) -> bool {
    path.starts_with('/') || is_windows_absolute(path)
}

fn is_windows_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with("//") || (bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'/')
}

fn path_key(path: &str) -> String {
    path.to_lowercase()
}

fn input_path(root: &Path, path: &Path) -> PathBuf {
    let root_text = lexical_path(root);
    let root_windows = is_windows_absolute(&root_text);
    normalize_report_path(&root_text, root_windows, path)
        .map_or_else(|| PathBuf::from(lexical_path(path)), PathBuf::from)
}

fn source_line_count(source: &str) -> usize {
    if source.is_empty() {
        return 0;
    }
    let count = source.bytes().filter(|byte| *byte == b'\n').count();
    if source.ends_with('\n') {
        count
    } else {
        count.saturating_add(1)
    }
}

fn is_lcov_checksum(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

fn source_line_checksum(source: &str, line: u32) -> Option<String> {
    let index = usize::try_from(line).ok()?.checked_sub(1)?;
    let source_line = source.split('\n').nth(index)?;
    let source_line = source_line.strip_suffix('\r').unwrap_or(source_line);
    let digest = Md5::digest(source_line.as_bytes());
    Some(STANDARD_NO_PAD.encode(digest))
}

fn classification_name(classification: FileClassification) -> &'static str {
    match classification {
        FileClassification::Source => "source",
        FileClassification::Test => "test",
        FileClassification::Generated => "generated",
        FileClassification::Vendor => "vendor",
        FileClassification::Excluded => "excluded",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn verify_file_hash(reported: &str, source_digest: &str) -> bool {
    reported.len() == 64 && reported.eq_ignore_ascii_case(source_digest)
}

fn parse_u32(value: &str) -> Option<u32> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    value.parse().ok()
}

fn parse_nonnegative_u64(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    value.parse().ok()
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn xml_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn xml_attributes(
    start: &BytesStart<'_>,
    diagnostics: &mut Vec<String>,
    invalid: &mut bool,
) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    for attribute in start.attributes() {
        let Ok(attribute) = attribute else {
            *invalid = true;
            diagnostics.push("malformed OpenCover XML attribute".to_owned());
            continue;
        };
        let key = xml_name(attribute.key.as_ref());
        let Ok(value) = attribute.normalized_value(XmlVersion::Implicit1_0) else {
            *invalid = true;
            diagnostics.push(format!("invalid OpenCover XML attribute '{key}'"));
            continue;
        };
        attrs.insert(key, value.into_owned());
    }
    attrs
}

fn attr<'a>(attrs: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    attrs.get(key).map(String::as_str)
}

fn attr_any<'a>(attrs: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| attr(attrs, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source<'a>(path: &'a str, text: &'a str) -> CoverageFile<'a> {
        CoverageFile {
            path: Path::new(path),
            source: text,
            classification: FileClassification::Source,
        }
    }

    fn lcov(path: &str, body: &str) -> CoverageSource {
        CoverageSource {
            path: PathBuf::from(path),
            format: CoverageFormat::Lcov,
            content: body.to_owned(),
        }
    }

    #[test]
    fn lcov_partial_zero_and_full_runs_are_distinct_and_deterministic() {
        let files = [source("src/a.js", "one\ntwo\nthree\n")];
        let partial = import_coverage(
            Path::new("/repo"),
            &[lcov(
                "coverage/lcov.info",
                "TN:\nSF:/repo/src/a.js\nDA:1,0\nDA:2,1\nLF:2\nLH:1\nend_of_record\n",
            )],
            &files,
        );
        assert_eq!(partial.status, AssessmentStatus::Complete);
        assert_eq!(
            partial.lines,
            CoverageCounter {
                eligible: 2,
                covered: 1
            }
        );
        let full = import_coverage(
            Path::new("/repo"),
            &[lcov(
                "coverage/lcov.info",
                "TN:\nSF:src/a.js\nDA:1,1\nDA:2,1\nDA:3,1\nLF:3\nLH:3\nend_of_record\n",
            )],
            &files,
        );
        assert_eq!(
            full.lines,
            CoverageCounter {
                eligible: 3,
                covered: 3
            }
        );
        assert_ne!(partial.lines, full.lines);
    }

    #[test]
    fn repeated_runs_union_without_inflating_line_or_branch_denominators() {
        let files = [source("src/a.js", "one\ntwo\n")];
        let first = lcov(
            "a.info",
            "SF:src/a.js\nDA:1,1\nBRDA:1,0,0,1\nBRDA:1,0,1,-\nend_of_record\n",
        );
        let second = lcov(
            "b.info",
            "SF:src/a.js\nDA:1,0\nDA:2,1\nBRDA:1,0,0,0\nBRDA:1,0,1,1\nend_of_record\n",
        );
        let report = import_coverage(Path::new("/repo"), &[first, second], &files);
        assert_eq!(
            report.lines,
            CoverageCounter {
                eligible: 2,
                covered: 2
            }
        );
        assert_eq!(
            report.branches,
            CoverageCounter {
                eligible: 2,
                covered: 2
            }
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|message| message.contains("contradictory"))
        );
    }

    #[test]
    fn paths_are_root_relative_and_outside_unknown_and_missing_lines_are_invalid() {
        let files = [source("src/ü.js", "one\ntwo\n")];
        for invalid_record in [
            "SF:src/ü.js\nDA:3,1\nend_of_record\n",
            "SF:src/no.js\nDA:1,1\nend_of_record\n",
            "SF:../outside.js\nDA:1,1\nend_of_record\n",
        ] {
            let report = import_coverage(
                Path::new("/repo"),
                &[lcov("/tmp/a.info", invalid_record)],
                &files,
            );
            assert_eq!(report.status, AssessmentStatus::Invalid, "{invalid_record}");
            assert_eq!(report.lines.covered, 0);
        }
    }

    #[test]
    fn scope_classes_do_not_enter_denominators() {
        let mut test = source("tests/a.js", "one\n");
        test.classification = FileClassification::Test;
        let mut generated = source("gen/a.js", "one\n");

        generated.classification = FileClassification::Generated;
        let report = import_coverage(
            Path::new("/repo"),
            &[lcov(
                "coverage.info",
                "SF:tests/a.js\nDA:1,1\nend_of_record\nSF:gen/a.js\nDA:1,1\nend_of_record\n",
            )],
            &[test, generated],
        );
        assert_eq!(report.status, AssessmentStatus::Complete);
        assert_eq!(
            report.lines,
            CoverageCounter {
                eligible: 0,
                covered: 0
            }
        );
        assert!(report.files.is_empty());
    }
    #[test]
    fn opencover_sha256_file_hash_mismatch_is_invalid() {
        let files = [source("src/A.cs", "one\n")];
        let xml = r#"<CoverageSession><Modules><Module><Files><File uid="1" fullPath="/repo/src/A.cs" hash="0000000000000000000000000000000000000000000000000000000000000000"/></Files><Classes><Class><Methods><Method><FileRef uid="1"/><SequencePoints><SequencePoint vc="1" sl="1" el="1"/></SequencePoints></Method></Methods></Class></Classes></Module></Modules></CoverageSession>"#;
        let report = import_coverage(
            Path::new("/repo"),
            &[CoverageSource {
                path: PathBuf::from("coverage.xml"),
                format: CoverageFormat::OpenCover,
                content: xml.to_owned(),
            }],
            &files,
        );
        assert_eq!(report.status, AssessmentStatus::Invalid);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|message| message.contains("hash mismatch"))
        );
    }

    #[test]
    fn windows_case_folded_path_with_two_candidates_is_ambiguous() {
        let files = [source("src/A.js", "one\n"), source("src/a.js", "one\n")];
        let report = import_coverage(
            Path::new("C:\\repo"),
            &[lcov(
                "coverage.info",
                "SF:SRC\\A.JS\nDA:1,1\nend_of_record\n",
            )],
            &files,
        );
        assert_eq!(report.status, AssessmentStatus::Invalid);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|message| message.contains("ambiguous"))
        );
    }

    #[test]
    fn lcov_record_without_measurement_is_incomplete() {
        let files = [source("src/a.js", "one\n")];
        let report = import_coverage(
            Path::new("/repo"),
            &[lcov("coverage.info", "SF:src/a.js\nend_of_record\n")],
            &files,
        );
        assert_eq!(report.status, AssessmentStatus::Incomplete);
        assert_eq!(
            report.lines,
            CoverageCounter {
                eligible: 0,
                covered: 0
            }
        );
    }

    #[test]
    fn truncated_and_malformed_reports_are_not_measured_zero() {
        let files = [source("src/a.js", "one\n")];
        let truncated = import_coverage(
            Path::new("/repo"),
            &[lcov("coverage.info", "SF:src/a.js\nDA:1,0\n")],
            &files,
        );
        assert_eq!(truncated.status, AssessmentStatus::Incomplete);
        let malformed = import_coverage(
            Path::new("/repo"),
            &[lcov(
                "coverage.info",
                "SF:src/a.js\nDA:one,nope\nend_of_record\n",
            )],
            &files,
        );
        assert_eq!(malformed.status, AssessmentStatus::Invalid);
        assert_ne!(malformed.status, AssessmentStatus::Complete);
    }

    #[test]
    fn opencover_sequence_and_branch_points_are_joined_by_file_ref() {
        let files = [source("src/A.cs", "one\ntwo\n")];
        let xml = r#"<?xml version="1.0"?><CoverageSession><Summary numSequencePoints="2" visitedSequencePoints="1" numBranchPoints="2" visitedBranchPoints="1"/><Modules><Module><Files><File uid="1" fullPath="C:\repo\src\A.cs"/></Files><Classes><Class><Methods><Method><FileRef uid="1"/><SequencePoints><SequencePoint vc="1" sl="1" el="1"/><SequencePoint vc="0" sl="2" el="2"/></SequencePoints><BranchPoints><BranchPoint vc="1" sl="1" ordinal="0"/><BranchPoint vc="0" sl="1" ordinal="1"/></BranchPoints></Method></Methods></Class></Classes></Module></Modules></CoverageSession>"#;
        let report = import_coverage(
            Path::new("C:\\repo"),
            &[CoverageSource {
                path: PathBuf::from("coverage.xml"),
                format: CoverageFormat::OpenCover,
                content: xml.to_owned(),
            }],
            &files,
        );
        assert_eq!(report.status, AssessmentStatus::Complete);
        assert_eq!(
            report.lines,
            CoverageCounter {
                eligible: 2,
                covered: 1
            }
        );
        assert_eq!(
            report.branches,
            CoverageCounter {
                eligible: 2,
                covered: 1
            }
        );
    }

    #[test]
    fn opencover_keeps_records_for_multiple_files_and_rejects_dtds() {
        let files = [source("src/a.cs", "one\n"), source("src/b.cs", "one\n")];
        let xml = r#"<!DOCTYPE CoverageSession SYSTEM "file:///tmp/evil"><CoverageSession><Modules><Module><Files><File uid="1" fullPath="/repo/src/a.cs"/><File uid="2" fullPath="/repo/src/b.cs"/></Files><Classes><Class><Methods><Method><FileRef uid="1"/><SequencePoints><SequencePoint vc="1" sl="1" el="1"/></SequencePoints></Method><Method><FileRef uid="2"/><SequencePoints><SequencePoint vc="0" sl="1" el="1"/></SequencePoints></Method></Methods></Class></Classes></Module></Modules></CoverageSession>"#;
        let report = import_coverage(
            Path::new("/repo"),
            &[CoverageSource {
                path: PathBuf::from("coverage.xml"),
                format: CoverageFormat::OpenCover,
                content: xml.to_owned(),
            }],
            &files,
        );
        assert_eq!(report.status, AssessmentStatus::Invalid);
        assert_eq!(
            report.lines,
            CoverageCounter {
                eligible: 2,
                covered: 1
            }
        );
        assert_eq!(report.files.len(), 2);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|message| message.contains("DTD"))
        );
    }

    #[test]
    fn lcov_line_checksums_validate_exact_source_lines_and_crlf() {
        let files = [source("src/a.js", "one\r\ntwo\r\n")];
        let checksum = STANDARD_NO_PAD.encode(Md5::digest(b"one"));
        let valid = lcov(
            "coverage.info",
            &format!("SF:src/a.js\nDA:1,1,{checksum}\nend_of_record\n"),
        );
        let report = import_coverage(Path::new("/repo"), &[valid], &files);
        assert_eq!(report.status, AssessmentStatus::Complete);

        let wrong_checksum = STANDARD_NO_PAD.encode(Md5::digest(b"wrong"));
        let invalid = lcov(
            "coverage.info",
            &format!("SF:src/a.js\nDA:1,1,{wrong_checksum}\nend_of_record\n"),
        );
        let report = import_coverage(Path::new("/repo"), &[invalid], &files);
        assert_eq!(report.status, AssessmentStatus::Invalid);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|message| message.contains("checksum mismatch"))
        );
    }

    #[test]
    fn empty_inputs_are_missing_not_zero() {
        let report = import_coverage(Path::new("/repo"), &[], &[]);
        assert_eq!(report.status, AssessmentStatus::Missing);
        assert_eq!(
            report.lines,
            CoverageCounter {
                eligible: 0,
                covered: 0
            }
        );
    }
}
