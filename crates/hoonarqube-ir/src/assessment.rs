//! Versioned assessment artifacts and source-derived finding identities.
//!
//! Assessment is deliberately separate from the native report schema. The
//! native [`crate::AnalysisReport`] remains schema version one; an optional
//! assessment carries its own version and can therefore be rejected without
//! changing the meaning of existing exports.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest as _, Sha256};

/// The assessment artifact schema currently understood by this crate.
pub const ASSESSMENT_SCHEMA_VERSION: u32 = 1;

/// Borrowed source input used when the caller already owns the source bytes.
#[derive(Debug, Clone, Copy)]
pub struct SourceInput<'a> {
    pub path: &'a Path,
    pub content: &'a [u8],
}

impl<'a> SourceInput<'a> {
    /// Builds a borrowed input without reading the path.
    #[must_use]
    pub const fn new(path: &'a Path, content: &'a [u8]) -> Self {
        Self { path, content }
    }
}

/// Construction and validation failures at the assessment boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssessmentError {
    UnsupportedSchema {
        artifact: &'static str,
        version: u32,
    },
    Invalid {
        artifact: &'static str,
        reason: String,
    },
    InvalidPath(String),
    InvalidSource {
        path: PathBuf,
        reason: String,
    },
    MissingSource(PathBuf),
    DuplicatePath(PathBuf),
}

impl fmt::Display for AssessmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { artifact, version } => {
                write!(formatter, "unsupported {artifact} schema version {version}")
            }
            Self::Invalid { artifact, reason } => {
                write!(formatter, "invalid {artifact}: {reason}")
            }
            Self::InvalidPath(path) => write!(formatter, "invalid assessment path: {path}"),
            Self::InvalidSource { path, reason } => {
                write!(formatter, "invalid source {}: {reason}", path.display())
            }
            Self::MissingSource(path) => {
                write!(
                    formatter,
                    "assessment source bytes missing for {}",
                    path.display()
                )
            }
            Self::DuplicatePath(path) => {
                write!(formatter, "duplicate assessment path: {}", path.display())
            }
        }
    }
}

impl std::error::Error for AssessmentError {}

/// Analyzer/profile/scope identity used for comparison. Source revision is
/// provenance, not a compatibility requirement across different commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub analyzer_version: String,
    pub catalog_digest: String,
    pub options_digest: String,
    pub scope_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
}

impl AnalysisContext {
    /// Creates a context from the complete analyzer/profile/scope identity.
    #[must_use]
    pub fn new(
        analyzer_version: impl Into<String>,
        catalog_digest: impl Into<String>,
        options_digest: impl Into<String>,
        scope_digest: impl Into<String>,
        source_revision: Option<impl Into<String>>,
    ) -> Self {
        Self {
            analyzer_version: analyzer_version.into(),
            catalog_digest: catalog_digest.into(),
            options_digest: options_digest.into(),
            scope_digest: scope_digest.into(),
            source_revision: source_revision.map(Into::into),
        }
    }

    /// Rejects a context that cannot identify the analyzer/profile/scope.
    ///
    /// A missing source revision is valid: callers may not have a VCS
    /// revision.  An explicitly supplied but blank revision is not useful
    /// provenance and is rejected.
    ///
    /// # Errors
    /// Returns [`AssessmentError::Invalid`] if a required identity field or
    /// an explicitly supplied source revision is blank.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        for (field, value) in [
            ("analyzer_version", &self.analyzer_version),
            ("catalog_digest", &self.catalog_digest),
            ("options_digest", &self.options_digest),
            ("scope_digest", &self.scope_digest),
        ] {
            if value.trim().is_empty() {
                return Err(AssessmentError::Invalid {
                    artifact: "analysis context",
                    reason: format!("{field} must not be empty"),
                });
            }
        }
        if self
            .source_revision
            .as_deref()
            .is_some_and(|revision| revision.trim().is_empty())
        {
            return Err(AssessmentError::Invalid {
                artifact: "analysis context",
                reason: "source_revision must not be empty when supplied".to_string(),
            });
        }
        Ok(())
    }

    /// Returns true only when all baseline-relevant context fields match.
    #[must_use]
    pub fn compatible_with(&self, other: &Self) -> bool {
        self.analyzer_version == other.analyzer_version
            && self.catalog_digest == other.catalog_digest
            && self.options_digest == other.options_digest
            && self.scope_digest == other.scope_digest
    }
}

/// One finding's stable, source-derived identity. `identity` intentionally
/// excludes path, line, message, and issue index so harmless movement and
/// message wording changes do not manufacture a new finding. If the same
/// identity occurs more than once, `ambiguous` is true and baseline matching
/// must remain conservative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingIdentity {
    pub issue_index: usize,
    pub rule_key: String,
    pub message: String,
    pub source_digest: String,
    pub context_digest: String,
    pub start_line: u32,
    pub end_line: u32,
    pub identity: String,
    pub ambiguous: bool,
}

/// One analyzed source snapshot and all findings produced for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshot {
    pub path: PathBuf,
    pub content_digest: String,
    pub line_digests: Vec<String>,
    pub findings: Vec<FindingIdentity>,
}

impl SourceSnapshot {
    /// Builds a snapshot from source bytes and a report whose path identifies
    /// the same file. The bytes must be the exact bytes read for analysis.
    ///
    /// # Errors
    /// Returns [`AssessmentError::InvalidPath`] when `path` or the report path
    /// cannot be normalized, [`AssessmentError::Invalid`] when normalized
    /// paths differ or an issue range is inconsistent, and
    /// [`AssessmentError::InvalidSource`] when `source` is not valid UTF-8.
    pub fn from_report(
        path: impl AsRef<Path>,
        source: &[u8],
        report: Option<&crate::FileReport>,
    ) -> Result<Self, AssessmentError> {
        let path = normalize_path(path.as_ref())?;
        if let Some(report) = report
            && normalize_path(&report.path)? != path
        {
            return Err(AssessmentError::Invalid {
                artifact: "source snapshot",
                reason: "report and source paths differ".to_string(),
            });
        }
        let issues = report.map_or(&[][..], |report| report.issues.as_slice());
        Self::from_source_and_issues(&path, source, issues)
    }

    /// Builds a snapshot from source bytes and an issue slice.
    ///
    /// # Errors
    /// Returns [`AssessmentError::InvalidPath`] when `path` cannot be
    /// normalized, [`AssessmentError::Invalid`] when an issue range is
    /// inconsistent, and [`AssessmentError::InvalidSource`] when `source` is
    /// not valid UTF-8.
    pub fn from_source(
        path: impl AsRef<Path>,
        source: &[u8],
        issues: &[crate::Issue],
    ) -> Result<Self, AssessmentError> {
        let path = normalize_path(path.as_ref())?;
        Self::from_source_and_issues(&path, source, issues)
    }

    fn from_source_and_issues(
        path: &Path,
        source: &[u8],
        issues: &[crate::Issue],
    ) -> Result<Self, AssessmentError> {
        let text = std::str::from_utf8(source).map_err(|error| AssessmentError::InvalidSource {
            path: path.to_path_buf(),
            reason: format!("source is not valid UTF-8: {error}"),
        })?;
        let line_digests = split_lines(source).map(line_digest).collect::<Vec<_>>();
        let line_starts = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(offset, _)| offset + 1))
            .collect::<Vec<_>>();
        let content_digest = digest_parts(&[b"content", source]);
        let mut findings = issues
            .iter()
            .enumerate()
            .map(|(issue_index, issue)| {
                finding_identity(issue_index, issue, text, source, &line_starts)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut counts = BTreeMap::<String, usize>::new();
        for finding in &findings {
            *counts.entry(finding.identity.clone()).or_default() += 1;
        }
        for finding in &mut findings {
            finding.ambiguous = counts.get(&finding.identity).copied().unwrap_or(0) > 1;
        }

        Ok(Self {
            path: path.to_path_buf(),
            content_digest,
            line_digests,
            findings,
        })
    }

    /// Validates serialized or manually assembled snapshot data.
    ///
    /// # Errors
    /// Returns [`AssessmentError::InvalidPath`] for paths that cannot be
    /// normalized, or [`AssessmentError::Invalid`] when snapshot path, digest,
    /// or finding invariants are invalid.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.path.as_os_str().is_empty() {
            return Err(AssessmentError::Invalid {
                artifact: "source snapshot",
                reason: "path must not be empty".to_string(),
            });
        }
        let normalized = normalize_path(&self.path)?;
        if normalized != self.path {
            return Err(AssessmentError::Invalid {
                artifact: "source snapshot",
                reason: format!("path is not normalized: {}", self.path.display()),
            });
        }
        if !is_digest(&self.content_digest)
            || self.line_digests.iter().any(|digest| !is_digest(digest))
        {
            return Err(AssessmentError::Invalid {
                artifact: "source snapshot",
                reason: "content and line digests must be lowercase SHA-256 hex".to_string(),
            });
        }
        for (index, finding) in self.findings.iter().enumerate() {
            validate_finding(finding)?;
            if finding.issue_index != index
                || usize::try_from(finding.end_line)
                    .is_ok_and(|line| line > self.line_digests.len().saturating_add(1))
            {
                return Err(AssessmentError::Invalid {
                    artifact: "source snapshot",
                    reason: "finding index or source line is inconsistent".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Finding assessment state relative to a pinned reference report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Existing,
    Uncertain,
}

/// One current finding's baseline classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingMatch {
    pub path: PathBuf,
    pub issue_index: usize,
    pub identity: String,
    pub status: FindingStatus,
}

/// Explicit physical source lines added or changed relative to the reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewCodeLines {
    pub path: PathBuf,
    pub lines: Vec<u32>,
}

/// Assessment state for a baseline/coverage operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    Complete,
    Missing,
    Invalid,
    Incomplete,
}

/// Versioned new-code baseline result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewCodeReport {
    pub schema_version: u32,
    pub status: AssessmentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_context: Option<AnalysisContext>,
    pub findings: Vec<FindingMatch>,
    pub resolved: Vec<FindingIdentity>,
    pub lines: Vec<NewCodeLines>,
    pub diagnostics: Vec<String>,
}

impl NewCodeReport {
    /// Validates the independently versioned new-code artifact.
    ///
    /// # Errors
    /// Returns [`AssessmentError::UnsupportedSchema`] for an unknown artifact
    /// version or [`AssessmentError::Invalid`] when context, finding, or
    /// new-code line invariants fail.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.schema_version != ASSESSMENT_SCHEMA_VERSION {
            return Err(AssessmentError::UnsupportedSchema {
                artifact: "new_code",
                version: self.schema_version,
            });
        }
        if let Some(context) = &self.reference_context {
            context.validate()?;
        }
        for finding in &self.findings {
            if finding.path.as_os_str().is_empty() || !is_digest(&finding.identity) {
                return Err(AssessmentError::Invalid {
                    artifact: "new_code",
                    reason: "finding path and identity must be present".to_string(),
                });
            }
            if normalize_path(&finding.path).ok().as_ref() != Some(&finding.path) {
                return Err(AssessmentError::Invalid {
                    artifact: "new_code",
                    reason: "finding paths must be normalized".to_string(),
                });
            }
        }
        for finding in &self.resolved {
            validate_finding(finding)?;
        }
        for lines in &self.lines {
            if lines.path.as_os_str().is_empty()
                || normalize_path(&lines.path).ok().as_ref() != Some(&lines.path)
                || lines.lines.contains(&0)
                || lines.lines.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(AssessmentError::Invalid {
                    artifact: "new_code",
                    reason: "new-code lines must be positive, sorted, and unique".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Coverage counters with an explicit denominator. `covered > eligible` is
/// rejected rather than silently clamped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageCounter {
    pub eligible: u64,
    pub covered: u64,
}

impl CoverageCounter {
    /// Creates a counter after checking its invariant.
    ///
    /// # Errors
    /// Returns [`AssessmentError::Invalid`] if `covered` exceeds `eligible`.
    pub fn new(eligible: u64, covered: u64) -> Result<Self, AssessmentError> {
        if covered > eligible {
            return Err(AssessmentError::Invalid {
                artifact: "coverage counter",
                reason: "covered cannot exceed eligible".to_string(),
            });
        }
        Ok(Self { eligible, covered })
    }

    /// Returns the unrounded percentage when a denominator exists.
    ///
    /// Coverage counters remain `u64` for the artifact contract. This
    /// presentation calculation intentionally widens them to `f64`; values
    /// above `2^53` may round at `f64` precision, but the mathematical
    /// contract remains `covered / eligible * 100.0` without narrowing the
    /// counters.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn percentage(&self) -> Option<f64> {
        (self.eligible != 0).then(|| self.covered as f64 * 100.0 / self.eligible as f64)
    }

    /// Validates the coverage counter invariant.
    ///
    /// # Errors
    /// Returns [`AssessmentError::Invalid`] if `covered` exceeds `eligible`.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.covered > self.eligible {
            return Err(AssessmentError::Invalid {
                artifact: "coverage counter",
                reason: "covered cannot exceed eligible".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct CoverageCounterRepr {
    eligible: u64,
    covered: u64,
}

impl<'de> Deserialize<'de> for CoverageCounter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = CoverageCounterRepr::deserialize(deserializer)?;
        Self::new(raw.eligible, raw.covered).map_err(de::Error::custom)
    }
}

/// One line's coverage and optional branch/condition counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineCoverage {
    pub line: u32,
    /// `None` means no line hit record was supplied (for example a
    /// branch-only coverage record); `Some(false)` is measured uncovered.
    pub covered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branches: Option<CoverageCounter>,
}

/// Coverage for one normalized source path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCoverage {
    pub path: PathBuf,
    pub lines: Vec<LineCoverage>,
}

/// Origin of one imported coverage input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageInput {
    pub path: PathBuf,
    pub format: String,
    pub content_digest: String,
}

/// Versioned coverage assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub schema_version: u32,
    pub status: AssessmentStatus,
    pub files: Vec<FileCoverage>,
    pub inputs: Vec<CoverageInput>,
    pub lines: CoverageCounter,
    pub branches: CoverageCounter,
    pub diagnostics: Vec<String>,
}

impl CoverageReport {
    /// Validates coverage schema and all counter/path invariants.
    ///
    /// # Errors
    /// Returns [`AssessmentError::UnsupportedSchema`] for an unknown coverage
    /// schema version, [`AssessmentError::InvalidPath`] for an unnormalizable
    /// file path, or [`AssessmentError::Invalid`] when counters, paths, lines,
    /// or imported input metadata violate coverage invariants.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.schema_version != ASSESSMENT_SCHEMA_VERSION {
            return Err(AssessmentError::UnsupportedSchema {
                artifact: "coverage",
                version: self.schema_version,
            });
        }
        self.lines.validate()?;
        self.branches.validate()?;
        let (lines, branches) = coverage_totals(&self.files)?;
        if self.lines != lines || self.branches != branches {
            return Err(AssessmentError::Invalid {
                artifact: "coverage",
                reason: "aggregate counters differ from per-line measurements".to_string(),
            });
        }
        for input in &self.inputs {
            if input.path.as_os_str().is_empty()
                || input.format.is_empty()
                || !is_digest(&input.content_digest)
            {
                return Err(AssessmentError::Invalid {
                    artifact: "coverage",
                    reason: "coverage input path, format, and digest are required".to_string(),
                });
            }
        }
        Ok(())
    }
}

fn coverage_totals(
    files: &[FileCoverage],
) -> Result<(CoverageCounter, CoverageCounter), AssessmentError> {
    let mut lines = CoverageCounter {
        eligible: 0,
        covered: 0,
    };
    let mut branches = CoverageCounter {
        eligible: 0,
        covered: 0,
    };
    let mut previous_file: Option<&Path> = None;
    for file in files {
        if file.path.as_os_str().is_empty()
            || normalize_path(&file.path)? != file.path
            || previous_file.is_some_and(|previous| previous >= file.path.as_path())
        {
            return Err(AssessmentError::Invalid {
                artifact: "coverage",
                reason: "coverage files must have sorted unique normalized paths".to_string(),
            });
        }
        previous_file = Some(&file.path);
        let mut previous_line = 0;
        for line in &file.lines {
            if line.line <= previous_line || (line.covered.is_none() && line.branches.is_none()) {
                return Err(AssessmentError::Invalid {
                    artifact: "coverage",
                    reason: "coverage lines must be sorted, unique, 1-based measurements"
                        .to_string(),
                });
            }
            previous_line = line.line;
            if let Some(covered) = line.covered {
                add_coverage_counter(
                    &mut lines,
                    &CoverageCounter {
                        eligible: 1,
                        covered: u64::from(covered),
                    },
                )?;
            }
            if let Some(counter) = &line.branches {
                counter.validate()?;
                add_coverage_counter(&mut branches, counter)?;
            }
        }
    }
    Ok((lines, branches))
}

fn add_coverage_counter(
    total: &mut CoverageCounter,
    part: &CoverageCounter,
) -> Result<(), AssessmentError> {
    let Some((eligible, covered)) = total
        .eligible
        .checked_add(part.eligible)
        .zip(total.covered.checked_add(part.covered))
    else {
        return Err(AssessmentError::Invalid {
            artifact: "coverage",
            reason: "coverage totals overflow".to_string(),
        });
    };
    *total = CoverageCounter { eligible, covered };
    Ok(())
}

/// Scope of a quality-gate condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateScope {
    Overall,
    NewCode,
}

/// Comparison operator for a quality-gate threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOperator {
    Lt,
    Lte,
    Eq,
    Gte,
    Gt,
}

/// Pass/fail/unavailable state of one gate condition or report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Pass,
    Fail,
    Unavailable,
}

/// One evaluated quality-gate condition.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateConditionResult {
    pub scope: GateScope,
    pub metric: String,
    pub operator: GateOperator,
    pub threshold: f64,
    pub actual: Option<f64>,
    pub status: GateStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
}

#[derive(Deserialize)]
struct GateConditionResultRepr {
    scope: GateScope,
    metric: String,
    operator: GateOperator,
    threshold: f64,
    #[serde(default)]
    actual: Option<f64>,
    status: GateStatus,
    #[serde(default)]
    diagnostic: Option<String>,
}

impl<'de> Deserialize<'de> for GateConditionResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = GateConditionResultRepr::deserialize(deserializer)?;
        if !raw.threshold.is_finite() || raw.actual.is_some_and(|actual| !actual.is_finite()) {
            return Err(de::Error::custom(
                "gate threshold and actual must be finite",
            ));
        }
        if raw.metric.trim().is_empty() {
            return Err(de::Error::custom("gate metric must not be empty"));
        }
        Ok(Self {
            scope: raw.scope,
            metric: raw.metric,
            operator: raw.operator,
            threshold: raw.threshold,
            actual: raw.actual,
            status: raw.status,
            diagnostic: raw.diagnostic,
        })
    }
}

/// Versioned quality-gate result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateReport {
    pub schema_version: u32,
    pub status: GateStatus,
    pub conditions: Vec<GateConditionResult>,
    pub diagnostics: Vec<String>,
}

impl GateReport {
    /// Validates gate schema and finite numeric values.
    ///
    /// # Errors
    /// Returns [`AssessmentError::UnsupportedSchema`] for an unknown gate schema
    /// version or [`AssessmentError::Invalid`] when a condition, status, or
    /// numeric value violates gate invariants.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.schema_version != ASSESSMENT_SCHEMA_VERSION {
            return Err(AssessmentError::UnsupportedSchema {
                artifact: "gate",
                version: self.schema_version,
            });
        }
        let mut status = if self.conditions.is_empty() {
            GateStatus::Unavailable
        } else {
            GateStatus::Pass
        };
        for condition in &self.conditions {
            if condition.metric.trim().is_empty()
                || !condition.threshold.is_finite()
                || condition.threshold < 0.0
                || condition
                    .actual
                    .is_some_and(|actual| !actual.is_finite() || actual < 0.0)
                || (condition.status != GateStatus::Unavailable && condition.actual.is_none())
            {
                return Err(AssessmentError::Invalid {
                    artifact: "gate",
                    reason: "metric and finite threshold/actual are required".to_string(),
                });
            }
            if condition.status == GateStatus::Unavailable {
                status = GateStatus::Unavailable;
            } else if condition.status == GateStatus::Fail && status != GateStatus::Unavailable {
                status = GateStatus::Fail;
            }
        }
        if self.status != status {
            return Err(AssessmentError::Invalid {
                artifact: "gate",
                reason: "gate status differs from its condition outcomes".to_string(),
            });
        }
        Ok(())
    }
}

/// Complete optional assessment attached to a native analysis report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AssessmentReport {
    pub schema_version: u32,
    pub context: AnalysisContext,
    pub sources: Vec<SourceSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CoverageReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_code: Option<NewCodeReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate: Option<GateReport>,
}

#[derive(Deserialize)]
struct AssessmentReportRepr {
    schema_version: u32,
    context: AnalysisContext,
    sources: Vec<SourceSnapshot>,
    #[serde(default)]
    coverage: Option<CoverageReport>,
    #[serde(default)]
    new_code: Option<NewCodeReport>,
    #[serde(default)]
    gate: Option<GateReport>,
}

impl<'de> Deserialize<'de> for AssessmentReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = AssessmentReportRepr::deserialize(deserializer)?;
        let report = Self {
            schema_version: raw.schema_version,
            context: raw.context,
            sources: raw.sources,
            coverage: raw.coverage,
            new_code: raw.new_code,
            gate: raw.gate,
        };
        report.validate().map_err(de::Error::custom)?;
        Ok(report)
    }
}

impl AssessmentReport {
    /// Constructs an assessment from borrowed source inputs, avoiding a second
    /// source read or an intermediate source copy.
    ///
    /// # Errors
    /// Returns [`AssessmentError::InvalidPath`] for an unnormalizable report or
    /// source path, [`AssessmentError::DuplicatePath`] for duplicate normalized
    /// paths, [`AssessmentError::MissingSource`] when a report has no matching
    /// source bytes, [`AssessmentError::InvalidSource`] for invalid source
    /// bytes, or [`AssessmentError::Invalid`] for other invariants.
    pub fn from_reports_and_source_inputs(
        context: AnalysisContext,
        reports: &[crate::FileReport],
        sources: &[SourceInput<'_>],
    ) -> Result<Self, AssessmentError> {
        let mut report_by_path = BTreeMap::<PathBuf, &crate::FileReport>::new();
        for report in reports {
            let path = normalize_path(&report.path)?;
            if report_by_path.insert(path.clone(), report).is_some() {
                return Err(AssessmentError::DuplicatePath(path));
            }
        }

        let mut source_by_path = BTreeMap::<PathBuf, SourceInput<'_>>::new();
        for source in sources {
            let path = normalize_path(source.path)?;
            if source_by_path.insert(path.clone(), *source).is_some() {
                return Err(AssessmentError::DuplicatePath(path));
            }
        }
        for path in report_by_path.keys() {
            if !source_by_path.contains_key(path) {
                return Err(AssessmentError::MissingSource(path.clone()));
            }
        }

        let mut snapshots = Vec::with_capacity(source_by_path.len());
        for (path, source) in source_by_path {
            snapshots.push(SourceSnapshot::from_report(
                &path,
                source.content,
                report_by_path.get(&path).copied(),
            )?);
        }
        let report = Self {
            schema_version: ASSESSMENT_SCHEMA_VERSION,
            context,
            sources: snapshots,
            coverage: None,
            new_code: None,
            gate: None,
        };
        report.validate()?;
        Ok(report)
    }

    /// Creates an assessment from already-built snapshots.
    ///
    /// # Errors
    /// Returns [`AssessmentError::InvalidPath`] when a source path cannot be
    /// normalized or [`AssessmentError::Invalid`] when context, source, or
    /// ordering invariants fail.
    pub fn new(
        context: AnalysisContext,
        mut sources: Vec<SourceSnapshot>,
    ) -> Result<Self, AssessmentError> {
        sources.sort_by(|left, right| left.path.cmp(&right.path));
        let report = Self {
            schema_version: ASSESSMENT_SCHEMA_VERSION,
            context,
            sources,
            coverage: None,
            new_code: None,
            gate: None,
        };
        report.validate().map(|()| report)
    }

    /// Checks the complete assessment artifact without reading source files.
    ///
    /// # Errors
    /// Returns [`AssessmentError::UnsupportedSchema`] for unknown assessment
    /// versions, [`AssessmentError::InvalidPath`] for an unnormalizable path,
    /// or [`AssessmentError::Invalid`] when context, source ordering, or
    /// optional assessment invariants fail.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.schema_version != ASSESSMENT_SCHEMA_VERSION {
            return Err(AssessmentError::UnsupportedSchema {
                artifact: "assessment",
                version: self.schema_version,
            });
        }
        self.context.validate()?;
        let mut previous = None;
        for source in &self.sources {
            source.validate()?;
            if previous.is_some_and(|path: &PathBuf| path >= &source.path) {
                return Err(AssessmentError::Invalid {
                    artifact: "assessment",
                    reason: "sources must be sorted by unique normalized path".to_string(),
                });
            }
            previous = Some(&source.path);
        }
        if let Some(coverage) = &self.coverage {
            coverage.validate()?;
        }
        if let Some(new_code) = &self.new_code {
            new_code.validate()?;
        }
        if let Some(gate) = &self.gate {
            gate.validate()?;
        }
        Ok(())
    }

    /// Reconciles assessment identities with the native issue inventory.
    /// A complete-looking subset must not become a zero-finding gate or review.
    ///
    /// # Errors
    /// Returns [`AssessmentError::UnsupportedSchema`],
    /// [`AssessmentError::InvalidPath`], [`AssessmentError::DuplicatePath`],
    /// [`AssessmentError::MissingSource`], or [`AssessmentError::Invalid`] when
    /// the assessment, paths, or finding inventories violate their invariants.
    pub fn validate_against(&self, files: &[crate::FileReport]) -> Result<(), AssessmentError> {
        self.validate()?;
        let mut reports = BTreeMap::new();
        for report in files {
            let path = normalize_path(&report.path)?;
            if reports.insert(path.clone(), report).is_some() {
                return Err(AssessmentError::DuplicatePath(path));
            }
        }
        for source in &self.sources {
            let issues = reports
                .remove(&source.path)
                .map_or(&[][..], |report| report.issues.as_slice());
            if source.findings.len() != issues.len()
                || source.findings.iter().zip(issues).enumerate().any(
                    |(index, (finding, issue))| {
                        finding.issue_index != index
                            || finding.rule_key != issue.rule_key
                            || finding.message != issue.message
                            || finding.start_line != issue.range.start.line
                            || finding.end_line != issue.range.end.line
                    },
                )
            {
                return Err(AssessmentError::Invalid {
                    artifact: "assessment",
                    reason: format!(
                        "snapshot finding inventory differs from native report: {}",
                        source.path.display()
                    ),
                });
            }
        }
        if let Some((path, _)) = reports.first_key_value() {
            return Err(AssessmentError::MissingSource(path.clone()));
        }
        Ok(())
    }
}

/// Normalizes path spelling for identity and artifact matching.
///
/// Both slash styles are accepted, `.` segments and repeated separators are
/// removed, and traversal above a relative root is rejected. This is lexical
/// normalization only; no filesystem access or symlink resolution occurs.
///
/// # Errors
/// Returns [`AssessmentError::InvalidPath`] if `path` is not valid UTF-8, is
/// empty or contains NUL, or traverses above a relative root.
pub fn normalize_path(path: &Path) -> Result<PathBuf, AssessmentError> {
    let raw = path
        .to_str()
        .ok_or_else(|| AssessmentError::InvalidPath("path is not valid UTF-8".to_string()))?
        .to_string();
    if raw.is_empty() || raw.as_bytes().contains(&0) {
        return Err(AssessmentError::InvalidPath(raw));
    }
    let replaced = raw.replace('\\', "/");
    let (drive, rest) = split_drive_prefix(&replaced);
    let absolute = rest.starts_with('/');
    let components = normalized_path_components(rest, &replaced)?;
    let joined = components.join("/");
    Ok(build_normalized_path(drive, absolute, joined))
}

fn split_drive_prefix(path: &str) -> (Option<String>, &str) {
    let bytes = path.as_bytes();
    let drive = (bytes.len() >= 2 && bytes[1] == b':').then(|| path[..2].to_string());
    let rest = drive.as_ref().map_or(path, |drive| &path[drive.len()..]);
    (drive, rest)
}

fn normalized_path_components<'a>(
    rest: &'a str,
    invalid_path: &str,
) -> Result<Vec<&'a str>, AssessmentError> {
    let mut components = Vec::new();
    for component in rest.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(AssessmentError::InvalidPath(invalid_path.to_string()));
                }
            }
            value => components.push(value),
        }
    }
    Ok(components)
}

fn build_normalized_path(drive: Option<String>, absolute: bool, joined: String) -> PathBuf {
    let normalized = match drive {
        Some(drive) => normalized_drive_path(&drive, absolute, &joined),
        None => normalized_non_drive_path(absolute, joined),
    };
    PathBuf::from(normalized)
}

fn normalized_drive_path(drive: &str, absolute: bool, joined: &str) -> String {
    if absolute {
        if joined.is_empty() {
            format!("{drive}/")
        } else {
            format!("{drive}/{joined}")
        }
    } else if joined.is_empty() {
        format!("{drive}.")
    } else {
        format!("{drive}{joined}")
    }
}

fn normalized_non_drive_path(absolute: bool, joined: String) -> String {
    if absolute {
        if joined.is_empty() {
            "/".to_string()
        } else {
            format!("/{joined}")
        }
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

fn validate_finding(finding: &FindingIdentity) -> Result<(), AssessmentError> {
    if finding.rule_key.trim().is_empty()
        || !is_digest(&finding.source_digest)
        || !is_digest(&finding.context_digest)
        || !is_digest(&finding.identity)
        || ((finding.start_line == 0) != (finding.end_line == 0))
        || finding.start_line > finding.end_line
    {
        return Err(AssessmentError::Invalid {
            artifact: "finding identity",
            reason: "rule, digests, identity, and line range are invalid".to_string(),
        });
    }
    if finding.identity
        != digest_parts(&[
            b"finding",
            finding.rule_key.as_bytes(),
            finding.source_digest.as_bytes(),
            finding.context_digest.as_bytes(),
        ])
    {
        return Err(AssessmentError::Invalid {
            artifact: "finding identity",
            reason: "identity does not match its rule and source/context digests".to_string(),
        });
    }
    Ok(())
}

fn finding_identity(
    issue_index: usize,
    issue: &crate::Issue,
    text: &str,
    source: &[u8],
    line_starts: &[usize],
) -> Result<FindingIdentity, AssessmentError> {
    let range = issue.range.clone();
    let (start_line, end_line, source_digest, context_digest) = if range.is_file_level() {
        (
            0,
            0,
            digest_parts(&[b"file-level"]),
            digest_parts(&[b"context", without_final_line_ending(source)]),
        )
    } else {
        let start = position_to_offset(text, line_starts, range.start).ok_or_else(|| {
            AssessmentError::Invalid {
                artifact: "finding identity",
                reason: format!("finding {issue_index} starts outside source"),
            }
        })?;
        let end = position_to_offset(text, line_starts, range.end).ok_or_else(|| {
            AssessmentError::Invalid {
                artifact: "finding identity",
                reason: format!("finding {issue_index} ends outside source"),
            }
        })?;
        if start > end {
            return Err(AssessmentError::Invalid {
                artifact: "finding identity",
                reason: format!("finding {issue_index} has an inverted range"),
            });
        }
        let bytes = &source[start..end];
        let first_line =
            usize::try_from(range.start.line - 1).map_err(|_| AssessmentError::Invalid {
                artifact: "finding identity",
                reason: "source line exceeds the supported range".to_string(),
            })?;
        let after_last_line = usize::try_from(
            range.end.line - u32::from(range.end.column == 0 && range.end.line > range.start.line),
        )
        .map_err(|_| AssessmentError::Invalid {
            artifact: "finding identity",
            reason: "source line exceeds the supported range".to_string(),
        })?;
        let context_start = line_starts[first_line];
        let context_end = line_starts
            .get(after_last_line)
            .copied()
            .unwrap_or(source.len());
        (
            range.start.line,
            range.end.line,
            digest_parts(&[b"range", bytes]),
            digest_parts(&[
                b"context",
                without_final_line_ending(&source[context_start..context_end]),
            ]),
        )
    };
    let identity = digest_parts(&[
        b"finding",
        issue.rule_key.as_bytes(),
        source_digest.as_bytes(),
        context_digest.as_bytes(),
    ]);
    Ok(FindingIdentity {
        issue_index,
        rule_key: issue.rule_key.clone(),
        message: issue.message.clone(),
        source_digest,
        context_digest,
        start_line,
        end_line,
        identity,
        ambiguous: false,
    })
}

fn split_lines(source: &[u8]) -> impl Iterator<Item = &[u8]> {
    source.split_inclusive(|byte| *byte == b'\n').map(|line| {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        line.strip_suffix(b"\r").unwrap_or(line)
    })
}

fn position_to_offset(source: &str, starts: &[usize], pos: crate::Pos) -> Option<usize> {
    if pos.line == 0 {
        return None;
    }
    let line_index = usize::try_from(pos.line).ok()?.checked_sub(1)?;
    let bytes = source.as_bytes();
    let start = *starts.get(line_index)?;
    let next = starts.get(line_index + 1).copied().unwrap_or(bytes.len());
    let mut end = next;
    if end > start && bytes[end - 1] == b'\n' {
        end -= 1;
    }
    if end > start && bytes[end - 1] == b'\r' {
        end -= 1;
    }
    let content = source.get(start..end)?;
    let column = usize::try_from(pos.column).ok()?;
    content
        .char_indices()
        .map(|(offset, _)| start + offset)
        .chain(std::iter::once(start + content.len()))
        .nth(column)
}

fn without_final_line_ending(bytes: &[u8]) -> &[u8] {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    bytes.strip_suffix(b"\r").unwrap_or(bytes)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Computes the exact digest used for one source line in `line_digests`.
#[must_use]
pub fn line_digest(line: &[u8]) -> String {
    digest_parts(&[b"line", line.strip_suffix(b"\r").unwrap_or(line)])
}

fn digest_parts(parts: &[&[u8]]) -> String {
    let mut input = Sha256::new();
    input.update(b"hoonarqube-assessment\0");
    input.update(ASSESSMENT_SCHEMA_VERSION.to_be_bytes());
    input.update(crate::u32_saturating(parts.len()).to_be_bytes());
    for part in parts {
        input.update((part.len() as u64).to_be_bytes());
        input.update(part);
    }
    let digest = input.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_normalization_is_lexical_and_cross_platform() {
        assert_eq!(
            normalize_path(Path::new("./src\\./a.py")).expect("path"),
            PathBuf::from("src/a.py")
        );
        assert_eq!(
            normalize_path(Path::new("C:\\src\\a.py")).expect("path"),
            PathBuf::from("C:/src/a.py")
        );
        assert!(normalize_path(Path::new("../outside.py")).is_err());
    }

    #[test]
    fn coverage_counter_rejects_an_impossible_denominator() {
        assert!(CoverageCounter::new(1, 2).is_err());
        let json = r#"{"eligible":1,"covered":2}"#;
        assert!(serde_json::from_str::<CoverageCounter>(json).is_err());
    }

    fn identity_issue(line: u32, column: u32) -> crate::Issue {
        crate::Issue::new(
            "python:S1",
            "finding",
            crate::Range {
                start: crate::Pos { line, column },
                end: crate::Pos {
                    line,
                    column: column + 3,
                },
            },
        )
    }

    #[test]
    fn finding_identity_preserves_movement_but_not_changed_operands() {
        let original =
            SourceSnapshot::from_source("a.py", b"bad(1)\n", &[identity_issue(1, 0)]).unwrap();
        let moved =
            SourceSnapshot::from_source("renamed.py", b"\n\nbad(1)\n", &[identity_issue(3, 0)])
                .unwrap();
        let changed =
            SourceSnapshot::from_source("a.py", b"bad(2)\n", &[identity_issue(1, 0)]).unwrap();
        assert_eq!(original.findings[0].identity, moved.findings[0].identity);
        assert_ne!(original.findings[0].identity, changed.findings[0].identity);
        let unicode_lf =
            SourceSnapshot::from_source("a.py", "𝄞 bad(1)\n".as_bytes(), &[identity_issue(1, 2)])
                .unwrap();
        let unicode_crlf =
            SourceSnapshot::from_source("a.py", "𝄞 bad(1)\r\n".as_bytes(), &[identity_issue(1, 2)])
                .unwrap();
        assert_eq!(
            unicode_lf.findings[0].identity,
            unicode_crlf.findings[0].identity
        );
    }

    #[test]
    fn finding_identity_detects_changed_whitespace_inside_literals() {
        let original =
            SourceSnapshot::from_source("a.py", b"bad('a b')\n", &[identity_issue(1, 0)]).unwrap();
        let changed =
            SourceSnapshot::from_source("a.py", b"bad('a  b')\n", &[identity_issue(1, 0)]).unwrap();
        assert_ne!(original.findings[0].identity, changed.findings[0].identity);
    }

    #[test]
    fn line_inventory_excludes_eof_sentinel_but_preserves_real_blank_lines() {
        let empty = SourceSnapshot::from_source("empty.py", b"", &[]).unwrap();
        let source = SourceSnapshot::from_source("a.py", b"bad()\n\n", &[]).unwrap();
        assert_eq!(empty.line_digests, Vec::<String>::new());
        assert_eq!(
            source.line_digests,
            vec![line_digest(b"bad()"), line_digest(b"")]
        );
    }

    #[test]
    fn coverage_rejects_forged_totals_and_duplicate_measurements() {
        let mut report = CoverageReport {
            schema_version: 1,
            status: AssessmentStatus::Complete,
            files: vec![FileCoverage {
                path: PathBuf::from("a.py"),
                lines: vec![
                    LineCoverage {
                        line: 1,
                        covered: Some(false),
                        branches: None,
                    },
                    LineCoverage {
                        line: 2,
                        covered: None,
                        branches: Some(CoverageCounter {
                            eligible: 1,
                            covered: 1,
                        }),
                    },
                ],
            }],
            inputs: Vec::new(),
            lines: CoverageCounter {
                eligible: 1,
                covered: 0,
            },
            branches: CoverageCounter {
                eligible: 1,
                covered: 1,
            },
            diagnostics: Vec::new(),
        };
        report
            .validate()
            .expect("consistent branch-only and line measurements");
        report.lines.covered = 1;
        assert!(report.validate().is_err());
        report.lines.covered = 0;
        report.branches.covered = 0;
        assert!(report.validate().is_err());
        report.branches.covered = 1;
        let duplicate = report.files[0].lines[0].clone();
        report.files[0].lines.push(duplicate);
        assert!(report.validate().is_err());
    }

    #[test]
    fn native_finding_omission_cannot_validate_as_an_empty_assessment() {
        let native = crate::FileReport {
            path: PathBuf::from("a.py"),
            language: "python".to_string(),
            issues: vec![identity_issue(1, 0)],
            metrics: crate::FileMetrics {
                lines: 1,
                code_lines: 1,
                comment_lines: 0,
            },
        };
        let context =
            AnalysisContext::new("test/v1", "catalog", "options", "scope", None::<String>);
        let source = SourceSnapshot::from_report("a.py", b"bad()\n", Some(&native)).unwrap();
        let mut assessment = AssessmentReport::new(context, vec![source]).unwrap();
        assessment
            .validate_against(std::slice::from_ref(&native))
            .expect("complete inventory");
        assessment.sources[0].findings.clear();
        assert!(
            assessment
                .validate_against(std::slice::from_ref(&native))
                .is_err()
        );
    }

    #[test]
    fn analysis_context_validation_preserves_unknown_revision_semantics() {
        let valid = AnalysisContext::new("analyzer", "catalog", "options", "scope", None::<String>);
        assert!(valid.validate().is_ok());
        let other_revision = AnalysisContext::new(
            "analyzer",
            "catalog",
            "options",
            "scope",
            Some("different-revision"),
        );
        assert!(valid.compatible_with(&other_revision));
        let other_options = AnalysisContext::new(
            "analyzer",
            "catalog",
            "different-options",
            "scope",
            None::<String>,
        );
        assert!(!valid.compatible_with(&other_options));

        let invalid_contexts = [
            AnalysisContext::new("", "catalog", "options", "scope", None::<String>),
            AnalysisContext::new("analyzer", " ", "options", "scope", None::<String>),
            AnalysisContext::new("analyzer", "catalog", "\t", "scope", None::<String>),
            AnalysisContext::new("analyzer", "catalog", "options", "\n", None::<String>),
            AnalysisContext::new("analyzer", "catalog", "options", "scope", Some(" ")),
        ];
        for context in &invalid_contexts {
            assert!(context.validate().is_err());
        }

        let mut report = AssessmentReport::new(valid.clone(), Vec::new()).expect("report");
        report.context.scope_digest.clear();
        assert!(report.validate().is_err());

        let new_code = NewCodeReport {
            schema_version: ASSESSMENT_SCHEMA_VERSION,
            status: AssessmentStatus::Complete,
            reference_context: Some(invalid_contexts[0].clone()),
            findings: Vec::new(),
            resolved: Vec::new(),
            lines: Vec::new(),
            diagnostics: Vec::new(),
        };
        assert!(new_code.validate().is_err());
    }
}
