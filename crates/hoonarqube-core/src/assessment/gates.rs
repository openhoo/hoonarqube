//! Strict, fail-closed metric quality-gate evaluation.
//!
//! Gate configuration is deliberately kept separate from the report IR.  The
//! report owns the stable artifact/result types; this module owns the small
//! typed input API and the metric derivations that can be proved from that
//! artifact.  A gate never turns missing or partial data into a zero.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use hoonarqube_ir::assessment::{
    ASSESSMENT_SCHEMA_VERSION, AssessmentStatus, FindingStatus, GateConditionResult, GateOperator,
    GateReport, GateScope, GateStatus,
};
use hoonarqube_ir::{AnalysisReport, FileClassification, MeasurementStatus};

/// The version accepted by [`evaluate_gate`].
pub const GATE_CONFIG_SCHEMA_VERSION: u32 = 1;
/// The version emitted by [`evaluate_gate`].
pub const GATE_REPORT_SCHEMA_VERSION: u32 = ASSESSMENT_SCHEMA_VERSION;

/// Metric names supported by this evaluator, in stable display order.
///
/// A metric is not implicitly available in every scope.  See
/// [`metric_supported`] for the exact scope matrix.
pub const SUPPORTED_METRICS: &[&str] = &[
    "files",
    "lines",
    "code_lines",
    "comment_lines",
    "issues",
    "duplicated_lines",
    "duplicated_blocks",
    "duplicated_files",
    "duplicated_lines_density",
    "line_coverage",
    "branch_coverage",
];

/// Versioned metric gate configuration.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateConfig {
    pub schema_version: u32,
    pub conditions: Vec<GateCondition>,
}

/// One typed metric comparison.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateCondition {
    pub scope: GateScope,
    pub metric: String,
    pub operator: GateOperator,
    pub threshold: f64,
}

impl GateCondition {
    /// Validates the metric/operator/scope tuple without reading a report.
    ///
    /// # Errors
    ///
    /// Returns an error when the threshold is non-finite or negative, the
    /// metric is unknown, or the metric is unsupported for the configured
    /// scope.
    pub fn validate(&self) -> Result<(), String> {
        if !self.threshold.is_finite() {
            return Err("gate threshold must be finite".to_string());
        }
        if self.threshold < 0.0 {
            return Err("gate threshold must not be negative".to_string());
        }
        if !SUPPORTED_METRICS.contains(&self.metric.as_str()) {
            return Err(format!(
                "unknown gate metric {:?}; supported metrics: {}",
                self.metric,
                SUPPORTED_METRICS.join(", ")
            ));
        }
        if !metric_supported(&self.scope, &self.metric) {
            return Err(format!(
                "metric {:?} is not supported for {:?} scope",
                self.metric, self.scope
            ));
        }
        Ok(())
    }
}

impl GateConfig {
    /// Validates the version and all statically checkable conditions.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema version is unsupported, no conditions
    /// are configured, or any configured condition is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != GATE_CONFIG_SCHEMA_VERSION {
            return Err(format!(
                "unsupported gate configuration schema_version {}; expected {}",
                self.schema_version, GATE_CONFIG_SCHEMA_VERSION
            ));
        }
        if self.conditions.is_empty() {
            return Err("gate configuration must contain at least one condition".to_string());
        }
        for condition in &self.conditions {
            condition.validate()?;
        }
        Ok(())
    }
}

/// Returns the stable list of supported metric names.
#[must_use]
pub const fn supported_metrics() -> &'static [&'static str] {
    SUPPORTED_METRICS
}

/// Returns whether a metric has an exact derivation in the requested scope.
///
/// `code_lines` and `comment_lines` are not derivable for `NewCode` because the
/// IR supplies changed line sets, but not a code/comment classification for
/// every changed line.  Coverage and duplication are scoped only through their
/// corresponding line/range records, never by reusing project totals.
#[must_use]
pub fn metric_supported(scope: &GateScope, metric: &str) -> bool {
    match scope {
        GateScope::Overall => matches!(
            metric,
            "files"
                | "lines"
                | "code_lines"
                | "comment_lines"
                | "issues"
                | "duplicated_lines"
                | "duplicated_blocks"
                | "duplicated_files"
                | "duplicated_lines_density"
                | "line_coverage"
                | "branch_coverage"
        ),
        GateScope::NewCode => matches!(
            metric,
            "files"
                | "lines"
                | "issues"
                | "duplicated_lines"
                | "duplicated_blocks"
                | "duplicated_files"
                | "duplicated_lines_density"
                | "line_coverage"
                | "branch_coverage"
        ),
    }
}

/// Evaluates every configured condition and aggregates its result.
///
/// Configuration errors and unavailable measurements are represented by an
/// `Unavailable` report rather than an error or a fabricated zero.  `Fail`
/// remains distinct from `Unavailable`, allowing the CLI to preserve its
/// exit-code contract.  Conditions are evaluated in configuration order and
/// diagnostics are emitted in that same order.
#[must_use]
pub fn evaluate_gate(config: &GateConfig, report: &AnalysisReport) -> GateReport {
    let mut conditions = Vec::with_capacity(config.conditions.len());
    let mut diagnostics = Vec::new();

    if config.schema_version != GATE_CONFIG_SCHEMA_VERSION {
        let diagnostic = format!(
            "unsupported gate configuration schema_version {}; expected {}",
            config.schema_version, GATE_CONFIG_SCHEMA_VERSION
        );
        diagnostics.push(diagnostic.clone());
        conditions.extend(
            config
                .conditions
                .iter()
                .map(|condition| unavailable_condition(condition, diagnostic.clone())),
        );
        return GateReport {
            schema_version: GATE_REPORT_SCHEMA_VERSION,
            status: GateStatus::Unavailable,
            conditions,
            diagnostics,
        };
    }

    if config.conditions.is_empty() {
        diagnostics.push("gate configuration must contain at least one condition".to_string());
        return GateReport {
            schema_version: GATE_REPORT_SCHEMA_VERSION,
            status: GateStatus::Unavailable,
            conditions,
            diagnostics,
        };
    }

    if report.schema_version != 1 {
        let diagnostic = format!(
            "unsupported analysis report schema_version {}; expected 1",
            report.schema_version
        );
        diagnostics.push(diagnostic.clone());
        conditions.extend(
            config
                .conditions
                .iter()
                .map(|condition| unavailable_condition(condition, diagnostic.clone())),
        );
        return GateReport {
            schema_version: GATE_REPORT_SCHEMA_VERSION,
            status: GateStatus::Unavailable,
            conditions,
            diagnostics,
        };
    }

    for condition in &config.conditions {
        let result = evaluate_condition(condition, report);
        if let Some(diagnostic) = result.diagnostic.as_ref() {
            diagnostics.push(diagnostic.clone());
        }
        conditions.push(result);
    }

    let status = if conditions
        .iter()
        .any(|condition| condition.status == GateStatus::Unavailable)
    {
        GateStatus::Unavailable
    } else if conditions
        .iter()
        .any(|condition| condition.status == GateStatus::Fail)
    {
        GateStatus::Fail
    } else {
        GateStatus::Pass
    };

    GateReport {
        schema_version: GATE_REPORT_SCHEMA_VERSION,
        status,
        conditions,
        diagnostics,
    }
}

fn evaluate_condition(condition: &GateCondition, report: &AnalysisReport) -> GateConditionResult {
    let mut result = GateConditionResult {
        scope: condition.scope,
        metric: condition.metric.clone(),
        operator: condition.operator,
        threshold: safe_threshold(condition.threshold),
        actual: None,
        status: GateStatus::Unavailable,
        diagnostic: None,
    };

    if let Err(diagnostic) = condition.validate() {
        result.diagnostic = Some(diagnostic);
        return result;
    }

    let value = match &condition.scope {
        GateScope::Overall => overall_metric(&condition.metric, report),
        GateScope::NewCode => new_code_metric(&condition.metric, report),
    };
    let value = match value {
        Ok(value) => value,
        Err(diagnostic) => {
            result.diagnostic = Some(diagnostic);
            return result;
        }
    };

    if !value.is_finite() {
        result.diagnostic = Some("derived gate metric is non-finite".to_string());
        return result;
    }
    result.actual = Some(value.as_f64());

    if value.meets(condition.operator, condition.threshold) {
        result.status = GateStatus::Pass;
    } else {
        result.status = GateStatus::Fail;
        result.diagnostic = Some(format!(
            "actual {} does not satisfy {} {} for {}",
            format_number(value.as_f64()),
            operator_text(condition.operator),
            format_number(condition.threshold),
            condition.metric
        ));
    }
    result
}

fn unavailable_condition(condition: &GateCondition, diagnostic: String) -> GateConditionResult {
    GateConditionResult {
        scope: condition.scope,
        metric: condition.metric.clone(),
        operator: condition.operator,
        threshold: safe_threshold(condition.threshold),
        actual: None,
        status: GateStatus::Unavailable,
        diagnostic: Some(diagnostic),
    }
}

#[derive(Debug, Clone, Copy)]
enum MetricValue {
    Count(u64),
    Percentage(f64),
}

fn usize_as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn counter_as_f64(value: u64) -> f64 {
    let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(value & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

impl MetricValue {
    fn as_f64(self) -> f64 {
        match self {
            Self::Count(value) => counter_as_f64(value),
            Self::Percentage(value) => value,
        }
    }

    fn is_finite(self) -> bool {
        match self {
            Self::Count(_) => true,
            Self::Percentage(value) => value.is_finite(),
        }
    }

    fn meets(self, operator: GateOperator, threshold: f64) -> bool {
        match self {
            Self::Count(value) => {
                let ordering = compare_u64_f64(value, threshold);
                compare_ordering(ordering, operator)
            }
            Self::Percentage(value) => compare_ordering(
                value.partial_cmp(&threshold).unwrap_or(Ordering::Greater),
                operator,
            ),
        }
    }
}

fn compare_ordering(ordering: Ordering, operator: GateOperator) -> bool {
    match operator {
        GateOperator::Lt => ordering == Ordering::Less,
        GateOperator::Lte => ordering != Ordering::Greater,
        GateOperator::Eq => ordering == Ordering::Equal,
        GateOperator::Gte => ordering != Ordering::Less,
        GateOperator::Gt => ordering == Ordering::Greater,
    }
}

fn operator_text(operator: GateOperator) -> &'static str {
    match operator {
        GateOperator::Lt => "<",
        GateOperator::Lte => "<=",
        GateOperator::Eq => "=",
        GateOperator::Gte => ">=",
        GateOperator::Gt => ">",
    }
}

fn overall_metric(metric: &str, report: &AnalysisReport) -> Result<MetricValue, String> {
    if !report.project.complete {
        return Err(
            "project analysis is incomplete; overall gate metric is unavailable".to_string(),
        );
    }

    let metrics = &report.project.metrics;
    match metric {
        "files" => Ok(MetricValue::Count(metrics.files)),
        "lines" => Ok(MetricValue::Count(metrics.lines)),
        "code_lines" => Ok(MetricValue::Count(metrics.code_lines)),
        "comment_lines" => Ok(MetricValue::Count(metrics.comment_lines)),
        "issues" => Ok(MetricValue::Count(
            report
                .files
                .iter()
                .map(|file| usize_as_u64(file.issues.len()))
                .sum(),
        )),
        "duplicated_lines" => duplication_counter(report, |metrics| metrics.duplicated_lines),
        "duplicated_blocks" => duplication_counter(report, |metrics| metrics.duplicated_blocks),
        "duplicated_files" => duplication_counter(report, |metrics| metrics.duplicated_files),
        "duplicated_lines_density" => {
            let duplication = complete_duplication(report)?;
            let density = duplication
                .duplicated_lines_density
                .ok_or_else(|| "duplication density has no denominator".to_string())?;
            if density.is_finite() && (0.0..=100.0).contains(&density) {
                Ok(MetricValue::Percentage(density))
            } else {
                Err("duplication density is invalid or non-finite".to_string())
            }
        }
        "line_coverage" => {
            let coverage = complete_coverage(report)?;
            percentage_counter(
                coverage.lines.eligible,
                coverage.lines.covered,
                "line coverage",
            )
        }
        "branch_coverage" => {
            let coverage = complete_coverage(report)?;
            percentage_counter(
                coverage.branches.eligible,
                coverage.branches.covered,
                "branch coverage",
            )
        }
        _ => Err("unsupported overall gate metric".to_string()),
    }
}

fn new_code_metric(metric: &str, report: &AnalysisReport) -> Result<MetricValue, String> {
    if !report.project.complete {
        return Err(
            "project analysis is incomplete; new-code gate metric is unavailable".to_string(),
        );
    }
    let new_code = complete_new_code(report)?;
    let line_sets = new_code_line_sets(new_code)?;
    let scoped_line_count = validate_new_line_sets(report, &line_sets)?;
    match metric {
        "files" => Ok(MetricValue::Count(usize_as_u64(line_sets.len()))),
        "lines" => Ok(MetricValue::Count(scoped_line_count)),
        "issues" => {
            if new_code
                .findings
                .iter()
                .any(|finding| matches!(&finding.status, FindingStatus::Uncertain))
            {
                return Err(
                    "new-code finding identities are uncertain; issue count is unavailable"
                        .to_string(),
                );
            }
            Ok(MetricValue::Count(usize_as_u64(
                new_code
                    .findings
                    .iter()
                    .filter(|finding| matches!(&finding.status, FindingStatus::New))
                    .count(),
            )))
        }
        "line_coverage" => {
            let coverage = complete_coverage(report)?;
            let (eligible, covered) = scoped_line_coverage(coverage, &line_sets)?;
            percentage_counter(eligible, covered, "new-code line coverage")
        }
        "branch_coverage" => {
            let coverage = complete_coverage(report)?;
            let (eligible, covered) = scoped_branch_coverage(coverage, &line_sets)?;
            percentage_counter(eligible, covered, "new-code branch coverage")
        }
        "duplicated_lines" => {
            let scoped = scoped_duplication(report, &line_sets)?;
            Ok(MetricValue::Count(scoped.duplicated_lines))
        }
        "duplicated_blocks" => {
            let scoped = scoped_duplication(report, &line_sets)?;
            Ok(MetricValue::Count(scoped.duplicated_blocks))
        }
        "duplicated_files" => {
            let scoped = scoped_duplication(report, &line_sets)?;
            Ok(MetricValue::Count(scoped.duplicated_files))
        }
        "duplicated_lines_density" => {
            let scoped = scoped_duplication(report, &line_sets)?;
            percentage_counter(
                scoped.denominator,
                scoped.duplicated_lines,
                "new-code duplication density",
            )
        }
        _ => Err("unsupported new-code gate metric".to_string()),
    }
}

fn duplication_counter(
    report: &AnalysisReport,
    select: impl Fn(&hoonarqube_ir::DuplicationMetrics) -> u64,
) -> Result<MetricValue, String> {
    let duplication = complete_duplication(report)?;
    Ok(MetricValue::Count(select(duplication)))
}

fn complete_duplication(
    report: &AnalysisReport,
) -> Result<&hoonarqube_ir::DuplicationMetrics, String> {
    if !report.project.complete {
        return Err(
            "duplication is unavailable because the project analysis is incomplete".to_string(),
        );
    }
    report
        .project
        .duplication
        .as_ref()
        .ok_or_else(|| "duplication metrics are unavailable".to_string())
}

fn complete_coverage(
    report: &AnalysisReport,
) -> Result<&hoonarqube_ir::assessment::CoverageReport, String> {
    let assessment = report
        .assessment
        .as_ref()
        .ok_or_else(|| "coverage is unavailable because no assessment is attached".to_string())?;
    if assessment.schema_version != 1 {
        return Err(format!(
            "assessment schema_version {} is unsupported",
            assessment.schema_version
        ));
    }
    let coverage = assessment
        .coverage
        .as_ref()
        .ok_or_else(|| "coverage report is missing".to_string())?;
    if coverage.schema_version != 1 {
        return Err(format!(
            "coverage schema_version {} is unsupported",
            coverage.schema_version
        ));
    }
    if coverage.status != AssessmentStatus::Complete {
        return Err(format!(
            "coverage status is {:?}, not complete",
            coverage.status
        ));
    }
    coverage
        .validate()
        .map_err(|error| format!("coverage artifact is invalid: {error}"))?;
    validate_counter(
        coverage.lines.eligible,
        coverage.lines.covered,
        "line coverage",
    )?;
    validate_counter(
        coverage.branches.eligible,
        coverage.branches.covered,
        "branch coverage",
    )?;
    Ok(coverage)
}

fn complete_new_code(
    report: &AnalysisReport,
) -> Result<&hoonarqube_ir::assessment::NewCodeReport, String> {
    let assessment = report.assessment.as_ref().ok_or_else(|| {
        "new-code data is unavailable because no assessment is attached".to_string()
    })?;
    if assessment.schema_version != 1 {
        return Err(format!(
            "assessment schema_version {} is unsupported",
            assessment.schema_version
        ));
    }
    assessment
        .validate_against(&report.files)
        .map_err(|error| format!("assessment inventory is invalid: {error}"))?;
    let new_code = assessment
        .new_code
        .as_ref()
        .ok_or_else(|| "new-code report is missing; baseline is unavailable".to_string())?;
    if new_code.schema_version != 1 {
        return Err(format!(
            "new-code schema_version {} is unsupported",
            new_code.schema_version
        ));
    }
    if new_code.status != AssessmentStatus::Complete {
        return Err(format!(
            "new-code status is {:?}; a valid baseline is required",
            new_code.status
        ));
    }
    new_code
        .validate()
        .map_err(|error| format!("new-code artifact is invalid: {error}"))?;
    let reference_context = new_code
        .reference_context
        .as_ref()
        .ok_or_else(|| "new-code baseline context is missing".to_string())?;
    if !reference_context.compatible_with(&assessment.context) {
        return Err(
            "new-code baseline context is incompatible with the current assessment".to_string(),
        );
    }
    validate_current_finding_matches(assessment, new_code)?;
    Ok(new_code)
}

fn validate_current_finding_matches(
    assessment: &hoonarqube_ir::assessment::AssessmentReport,
    new_code: &hoonarqube_ir::assessment::NewCodeReport,
) -> Result<(), String> {
    let mut expected = BTreeSet::new();
    for source in &assessment.sources {
        for finding in &source.findings {
            let issue_index = finding.issue_index;
            let key = (source.path.clone(), issue_index, finding.identity.clone());
            if !expected.insert(key) {
                return Err(format!(
                    "assessment contains duplicate current source finding \"{}\" index {issue_index}",
                    source.path.to_string_lossy().escape_debug()
                ));
            }
        }
    }
    let mut observed = BTreeSet::new();
    for finding in &new_code.findings {
        let key = (
            finding.path.clone(),
            finding.issue_index,
            finding.identity.clone(),
        );
        let path = &key.0;
        let issue_index = key.1;
        if !observed.insert(key.clone()) {
            return Err(format!(
                "new-code findings contain duplicate current finding \"{}\" index {issue_index}",
                path.to_string_lossy().escape_debug()
            ));
        }
        if !expected.contains(&key) {
            return Err(format!(
                "new-code finding \"{}\" index {issue_index} does not match a current source finding",
                path.to_string_lossy().escape_debug()
            ));
        }
    }
    if let Some((path, issue_index, _identity)) = expected.difference(&observed).next() {
        return Err(format!(
            "new-code findings omit current source finding \"{}\" index {issue_index}",
            path.to_string_lossy().escape_debug()
        ));
    }
    Ok(())
}

fn percentage_counter(eligible: u64, covered: u64, name: &str) -> Result<MetricValue, String> {
    validate_counter(eligible, covered, name)?;
    if eligible == 0 {
        return Err(format!("{name} has no denominator"));
    }
    let value = counter_as_f64(covered) * 100.0 / counter_as_f64(eligible);
    if value.is_finite() {
        Ok(MetricValue::Percentage(value))
    } else {
        Err(format!("{name} is non-finite"))
    }
}

fn validate_counter(eligible: u64, covered: u64, name: &str) -> Result<(), String> {
    if covered > eligible {
        Err(format!("{name} covered counter exceeds eligible counter"))
    } else {
        Ok(())
    }
}

fn new_code_line_sets(
    new_code: &hoonarqube_ir::assessment::NewCodeReport,
) -> Result<BTreeMap<PathBuf, BTreeSet<u32>>, String> {
    let mut sets = BTreeMap::new();
    for entry in &new_code.lines {
        let lines = sets.entry(entry.path.clone()).or_insert_with(BTreeSet::new);
        for &line in &entry.lines {
            if line == 0 {
                return Err("new-code line sets must use one-based line numbers".to_string());
            }
            lines.insert(line);
        }
    }
    sets.retain(|_, lines| !lines.is_empty());
    // An unchanged complete baseline has no new-code lines. Count metrics
    // still have a defined zero value; denominator-based metrics reject the
    // empty scope at their own derivation boundary.
    Ok(sets)
}

#[derive(Debug, Clone, Copy)]
struct ScopedDuplication {
    duplicated_lines: u64,
    duplicated_blocks: u64,
    duplicated_files: u64,
    denominator: u64,
}

fn scoped_duplication(
    report: &AnalysisReport,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<ScopedDuplication, String> {
    let _ = complete_duplication(report)?;
    validate_new_line_sets(report, line_sets)?;
    let denominator = duplication_line_denominator(report, line_sets)?;
    let mut duplicated_lines = BTreeSet::new();
    let mut duplicated_blocks = BTreeSet::new();
    let mut duplicated_files = BTreeSet::new();

    for group in &report.project.duplications {
        for occurrence in &group.occurrences {
            collect_scoped_occurrence(
                occurrence,
                line_sets,
                &mut duplicated_lines,
                &mut duplicated_blocks,
                &mut duplicated_files,
            )?;
        }
    }

    Ok(ScopedDuplication {
        duplicated_lines: usize_as_u64(duplicated_lines.len()),
        duplicated_blocks: usize_as_u64(duplicated_blocks.len()),
        duplicated_files: usize_as_u64(duplicated_files.len()),
        denominator,
    })
}

fn collect_scoped_occurrence(
    occurrence: &hoonarqube_ir::DuplicateOccurrence,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
    duplicated_lines: &mut BTreeSet<(PathBuf, u32)>,
    duplicated_blocks: &mut BTreeSet<(PathBuf, u32, u32, u32, u32)>,
    duplicated_files: &mut BTreeSet<PathBuf>,
) -> Result<(), String> {
    if occurrence.start_line == 0 || occurrence.end_line < occurrence.start_line {
        return Err(format!(
            "duplication occurrence range is invalid for \"{}\"",
            occurrence.path.to_string_lossy().escape_debug()
        ));
    }
    let Some(lines) = line_sets.get(&occurrence.path) else {
        return Ok(());
    };
    let covered = (occurrence.start_line..=occurrence.end_line).any(|line| lines.contains(&line));
    if !covered {
        return Ok(());
    }
    duplicated_blocks.insert((
        occurrence.path.clone(),
        occurrence.start_line,
        occurrence.end_line,
        occurrence.start_byte,
        occurrence.end_byte,
    ));
    duplicated_files.insert(occurrence.path.clone());
    for line in occurrence.start_line..=occurrence.end_line {
        if lines.contains(&line) {
            duplicated_lines.insert((occurrence.path.clone(), line));
        }
    }
    Ok(())
}

fn validate_new_line_sets(
    report: &AnalysisReport,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<u64, String> {
    let mut denominator = 0_u64;
    for (path, lines) in line_sets {
        let measurement = report
            .project
            .files
            .iter()
            .find(|file| file.path == *path)
            .ok_or_else(|| {
                format!(
                    "new-code path \"{}\" is absent from project inventory",
                    path.to_string_lossy().escape_debug()
                )
            })?;
        if !matches!(
            measurement.classification,
            FileClassification::Source | FileClassification::Test
        ) || measurement.status != MeasurementStatus::Complete
        {
            return Err(format!(
                "new-code path \"{}\" is not a complete analyzed file",
                path.to_string_lossy().escape_debug()
            ));
        }
        let file_lines = u64::from(
            measurement
                .metrics
                .as_ref()
                .ok_or_else(|| {
                    format!(
                        "new-code path \"{}\" has no file metrics",
                        path.to_string_lossy().escape_debug()
                    )
                })?
                .lines,
        );
        for &line in lines {
            if u64::from(line) > file_lines {
                return Err(format!(
                    "new-code line {line} is outside the measured file \"{}\"",
                    path.to_string_lossy().escape_debug()
                ));
            }
            denominator = denominator
                .checked_add(1)
                .ok_or_else(|| "new-code line denominator overflows u64".to_string())?;
        }
    }
    // An empty complete scope is valid for count metrics.
    Ok(denominator)
}
fn duplication_line_denominator(
    report: &AnalysisReport,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<u64, String> {
    let mut denominator = 0_u64;
    for (path, lines) in line_sets {
        let measurement = report
            .project
            .files
            .iter()
            .find(|file| file.path == *path)
            .ok_or_else(|| {
                format!(
                    "new-code path \"{}\" is absent from project inventory",
                    path.to_string_lossy().escape_debug()
                )
            })?;
        if measurement.classification != FileClassification::Source
            || measurement.duplication.is_none()
        {
            continue;
        }
        denominator = denominator
            .checked_add(usize_as_u64(lines.len()))
            .ok_or_else(|| "new-code duplication denominator overflows u64".to_string())?;
    }
    // An empty complete scope has no density denominator.
    Ok(denominator)
}

fn scoped_line_coverage(
    coverage: &hoonarqube_ir::assessment::CoverageReport,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<(u64, u64), String> {
    validate_scoped_coverage_entries(coverage, line_sets)?;
    if coverage.lines.eligible == 0 {
        return Err("new-code line coverage has no global denominator".to_string());
    }
    let mut eligible = 0_u64;
    let mut covered = 0_u64;
    for file in &coverage.files {
        let Some(lines) = line_sets.get(&file.path) else {
            continue;
        };
        for line in &file.lines {
            if !lines.contains(&line.line) {
                continue;
            }
            let Some(covered_line) = line.covered else {
                continue;
            };
            eligible = eligible
                .checked_add(1)
                .ok_or_else(|| "new-code line denominator overflows u64".to_string())?;
            if covered_line {
                covered = covered
                    .checked_add(1)
                    .ok_or_else(|| "new-code covered line counter overflows u64".to_string())?;
            }
        }
    }
    Ok((eligible, covered))
}

fn scoped_branch_coverage(
    coverage: &hoonarqube_ir::assessment::CoverageReport,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<(u64, u64), String> {
    validate_scoped_coverage_entries(coverage, line_sets)?;
    let mut eligible = 0_u64;
    let mut covered = 0_u64;
    for file in &coverage.files {
        let Some(lines) = line_sets.get(&file.path) else {
            continue;
        };
        for line in &file.lines {
            if !lines.contains(&line.line) {
                continue;
            }
            if let Some(branches) = line.branches.as_ref() {
                validate_counter(
                    branches.eligible,
                    branches.covered,
                    "new-code branch coverage",
                )?;
                eligible = eligible
                    .checked_add(branches.eligible)
                    .ok_or_else(|| "new-code branch denominator overflows u64".to_string())?;
                covered = covered
                    .checked_add(branches.covered)
                    .ok_or_else(|| "new-code covered branch counter overflows u64".to_string())?;
            }
        }
    }
    Ok((eligible, covered))
}

fn validate_scoped_coverage_entries(
    coverage: &hoonarqube_ir::assessment::CoverageReport,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<(), String> {
    if line_sets.is_empty() {
        return Err("new-code scope is empty".to_string());
    }
    let mut entries = BTreeSet::new();
    for file in &coverage.files {
        for line in &file.lines {
            if !entries.insert((file.path.clone(), line.line)) {
                return Err(format!(
                    "coverage contains duplicate line {} for \"{}\"",
                    line.line,
                    file.path.to_string_lossy().escape_debug()
                ));
            }
        }
    }
    for (path, lines) in line_sets {
        for &line in lines {
            if !entries.contains(&(path.clone(), line)) {
                return Err(format!(
                    "coverage has no entry for new-code line {line} in \"{}\"",
                    path.to_string_lossy().escape_debug()
                ));
            }
        }
    }
    Ok(())
}

/// Exact ordering between a non-negative `u64` counter and a finite `f64`.
///
/// Casting a large counter to `f64` can round `u64::MAX` to `2^64`, changing a
/// boundary comparison.  Decode the binary float instead, retaining exact
/// integer semantics for count metrics while still accepting fractional
/// thresholds.
fn compare_u64_f64(value: u64, threshold: f64) -> Ordering {
    debug_assert!(threshold.is_finite());
    if threshold.is_nan() {
        return Ordering::Greater;
    }
    if threshold < 0.0 {
        return Ordering::Greater;
    }
    if threshold == 0.0 {
        return value.cmp(&0);
    }

    let bits = threshold.to_bits();
    let exponent = i32::try_from((bits >> 52) & 0x7ff).unwrap_or(0);
    let fraction = bits & ((1_u64 << 52) - 1);
    if exponent == 0 {
        // Positive subnormal values are strictly between zero and one.
        return if value == 0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let unbiased_exponent = exponent - 1023;

    let significand = (1_u128 << 52) | u128::from(fraction);
    let shift = unbiased_exponent - 52;
    if shift >= 64 {
        // Even the smallest value with this exponent is greater than every
        // u64 counter; avoid an overflowing u128 shift for huge f64 values.
        return Ordering::Less;
    }
    if shift >= 0 {
        let threshold_integer = significand << usize::try_from(shift).unwrap_or(0);
        return u128::from(value).cmp(&threshold_integer);
    }

    let right_shift = usize::try_from(-shift).unwrap_or(usize::MAX);
    if right_shift >= 128 {
        return if value == 0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let denominator = 1_u128 << right_shift;
    let floor = significand / denominator;
    match u128::from(value).cmp(&floor) {
        Ordering::Less => Ordering::Less,
        Ordering::Greater => Ordering::Greater,
        Ordering::Equal => {
            if significand.is_multiple_of(denominator) {
                Ordering::Equal
            } else {
                Ordering::Less
            }
        }
    }
}

fn safe_threshold(value: f64) -> f64 {
    if value.is_finite() { value } else { 0.0 }
}

fn format_number(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.12}")
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{GateCondition, GateConfig, compare_u64_f64, evaluate_gate};
    use hoonarqube_ir::assessment::{
        AssessmentReport, AssessmentStatus, CoverageCounter, CoverageReport, FileCoverage,
        FindingMatch, FindingStatus, GateOperator, GateScope, GateStatus, LineCoverage,
        NewCodeLines, NewCodeReport, SourceSnapshot,
    };
    use hoonarqube_ir::{
        AnalysisReport, DuplicationMetrics, FileClassification, FileMetrics, FileReport, Issue,
        MeasurementStatus, Pos, ProjectFileMeasurement, ProjectMetrics, ProjectReport, Range,
    };
    use std::cmp::Ordering;
    use std::path::PathBuf;

    fn context() -> hoonarqube_ir::assessment::AnalysisContext {
        hoonarqube_ir::assessment::AnalysisContext::new(
            "analyzer",
            "catalog",
            "options",
            "scope",
            None::<String>,
        )
    }

    fn project_file(path: &str, lines: u32) -> ProjectFileMeasurement {
        ProjectFileMeasurement {
            path: PathBuf::from(path),
            classification: FileClassification::Source,
            status: MeasurementStatus::Complete,
            metrics: Some(FileMetrics {
                lines,
                code_lines: lines,
                comment_lines: 0,
            }),
            duplication: Some(DuplicationMetrics {
                duplicated_lines: 0,
                duplicated_blocks: 0,
                duplicated_files: 0,
                duplicated_lines_density: Some(0.0),
            }),
            reason: None,
        }
    }

    fn current_issue_file_report() -> FileReport {
        FileReport {
            path: PathBuf::from("src/main.rs"),
            language: "rust".to_string(),
            issues: vec![Issue {
                rule_key: "rule".to_string(),
                message: "message".to_string(),
                range: Range {
                    start: Pos { line: 1, column: 0 },
                    end: Pos { line: 1, column: 1 },
                },
                fix: None,
                alternatives: Vec::new(),
                flows: Vec::new(),
            }],
            metrics: FileMetrics {
                lines: 1,
                code_lines: 1,
                comment_lines: 0,
            },
        }
    }
    fn current_issue_snapshot() -> SourceSnapshot {
        let file = current_issue_file_report();
        SourceSnapshot::from_source(&file.path, b"x\n", &file.issues)
            .expect("canonical current issue snapshot")
    }

    fn report(complete: bool) -> AnalysisReport {
        AnalysisReport {
            schema_version: 1,
            files: Vec::new(),
            project: ProjectReport {
                metrics: ProjectMetrics {
                    files: 1,
                    lines: 10,
                    code_lines: 10,
                    comment_lines: 0,
                },
                files: vec![project_file("src/main.rs", 10)],
                duplications: Vec::new(),
                duplication: Some(DuplicationMetrics {
                    duplicated_lines: 0,
                    duplicated_blocks: 0,
                    duplicated_files: 0,
                    duplicated_lines_density: Some(0.0),
                }),
                complete,
                warnings: Vec::new(),
                roots: vec![PathBuf::from(".")],
            },
            assessment: None,
        }
    }

    fn assessment(
        coverage: Option<CoverageReport>,
        new_code: Option<NewCodeReport>,
    ) -> AssessmentReport {
        AssessmentReport {
            schema_version: 1,
            context: context(),
            sources: Vec::new(),
            coverage,
            new_code,
            gate: None,
        }
    }

    fn condition(
        scope: GateScope,
        metric: &str,
        operator: GateOperator,
        threshold: f64,
    ) -> GateCondition {
        GateCondition {
            scope,
            metric: metric.to_string(),
            operator,
            threshold,
        }
    }

    fn new_code_report(
        status: AssessmentStatus,
        reference_context: Option<hoonarqube_ir::assessment::AnalysisContext>,
        findings: Vec<FindingMatch>,
    ) -> NewCodeReport {
        NewCodeReport {
            schema_version: 1,
            status,
            reference_context,
            findings,
            resolved: Vec::new(),
            lines: vec![NewCodeLines {
                path: PathBuf::from("src/main.rs"),
                lines: vec![1],
            }],
            diagnostics: Vec::new(),
        }
    }

    fn coverage_report(lines: CoverageCounter, file_lines: Vec<LineCoverage>) -> CoverageReport {
        CoverageReport {
            schema_version: 1,
            status: AssessmentStatus::Complete,
            files: vec![FileCoverage {
                path: PathBuf::from("src/main.rs"),
                lines: file_lines,
            }],
            inputs: Vec::new(),
            lines,
            branches: CoverageCounter::new(0, 0).expect("empty branches"),
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn every_operator_respects_an_unrounded_count_boundary() {
        let report = report(true);
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![
                condition(GateScope::Overall, "lines", GateOperator::Lt, 10.0),
                condition(GateScope::Overall, "lines", GateOperator::Lte, 10.0),
                condition(GateScope::Overall, "lines", GateOperator::Eq, 10.0),
                condition(GateScope::Overall, "lines", GateOperator::Gte, 10.0),
                condition(GateScope::Overall, "lines", GateOperator::Gt, 10.0),
            ],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Fail);
        assert_eq!(
            evaluated
                .conditions
                .iter()
                .map(|condition| condition.status)
                .collect::<Vec<_>>(),
            vec![
                GateStatus::Fail,
                GateStatus::Pass,
                GateStatus::Pass,
                GateStatus::Pass,
                GateStatus::Fail
            ]
        );
        assert!(
            evaluated
                .conditions
                .iter()
                .all(|condition| condition.actual == Some(10.0))
        );
    }

    #[test]
    fn unavailable_prerequisite_takes_precedence_over_a_failed_condition() {
        let report = report(true);
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![
                condition(GateScope::Overall, "lines", GateOperator::Gt, 10.0),
                condition(GateScope::Overall, "line_coverage", GateOperator::Gte, 80.0),
            ],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Fail);
        assert_eq!(evaluated.conditions[1].status, GateStatus::Unavailable);
        assert!(evaluated.conditions[1].actual.is_none());
    }

    #[test]
    fn incomplete_project_never_passes_an_overall_gate() {
        let report = report(false);
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![condition(
                GateScope::Overall,
                "files",
                GateOperator::Gte,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
        assert!(evaluated.conditions[0].actual.is_none());
    }

    #[test]
    fn new_code_coverage_uses_changed_line_set_not_project_total() {
        let mut report = report(true);
        report.assessment = Some(assessment(
            Some(coverage_report(
                CoverageCounter::new(10, 9).expect("overall coverage"),
                (1..=10)
                    .map(|line| LineCoverage {
                        line,
                        covered: Some(line != 1),
                        branches: None,
                    })
                    .collect(),
            )),
            Some(new_code_report(
                AssessmentStatus::Complete,
                Some(context()),
                Vec::new(),
            )),
        ));
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![
                condition(GateScope::NewCode, "lines", GateOperator::Eq, 1.0),
                condition(
                    GateScope::NewCode,
                    "line_coverage",
                    GateOperator::Gte,
                    100.0,
                ),
            ],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Fail);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Pass);
        assert_eq!(evaluated.conditions[0].actual, Some(1.0));
        assert_eq!(evaluated.conditions[1].status, GateStatus::Fail);
        assert_eq!(evaluated.conditions[1].actual, Some(0.0));
    }

    #[test]
    fn branch_only_changed_line_does_not_become_zero_line_coverage() {
        let mut report = report(true);
        report.assessment = Some(assessment(
            Some(CoverageReport {
                schema_version: 1,
                status: AssessmentStatus::Complete,
                files: vec![FileCoverage {
                    path: PathBuf::from("src/main.rs"),
                    lines: vec![LineCoverage {
                        line: 1,
                        covered: None,
                        branches: Some(CoverageCounter::new(2, 1).expect("branches")),
                    }],
                }],
                inputs: Vec::new(),
                lines: CoverageCounter::new(0, 0).expect("unmeasured lines"),
                branches: CoverageCounter::new(2, 1).expect("branch coverage"),
                diagnostics: Vec::new(),
            }),
            Some(new_code_report(
                AssessmentStatus::Complete,
                Some(context()),
                Vec::new(),
            )),
        ));
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![
                condition(GateScope::NewCode, "line_coverage", GateOperator::Gte, 0.0),
                condition(
                    GateScope::NewCode,
                    "branch_coverage",
                    GateOperator::Gte,
                    50.0,
                ),
            ],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].actual, None);
        assert_eq!(evaluated.conditions[1].status, GateStatus::Pass);
        assert_eq!(evaluated.conditions[1].actual, Some(50.0));
    }

    #[test]
    fn empty_coverage_denominator_is_unavailable() {
        let mut report = report(true);
        report.assessment = Some(assessment(
            Some(coverage_report(
                CoverageCounter::new(0, 0).expect("empty lines"),
                Vec::new(),
            )),
            None,
        ));
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![condition(
                GateScope::Overall,
                "line_coverage",
                GateOperator::Gte,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
    }

    #[test]
    fn uncertain_new_issue_identity_is_unavailable() {
        let mut report = report(true);
        report.files = vec![current_issue_file_report()];
        let snapshot = current_issue_snapshot();
        let identity = snapshot.findings[0].identity.clone();
        let mut assessment = assessment(
            None,
            Some(new_code_report(
                AssessmentStatus::Complete,
                Some(context()),
                vec![FindingMatch {
                    path: PathBuf::from("src/main.rs"),
                    issue_index: 0,
                    identity,
                    status: FindingStatus::Uncertain,
                }],
            )),
        );
        assessment.sources = vec![snapshot];
        report.assessment = Some(assessment);
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![condition(
                GateScope::NewCode,
                "issues",
                GateOperator::Lte,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
    }

    #[test]
    fn missing_new_code_baseline_is_unavailable() {
        let mut report = report(true);
        report.assessment = Some(assessment(
            None,
            Some(new_code_report(
                AssessmentStatus::Complete,
                None,
                Vec::new(),
            )),
        ));
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![condition(
                GateScope::NewCode,
                "lines",
                GateOperator::Gte,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
    }
    #[test]
    fn missing_project_duplication_makes_new_code_duplication_unavailable() {
        let mut report = report(true);
        report.project.duplication = None;
        report.assessment = Some(assessment(
            None,
            Some(new_code_report(
                AssessmentStatus::Complete,
                Some(context()),
                Vec::new(),
            )),
        ));
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![condition(
                GateScope::NewCode,
                "duplicated_lines",
                GateOperator::Gte,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
        assert!(
            evaluated
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("duplication"))
        );
    }

    #[test]
    fn incompatible_new_code_baseline_is_unavailable() {
        let mut report = report(true);
        let mut reference_context = context();
        reference_context.options_digest = "different-options".to_string();
        report.assessment = Some(assessment(
            None,
            Some(new_code_report(
                AssessmentStatus::Complete,
                Some(reference_context),
                Vec::new(),
            )),
        ));
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![condition(
                GateScope::NewCode,
                "lines",
                GateOperator::Gte,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
        assert!(
            evaluated
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("incompatible"))
        );
    }

    #[test]
    fn new_code_findings_must_match_every_current_source_finding() {
        let mut report = report(true);
        report.files = vec![current_issue_file_report()];
        let mut assessment = assessment(
            None,
            Some(new_code_report(
                AssessmentStatus::Complete,
                Some(context()),
                Vec::new(),
            )),
        );
        assessment.sources = vec![current_issue_snapshot()];
        report.assessment = Some(assessment);
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![condition(
                GateScope::NewCode,
                "issues",
                GateOperator::Lte,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
        assert!(
            evaluated
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("omit"))
        );
    }

    #[test]
    fn complete_empty_new_code_scope_counts_zero_but_percentages_stay_unavailable() {
        let mut report = report(true);
        let mut new_code = new_code_report(AssessmentStatus::Complete, Some(context()), Vec::new());
        new_code.lines.clear();
        report.assessment = Some(assessment(
            Some(coverage_report(
                CoverageCounter::new(0, 0).expect("empty lines"),
                Vec::new(),
            )),
            Some(new_code),
        ));

        let count_metrics = [
            "issues",
            "files",
            "lines",
            "duplicated_lines",
            "duplicated_blocks",
            "duplicated_files",
        ];
        let mut conditions = count_metrics
            .iter()
            .map(|metric| condition(GateScope::NewCode, metric, GateOperator::Lte, 0.0))
            .collect::<Vec<_>>();
        conditions.extend([
            condition(GateScope::NewCode, "line_coverage", GateOperator::Gte, 0.0),
            condition(
                GateScope::NewCode,
                "branch_coverage",
                GateOperator::Gte,
                0.0,
            ),
            condition(
                GateScope::NewCode,
                "duplicated_lines_density",
                GateOperator::Gte,
                0.0,
            ),
        ]);

        let evaluated = evaluate_gate(
            &GateConfig {
                schema_version: 1,
                conditions,
            },
            &report,
        );
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions.len(), count_metrics.len() + 3);
        for (result, metric) in evaluated.conditions.iter().zip(count_metrics) {
            assert_eq!(result.metric, metric);
            assert_eq!(result.status, GateStatus::Pass);
            assert_eq!(result.actual, Some(0.0));
            assert!(result.diagnostic.is_none());
        }
        for result in &evaluated.conditions[count_metrics.len()..] {
            assert_eq!(result.status, GateStatus::Unavailable);
            assert_eq!(result.actual, None);
            assert!(result.diagnostic.is_some());
        }
    }

    #[test]
    fn unknown_and_unsupported_metrics_are_unavailable() {
        let report = report(true);
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![
                condition(GateScope::Overall, "not_a_metric", GateOperator::Gte, 0.0),
                condition(GateScope::NewCode, "code_lines", GateOperator::Gte, 0.0),
            ],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert!(
            evaluated
                .conditions
                .iter()
                .all(|condition| condition.status == GateStatus::Unavailable)
        );
        assert!(
            evaluated
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("unknown"))
        );
        assert!(
            evaluated
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("not supported"))
        );
    }

    #[test]
    fn nonfinite_threshold_is_rejected_without_nonfinite_result_artifact() {
        let report = report(true);
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![condition(
                GateScope::Overall,
                "files",
                GateOperator::Gte,
                f64::NAN,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].actual, None);
        assert!(evaluated.conditions[0].threshold.is_finite());
    }

    #[test]
    fn large_counter_comparison_does_not_round_at_u64_boundary() {
        assert_eq!(
            compare_u64_f64(u64::MAX, 18_446_744_073_709_551_616.0),
            Ordering::Less
        );
    }

    #[test]
    fn fractional_count_threshold_keeps_exact_boundary() {
        assert_eq!(compare_u64_f64(1, 1.5), Ordering::Less);
        assert_eq!(compare_u64_f64(2, 1.5), Ordering::Greater);
        assert_eq!(compare_u64_f64(2, 2.0), Ordering::Equal);
    }
}
