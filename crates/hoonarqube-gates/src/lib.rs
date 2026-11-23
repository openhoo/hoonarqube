//! Strict, fail-closed metric quality-gate evaluation.
//!
//! Gate configuration is deliberately kept separate from the report IR.  The
//! report owns the stable artifact/result types; this module owns the small
//! typed input API and the metric derivations that can be proved from that
//! artifact.  A gate never turns missing or partial data into a zero.

mod community_go;
mod community_profile;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use hoonarqube_ir::assessment::SmallChangePolicy;
use hoonarqube_ir::assessment::{
    ASSESSMENT_SCHEMA_VERSION, AssessmentStatus, CoverageCounter, FindingStatus,
    GateConditionResult, GateOperator, GatePrecision, GateReport, GateScope, GateStatus,
    normalize_path,
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
    community_go::CORE,
    community_go::EXTENDED,
    community_go::COMPREHENSIVE,
    "code_lines",
    "comment_lines",
    "issues",
    "violations",
    "security_hotspots_reviewed",
    community_profile::VIOLATIONS,
    community_profile::HOTSPOTS,
    "duplicated_lines",
    "duplicated_blocks",
    "duplicated_files",
    "duplicated_lines_density",
    "line_coverage",
    "branch_coverage",
    "coverage",
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
    #[serde(default, skip_serializing_if = "GatePrecision::is_full")]
    pub precision: GatePrecision,
    #[serde(default, skip_serializing_if = "SmallChangePolicy::is_off")]
    pub small_change_policy: SmallChangePolicy,
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
        if !self.small_change_policy.supports(self.scope, &self.metric) {
            return Err(
                "small-change policy requires a coverage or duplication condition on new code"
                    .into(),
            );
        }
        if !self.precision.supports(self.scope, &self.metric) {
            return Err(
                "one_decimal precision requires coverage or overall line_coverage".to_string(),
            );
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
                | community_go::CORE
                | community_go::EXTENDED
                | community_go::COMPREHENSIVE
                | "code_lines"
                | "comment_lines"
                | "issues"
                | "duplicated_lines"
                | "duplicated_blocks"
                | "duplicated_files"
                | "duplicated_lines_density"
                | "coverage"
                | "line_coverage"
                | "branch_coverage"
        ),
        GateScope::NewCode => matches!(
            metric,
            "files"
                | "lines"
                | "issues"
                | "violations"
                | "security_hotspots_reviewed"
                | community_profile::VIOLATIONS
                | community_profile::HOTSPOTS
                | "duplicated_lines"
                | "duplicated_blocks"
                | "duplicated_files"
                | "duplicated_lines_density"
                | "coverage"
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
    evaluate_gate_with_reviews(config, report, &BTreeSet::new())
}

/// Evaluates the configured gate with reviewed hotspot identities from a trusted
/// reviewer store. IDs are the native, unprefixed assessment digests. Never
/// populate this set from a scanner-supplied review claim.
#[must_use]
pub fn evaluate_gate_with_reviews(
    config: &GateConfig,
    report: &AnalysisReport,
    reviewed_hotspots: &BTreeSet<String>,
) -> GateReport {
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
        let result = evaluate_condition(condition, report, reviewed_hotspots);
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

fn evaluate_condition(
    condition: &GateCondition,
    report: &AnalysisReport,
    reviewed_hotspots: &BTreeSet<String>,
) -> GateConditionResult {
    let mut result = GateConditionResult {
        scope: condition.scope,
        metric: condition.metric.clone(),
        operator: condition.operator,
        threshold: safe_threshold(condition.threshold),
        precision: condition.precision,
        small_change_policy: condition.small_change_policy,
        ignored_on_small_change: None,
        actual: None,
        status: GateStatus::Unavailable,
        diagnostic: None,
    };

    if let Err(diagnostic) = condition.validate() {
        result.diagnostic = Some(diagnostic);
        return result;
    }

    let value = match &condition.scope {
        GateScope::Overall => {
            overall_metric(&condition.metric, condition.precision, report).map(|v| (v, None))
        }
        GateScope::NewCode => new_code_metric(
            &condition.metric,
            condition.precision,
            condition.small_change_policy,
            report,
            reviewed_hotspots,
        ),
    };
    let (value, change_size) = match value {
        Ok(value) => value,
        Err(diagnostic) => {
            result.diagnostic = Some(diagnostic);
            return result;
        }
    };

    let Some(actual) = value.as_f64() else {
        result.status = GateStatus::NoValue;
        return result;
    };
    if !actual.is_finite() {
        result.diagnostic = Some("derived gate metric is non-finite".to_string());
        return result;
    }
    result.actual = Some(actual);

    if value.meets(condition.operator, condition.threshold) {
        result.status = GateStatus::Pass;
    } else if let Some(n) = change_size.filter(|&n| n < 20) {
        result.status = GateStatus::Pass;
        result.ignored_on_small_change = Some(n);
    } else {
        result.status = GateStatus::Fail;
        result.diagnostic = Some(format!(
            "actual {} does not satisfy {} {} for {}",
            format_number(actual),
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
        precision: condition.precision,
        small_change_policy: condition.small_change_policy,
        ignored_on_small_change: None,
        actual: None,
        status: GateStatus::Unavailable,
        diagnostic: Some(diagnostic),
    }
}

#[derive(Debug, Clone, Copy)]
enum MetricValue {
    NoValue,
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
    fn as_f64(self) -> Option<f64> {
        match self {
            Self::NoValue => None,
            Self::Count(value) => Some(counter_as_f64(value)),
            Self::Percentage(value) => Some(value),
        }
    }

    fn meets(self, operator: GateOperator, threshold: f64) -> bool {
        match self {
            Self::NoValue => false,
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

fn overall_metric(
    metric: &str,
    precision: GatePrecision,
    report: &AnalysisReport,
) -> Result<MetricValue, String> {
    if !report.project.complete {
        return Err(
            "project analysis is incomplete; overall gate metric is unavailable".to_string(),
        );
    }

    let metrics = &report.project.metrics;
    match metric {
        community_go::CORE | community_go::EXTENDED | community_go::COMPREHENSIVE => {
            community_go::count(metric, report).map(MetricValue::Count)
        }
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
        "coverage" => {
            let coverage = complete_coverage(report)?;
            combined_coverage(&coverage.lines, &coverage.branches, precision)
        }
        "line_coverage" => {
            let coverage = complete_coverage(report)?;
            percentage_counter_with_precision(
                coverage.lines.eligible,
                coverage.lines.covered,
                "line coverage",
                precision,
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

fn new_code_metric(
    metric: &str,
    precision: GatePrecision,
    policy: SmallChangePolicy,
    report: &AnalysisReport,
    reviewed_hotspots: &BTreeSet<String>,
) -> Result<(MetricValue, Option<u64>), String> {
    if !report.project.complete {
        return Err(
            "project analysis is incomplete; new-code gate metric is unavailable".to_string(),
        );
    }
    let source_only = metric == "coverage"
        || !policy.is_off()
        || report
            .assessment
            .as_ref()
            .and_then(|a| a.new_code.as_ref())
            .is_some_and(|n| n.has_scm_source_metric(metric));
    let new_code = complete_new_code(report, source_only)?;
    let entries = if source_only {
        new_code.changed_source_lines.as_deref().ok_or_else(|| {
            "this condition requires exact changed source lines from a compatible baseline"
                .to_string()
        })?
    } else {
        &new_code.lines
    };
    let mut line_sets = new_code_line_sets(entries)?;
    let measurements = measurement_index(report)?;
    let scoped_line_count = validate_new_line_sets(report, &measurements, &line_sets)?;
    let mut change_size = None;
    let value = match metric {
        "files" => Ok(MetricValue::Count(usize_as_u64(line_sets.len()))),
        "lines" => Ok(MetricValue::Count(scoped_line_count)),
        "violations"
        | "security_hotspots_reviewed"
        | community_profile::VIOLATIONS
        | community_profile::HOTSPOTS => {
            let qualified = matches!(
                metric,
                community_profile::VIOLATIONS | community_profile::HOTSPOTS
            )
            .then(|| community_profile::Qualified::new(report))
            .transpose()?;
            let assessment = report.assessment.as_ref().ok_or("missing assessment")?;
            new_security_metric(
                metric,
                assessment,
                new_code,
                &measurements,
                reviewed_hotspots,
                qualified.as_ref(),
            )
        }
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
        "line_coverage" | "branch_coverage" | "coverage" => {
            if new_code.specific_analysis.is_some() {
                exclude_empty_scm_eof(report, &mut line_sets);
            }
            return new_code_coverage(metric, precision, policy, report, &line_sets);
        }
        "duplicated_lines"
        | "duplicated_blocks"
        | "duplicated_files"
        | "duplicated_lines_density" => {
            let scoped = scoped_duplication(report, &measurements, &line_sets)?;
            if !policy.is_off() {
                change_size = Some(scoped_line_count);
                if metric == "duplicated_lines_density" && scoped.denominator == 0 {
                    return Ok((MetricValue::NoValue, None));
                }
            }
            match metric {
                "duplicated_lines" => Ok(MetricValue::Count(scoped.duplicated_lines)),
                "duplicated_blocks" => Ok(MetricValue::Count(scoped.duplicated_blocks)),
                "duplicated_files" => Ok(MetricValue::Count(scoped.duplicated_files)),
                _ => percentage_counter(
                    scoped.denominator,
                    scoped.duplicated_lines,
                    "new-code duplication density",
                ),
            }
        }
        _ => Err("unsupported new-code gate metric".to_string()),
    }?;
    Ok((value, change_size))
}

/// Returns the catalog classification used by both the evaluator and the service.
/// Unknown rules cannot be silently treated as ordinary issues.
#[must_use]
pub fn is_security_hotspot(key: &str) -> Option<bool> {
    let rule_type = hoonarqube_catalog::embedded()
        .rule(key)
        .map(|rule| rule.rule_type.as_str())
        .or_else(|| hoonarqube_catalog::native_rule(key).map(|rule| rule.rule_type));
    match rule_type {
        Some("SECURITY_HOTSPOT") => Some(true),
        Some("BUG" | "CODE_SMELL" | "VULNERABILITY") => Some(false),
        _ => None,
    }
}

fn new_security_metric(
    metric: &str,
    assessment: &hoonarqube_ir::assessment::AssessmentReport,
    new_code: &hoonarqube_ir::assessment::NewCodeReport,
    measurements: &MeasurementIndex<'_>,
    reviewed: &BTreeSet<String>,
    qualified: Option<&community_profile::Qualified<'_>>,
) -> Result<MetricValue, String> {
    if assessment.context.catalog_digest != hoonarqube_catalog::embedded().snapshot().catalog_sha256
    {
        return Err("finding catalog differs from the gate evaluator".into());
    }
    let hotspots = matches!(
        metric,
        "security_hotspots_reviewed" | community_profile::HOTSPOTS
    );
    let sources: BTreeMap<_, _> = assessment.sources.iter().map(|s| (&s.path, s)).collect();
    validate_finding_inventory(measurements, &sources)?;
    let mut eligible = 0;
    let mut completed = 0;
    for entry in &new_code.findings {
        if entry.status == FindingStatus::Existing {
            continue;
        }
        let finding = sources
            .get(&entry.path)
            .and_then(|source| source.findings.get(entry.issue_index))
            .ok_or("new-code finding missing from source inventory")?;
        let kind = if let Some(profile) = qualified {
            let Some(hotspot) = profile.hotspot(&entry.path, &finding.rule_key)? else {
                continue;
            };
            hotspot
        } else {
            is_security_hotspot(&finding.rule_key)
                .ok_or_else(|| format!("unknown finding kind for {}", finding.rule_key))?
        };
        if kind != hotspots {
            continue;
        }
        if entry.status == FindingStatus::Uncertain || finding.ambiguous {
            return Err(format!("uncertain new-code finding identity for {metric}"));
        }
        eligible += 1;
        if hotspots && reviewed.contains(&entry.identity) {
            completed += 1;
        }
    }
    if hotspots && eligible == 0 {
        Ok(MetricValue::NoValue)
    } else if hotspots {
        percentage_counter(eligible, completed, "new-code hotspot review")
    } else {
        Ok(MetricValue::Count(eligible))
    }
}

fn validate_finding_inventory(
    measurements: &MeasurementIndex<'_>,
    sources: &BTreeMap<&PathBuf, &hoonarqube_ir::assessment::SourceSnapshot>,
) -> Result<(), String> {
    for (path, file) in &measurements.files {
        if matches!(
            file.classification,
            FileClassification::Source | FileClassification::Test
        ) && (file.status != MeasurementStatus::Complete || !sources.contains_key(path))
        {
            return Err(format!("incomplete finding inventory: {}", path.display()));
        }
    }
    if sources.keys().any(|path| {
        !measurements.files.get(*path).is_some_and(|file| {
            file.status == MeasurementStatus::Complete
                && matches!(
                    file.classification,
                    FileClassification::Source | FileClassification::Test
                )
        })
    }) {
        return Err("assessment contains a source outside the measured finding inventory".into());
    }
    Ok(())
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
    if assessment.schema_version != ASSESSMENT_SCHEMA_VERSION {
        return Err(format!(
            "assessment schema_version {} is unsupported",
            assessment.schema_version
        ));
    }
    let coverage = assessment
        .coverage
        .as_ref()
        .ok_or_else(|| "coverage report is missing".to_string())?;
    if coverage.schema_version != ASSESSMENT_SCHEMA_VERSION {
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
    source_only: bool,
) -> Result<&hoonarqube_ir::assessment::NewCodeReport, String> {
    let assessment = report.assessment.as_ref().ok_or_else(|| {
        "new-code data is unavailable because no assessment is attached".to_string()
    })?;
    if assessment.schema_version != ASSESSMENT_SCHEMA_VERSION {
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
    if new_code.schema_version != ASSESSMENT_SCHEMA_VERSION {
        return Err(format!(
            "new-code schema_version {} is unsupported",
            new_code.schema_version
        ));
    }
    let exact_source_diff = source_only
        && new_code.status == AssessmentStatus::Incomplete
        && new_code.changed_source_lines.is_some();
    if new_code.status != AssessmentStatus::Complete && !exact_source_diff {
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
    percentage_counter_with_precision(eligible, covered, name, GatePrecision::Full)
}

fn percentage_counter_with_precision(
    eligible: u64,
    covered: u64,
    name: &str,
    precision: GatePrecision,
) -> Result<MetricValue, String> {
    validate_counter(eligible, covered, name)?;
    coverage_ratio(u128::from(eligible), u128::from(covered), name, precision)
}

// The sum of two u64 counters may exceed u64::MAX; neither component may
// be rounded independently or interpreted as a percentage before adding.
fn combined_coverage(
    lines: &CoverageCounter,
    branches: &CoverageCounter,
    precision: GatePrecision,
) -> Result<MetricValue, String> {
    coverage_ratio(
        u128::from(lines.eligible) + u128::from(branches.eligible),
        u128::from(lines.covered) + u128::from(branches.covered),
        "coverage",
        precision,
    )
}

fn coverage_ratio(
    eligible: u128,
    covered: u128,
    name: &str,
    precision: GatePrecision,
) -> Result<MetricValue, String> {
    if eligible == 0 {
        return Err(format!("{name} has no denominator"));
    }
    let value = match precision {
        GatePrecision::Full => {
            // At most 65 significant counter bits. The wire representation of
            // an unrounded measured percentage is f64.
            #[allow(clippy::cast_precision_loss)]
            let value = covered as f64 * 100.0 / eligible as f64;
            value
        }
        GatePrecision::OneDecimal => {
            let tenths = (covered * 1000 + eligible / 2) / eligible;
            let tenths = u16::try_from(tenths).map_err(|_| format!("{name} is out of range"))?;
            f64::from(tenths) / 10.0
        }
    };
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
    entries: &[hoonarqube_ir::assessment::NewCodeLines],
) -> Result<BTreeMap<PathBuf, BTreeSet<u32>>, String> {
    let mut sets = BTreeMap::new();
    for entry in entries {
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

/// Normalized, duplicate-checked view of the project measurement inventory.
///
/// New-code artifacts identify files by normalized paths, so every
/// cross-artifact join against project measurements must resolve both sides
/// with the same normalization.  Inventory entries that normalize to the same
/// path are conflicting aliases and fail closed instead of silently joining.
struct MeasurementIndex<'a> {
    files: BTreeMap<PathBuf, &'a hoonarqube_ir::ProjectFileMeasurement>,
}

fn measurement_index(report: &AnalysisReport) -> Result<MeasurementIndex<'_>, String> {
    let mut files = BTreeMap::new();
    for measurement in &report.project.files {
        let path = normalize_path(&measurement.path).map_err(|error| {
            format!(
                "project inventory path \"{}\" is invalid: {error}",
                measurement.path.to_string_lossy().escape_debug()
            )
        })?;
        if files.insert(path.clone(), measurement).is_some() {
            return Err(format!(
                "project inventory contains duplicate path \"{}\"",
                path.to_string_lossy().escape_debug()
            ));
        }
    }
    Ok(MeasurementIndex { files })
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
    measurements: &MeasurementIndex<'_>,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<ScopedDuplication, String> {
    let _ = complete_duplication(report)?;
    let denominator = duplication_line_denominator(measurements, line_sets)?;
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
    let path = normalize_path(&occurrence.path).map_err(|error| {
        format!(
            "duplication occurrence path \"{}\" is invalid: {error}",
            occurrence.path.to_string_lossy().escape_debug()
        )
    })?;
    let Some(lines) = line_sets.get(&path) else {
        return Ok(());
    };
    let covered = (occurrence.start_line..=occurrence.end_line).any(|line| lines.contains(&line));
    if !covered {
        return Ok(());
    }
    duplicated_blocks.insert((
        path.clone(),
        occurrence.start_line,
        occurrence.end_line,
        occurrence.start_byte,
        occurrence.end_byte,
    ));
    duplicated_files.insert(path.clone());
    for line in occurrence.start_line..=occurrence.end_line {
        if lines.contains(&line) {
            duplicated_lines.insert((path.clone(), line));
        }
    }
    Ok(())
}

fn validate_new_line_sets(
    report: &AnalysisReport,
    measurements: &MeasurementIndex<'_>,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<u64, String> {
    let mut denominator = 0_u64;
    for (path, lines) in line_sets {
        let measurement = measurements.files.get(path).copied().ok_or_else(|| {
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
        // The IR has already checked the source snapshot and preceding line.
        let scm_eof = report.assessment.as_ref().is_some_and(|a| {
            a.new_code
                .as_ref()
                .is_some_and(|n| n.specific_analysis.is_some())
                && a.sources
                    .binary_search_by(|s| s.path.cmp(path))
                    .ok()
                    .is_some_and(|i| {
                        a.sources[i].ends_with_lf
                            && a.sources[i].line_digests.len() as u64 == file_lines
                    })
        });
        for &line in lines {
            if u64::from(line) > file_lines + u64::from(scm_eof) {
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
    measurements: &MeasurementIndex<'_>,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<u64, String> {
    let mut denominator = 0_u64;
    for (path, lines) in line_sets {
        let measurement = measurements.files.get(path).copied().ok_or_else(|| {
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

fn exclude_empty_scm_eof(
    report: &AnalysisReport,
    line_sets: &mut BTreeMap<PathBuf, BTreeSet<u32>>,
) {
    // SCM counts the empty line after a final LF; it has no executable
    // source bytes or LCOV observation. Physical lines still need proof.
    for source in &report
        .assessment
        .as_ref()
        .expect("validated assessment")
        .sources
    {
        if source.ends_with_lf
            && let Some(lines) = line_sets.get_mut(&source.path)
            && let Ok(eof) = u32::try_from(source.line_digests.len() + 1)
        {
            lines.remove(&eof);
        }
    }
}

/// Count only measured observations on the changed lines, before forming any percentage.
fn new_code_coverage(
    metric: &str,
    precision: GatePrecision,
    policy: SmallChangePolicy,
    report: &AnalysisReport,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<(MetricValue, Option<u64>), String> {
    let coverage = complete_coverage(report)?;
    if !policy.is_off() && line_sets.is_empty() {
        return Ok((MetricValue::NoValue, None));
    }
    let (lines, branches) = scoped_coverage(coverage, line_sets)?;
    if !policy.is_off() {
        let no_denominator = match metric {
            "line_coverage" => lines.eligible == 0,
            "branch_coverage" => branches.eligible == 0,
            _ => lines.eligible == 0 && branches.eligible == 0,
        };
        if no_denominator {
            return Ok((MetricValue::NoValue, None));
        }
    }
    let value = match metric {
        "line_coverage" => {
            percentage_counter(lines.eligible, lines.covered, "new-code line coverage")
        }
        "branch_coverage" => percentage_counter(
            branches.eligible,
            branches.covered,
            "new-code branch coverage",
        ),
        _ => combined_coverage(&lines, &branches, precision),
    }?;
    Ok((value, (!policy.is_off()).then_some(lines.eligible)))
}

fn scoped_coverage(
    coverage: &hoonarqube_ir::assessment::CoverageReport,
    line_sets: &BTreeMap<PathBuf, BTreeSet<u32>>,
) -> Result<(CoverageCounter, CoverageCounter), String> {
    validate_scoped_coverage_entries(coverage, line_sets)?;
    let mut lines = CoverageCounter {
        eligible: 0,
        covered: 0,
    };
    let mut branches = lines.clone();
    // complete_coverage validated the checked global sums of these disjoint
    // entries. The two subset counters therefore cannot overflow.
    for file in &coverage.files {
        let Some(changed) = line_sets.get(&file.path) else {
            continue;
        };
        for entry in &file.lines {
            if !changed.contains(&entry.line) {
                continue;
            }
            if let Some(hit) = entry.covered {
                lines.eligible += 1;
                lines.covered += u64::from(hit);
            }
            if let Some(counts) = &entry.branches {
                branches.eligible += counts.eligible;
                branches.covered += counts.covered;
            }
        }
    }
    Ok((lines, branches))
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
    use super::{
        GateCondition, GateConfig, compare_u64_f64, evaluate_gate,
        percentage_counter_with_precision,
    };
    use hoonarqube_ir::assessment::{
        ASSESSMENT_SCHEMA_VERSION, AssessmentReport, AssessmentStatus, CoverageCounter,
        CoverageReport, FileCoverage, FindingMatch, FindingStatus, GateOperator, GatePrecision,
        GateScope, GateStatus, LineCoverage, NewCodeLines, NewCodeReport, SmallChangePolicy,
        SourceSnapshot,
    };
    use hoonarqube_ir::{
        AnalysisReport, DuplicateGroup, DuplicateOccurrence, DuplicationMetrics,
        FileClassification, FileMetrics, FileReport, Issue, MeasurementStatus, Pos,
        ProjectFileMeasurement, ProjectMetrics, ProjectReport, Range,
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
            parity: None,
        }
    }

    fn assessment(
        coverage: Option<CoverageReport>,
        new_code: Option<NewCodeReport>,
    ) -> AssessmentReport {
        AssessmentReport {
            schema_version: ASSESSMENT_SCHEMA_VERSION,
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
            precision: GatePrecision::Full,
            small_change_policy: SmallChangePolicy::Off,
        }
    }

    fn new_code_report(
        status: AssessmentStatus,
        reference_context: Option<hoonarqube_ir::assessment::AnalysisContext>,
        findings: Vec<FindingMatch>,
    ) -> NewCodeReport {
        NewCodeReport {
            specific_analysis: None,
            changed_source_lines: None,
            schema_version: ASSESSMENT_SCHEMA_VERSION,
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
            schema_version: ASSESSMENT_SCHEMA_VERSION,
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
    fn coverage_tenths_round_exact_half_up_across_the_u64_range() {
        // These adjacent integers collapse to the same f64 above 2^53.
        let denominator = u64::MAX - 15;
        let tie = denominator / 16; // 6.25 percent
        for (eligible, covered, expected) in [
            (16, 1, 6.3),
            (denominator, tie - 1, 6.2),
            (denominator, tie, 6.3),
            (denominator, tie + 1, 6.3),
            (u64::MAX, u64::MAX, 100.0),
            (u64::MAX, 0, 0.0),
            (4201, 2485, 59.2),
        ] {
            let actual = percentage_counter_with_precision(
                eligible,
                covered,
                "coverage",
                GatePrecision::OneDecimal,
            )
            .unwrap();
            assert_eq!(
                actual.as_f64().unwrap().to_bits(),
                f64::to_bits(expected),
                "{covered}/{eligible}"
            );
        }
        for (eligible, covered) in [(0, 0), (2, 3)] {
            assert!(
                percentage_counter_with_precision(
                    eligible,
                    covered,
                    "coverage",
                    GatePrecision::OneDecimal
                )
                .is_err()
            );
        }
    }

    #[test]
    fn overall_line_gate_compares_only_the_rounded_actual() {
        let mut report = report(true);
        report.assessment = Some(assessment(
            Some(coverage_report(
                CoverageCounter::new(3, 2).unwrap(),
                (1..=3)
                    .map(|line| LineCoverage {
                        line,
                        covered: Some(line != 3),
                        branches: None,
                    })
                    .collect(),
            )),
            None,
        ));
        let full = condition(GateScope::Overall, "line_coverage", GateOperator::Gte, 66.7);
        let rounded = GateCondition {
            precision: GatePrecision::OneDecimal,
            ..full.clone()
        };
        let above = GateCondition {
            threshold: 66.71,
            ..rounded.clone()
        };
        let equal = GateCondition {
            operator: GateOperator::Eq,
            ..rounded.clone()
        };
        let gate = evaluate_gate(
            &GateConfig {
                schema_version: 1,
                conditions: vec![full, rounded, above, equal],
            },
            &report,
        );
        let actuals: Vec<_> = gate
            .conditions
            .iter()
            .map(|condition| (condition.status, condition.actual))
            .collect();
        assert_eq!(
            actuals,
            vec![
                (GateStatus::Fail, Some(200.0 / 3.0)),
                (GateStatus::Pass, Some(66.7)),
                (GateStatus::Fail, Some(66.7)),
                (GateStatus::Pass, Some(66.7))
            ]
        );
        assert_eq!(gate.conditions[1].precision, GatePrecision::OneDecimal);
    }

    #[test]
    fn one_decimal_requires_overall_line_coverage_and_complete_inputs() {
        let opt = GateCondition {
            precision: GatePrecision::OneDecimal,
            ..condition(GateScope::Overall, "line_coverage", GateOperator::Gte, 0.0)
        };
        for (scope, metric) in [
            (GateScope::NewCode, "line_coverage"),
            (GateScope::Overall, "branch_coverage"),
            (GateScope::Overall, "lines"),
        ] {
            let invalid = GateCondition {
                scope,
                metric: metric.to_owned(),
                ..opt.clone()
            };
            assert!(invalid.validate().is_err());
        }
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![opt],
        };
        let source = coverage_report(
            CoverageCounter::new(1, 1).unwrap(),
            vec![LineCoverage {
                line: 1,
                covered: Some(true),
                branches: None,
            }],
        );
        let mut partial = source.clone();
        partial.status = AssessmentStatus::Incomplete;
        let mut inconsistent = source.clone();
        inconsistent.lines.covered = 0;
        for (complete, coverage) in [
            (true, None),
            (false, Some(source)),
            (true, Some(partial)),
            (true, Some(inconsistent)),
            (
                true,
                Some(coverage_report(
                    CoverageCounter::new(0, 0).unwrap(),
                    Vec::new(),
                )),
            ),
        ] {
            let mut report = report(complete);
            report.assessment = Some(assessment(coverage, None));
            let gate = evaluate_gate(&config, &report);
            assert_eq!(gate.status, GateStatus::Unavailable);
            assert_eq!(gate.conditions[0].actual, None);
            assert_eq!(gate.conditions[0].precision, GatePrecision::OneDecimal);
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
    fn combined_coverage_weights_observations_and_scopes_before_rounding() {
        let mut report = report(true);
        // The first line has no DA record, but its two LCOV branches are measured.
        let mut coverage = coverage_report(
            CoverageCounter::new(2, 2).unwrap(),
            vec![
                LineCoverage {
                    line: 1,
                    covered: None,
                    branches: Some(CoverageCounter::new(2, 1).unwrap()),
                },
                LineCoverage {
                    line: 2,
                    covered: Some(true),
                    branches: Some(CoverageCounter::new(4, 4).unwrap()),
                },
                LineCoverage {
                    line: 3,
                    covered: Some(true),
                    branches: None,
                },
            ],
        );
        coverage.branches = CoverageCounter::new(6, 5).unwrap();
        let mut changed = new_code_report(AssessmentStatus::Complete, Some(context()), vec![]);
        changed.lines[0].lines = vec![1, 2, 3];
        changed.changed_source_lines = Some(vec![NewCodeLines {
            path: PathBuf::from("src/main.rs"),
            lines: vec![1, 3],
        }]);
        report.assessment = Some(assessment(Some(coverage), Some(changed)));
        let snapshot = SourceSnapshot::from_report(
            std::path::Path::new("src/main.rs"),
            b"one\ntwo\nthree\nfour\n",
            None,
        )
        .unwrap();
        report.assessment.as_mut().unwrap().sources.push(snapshot);
        let cfg = |scope, minimum| GateCondition {
            precision: GatePrecision::OneDecimal,
            ..condition(scope, "coverage", GateOperator::Gte, minimum)
        };
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![
                cfg(GateScope::Overall, 87.5),
                cfg(GateScope::NewCode, 66.7),
                GateCondition {
                    precision: GatePrecision::Full,
                    ..cfg(GateScope::NewCode, 66.7)
                },
            ],
        };
        let gate = evaluate_gate(&config, &report);
        assert_eq!(
            gate.conditions
                .iter()
                .map(|c| (c.actual, c.status))
                .collect::<Vec<_>>(),
            vec![
                (Some(87.5), GateStatus::Pass),
                (Some(66.7), GateStatus::Pass),
                (Some(200.0 / 3.0), GateStatus::Fail)
            ]
        );
        // An unrepresented changed line cannot silently reduce the denominator.
        let change = report
            .assessment
            .as_mut()
            .unwrap()
            .new_code
            .as_mut()
            .unwrap();
        change.lines[0].lines.push(4);
        change.changed_source_lines.as_mut().unwrap()[0]
            .lines
            .push(4);
        let gate = evaluate_gate(&config, &report);
        assert_eq!(gate.conditions[0].status, GateStatus::Pass);
        assert_eq!(gate.conditions[1].status, GateStatus::Unavailable);
        assert_eq!(gate.conditions[1].actual, None);
    }

    #[test]
    fn community_exception_counts_coverable_lines_separately_from_physical_lines() {
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![
                GateCondition {
                    small_change_policy: SmallChangePolicy::Community20,
                    ..condition(GateScope::NewCode, "coverage", GateOperator::Gte, 80.0)
                },
                GateCondition {
                    small_change_policy: SmallChangePolicy::Community20,
                    ..condition(
                        GateScope::NewCode,
                        "duplicated_lines_density",
                        GateOperator::Lte,
                        3.0,
                    )
                },
            ],
        };
        for (physical, coverable) in [(19, 19), (20, 19), (20, 20)] {
            let mut report = report(true);
            let path = "src/main.rs";
            report.project.files = vec![project_file(path, physical)];
            report.project.duplications.push(DuplicateGroup {
                language: "rust".into(),
                occurrences: vec![DuplicateOccurrence {
                    path: path.into(),
                    start_line: 1,
                    end_line: 2,
                    start_byte: 0,
                    end_byte: 4,
                }],
            });
            let mut coverage = coverage_report(
                CoverageCounter::new(u64::from(coverable), 0).unwrap(),
                (1..=physical)
                    .map(|line| LineCoverage {
                        line,
                        covered: (line <= coverable).then_some(false),
                        branches: (line > coverable).then(|| CoverageCounter::new(2, 0).unwrap()),
                    })
                    .collect(),
            );
            coverage.branches =
                CoverageCounter::new(u64::from((physical - coverable) * 2), 0).unwrap();
            let mut changed = new_code_report(AssessmentStatus::Complete, Some(context()), vec![]);
            changed.lines[0].lines = (1..=physical).collect();
            changed.changed_source_lines = Some(changed.lines.clone());
            let mut assessment = assessment(Some(coverage), Some(changed));
            assessment.sources.push(
                SourceSnapshot::from_report(path, "x\n".repeat(physical as usize).as_bytes(), None)
                    .unwrap(),
            );
            report.assessment = Some(assessment);
            let decision = evaluate_gate(&config, &report);
            for (c, n) in decision.conditions.iter().zip([coverable, physical]) {
                assert!(c.actual.is_some());
                assert_eq!(
                    c.status,
                    if n < 20 {
                        GateStatus::Pass
                    } else {
                        GateStatus::Fail
                    }
                );
                assert_eq!(c.ignored_on_small_change, (n < 20).then_some(u64::from(n)));
            }
            decision.validate().unwrap();

            // The same policy may only waive measured failures. It cannot supply missing evidence.
            report.assessment.as_mut().unwrap().coverage = None;
            assert_eq!(
                evaluate_gate(&config, &report).conditions[0].status,
                GateStatus::Unavailable
            );
            let changed = report
                .assessment
                .as_mut()
                .unwrap()
                .new_code
                .as_mut()
                .unwrap();
            changed.lines.clear();
            changed.changed_source_lines = Some(vec![]);
            let empty = evaluate_gate(&config, &report);
            assert_eq!(empty.conditions[1].status, GateStatus::NoValue);
            assert_eq!(empty.conditions[1].ignored_on_small_change, None);
            assert_eq!(empty.conditions[1].actual, None);
            assert_eq!(empty.conditions[0].status, GateStatus::Unavailable);
            empty.validate().unwrap();
        }
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
                schema_version: ASSESSMENT_SCHEMA_VERSION,
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
    fn new_hotspot_gate_separates_reviewed_empty_and_unknown() {
        use std::collections::BTreeSet;
        let mut report = report(true);
        let mut file = current_issue_file_report();
        file.issues[0].rule_key = "javascript:S2245".into();
        let snapshot = SourceSnapshot::from_source(&file.path, b"x\n", &file.issues).unwrap();
        let id = snapshot.findings[0].identity.clone();
        let mut scope = context();
        scope.catalog_digest = hoonarqube_catalog::embedded()
            .snapshot()
            .catalog_sha256
            .clone();
        let baseline = new_code_report(
            AssessmentStatus::Complete,
            Some(scope.clone()),
            vec![FindingMatch {
                path: file.path.clone(),
                issue_index: 0,
                identity: id.clone(),
                status: FindingStatus::New,
            }],
        );
        let mut current = assessment(None, Some(baseline));
        current.context = scope;
        current.sources = vec![snapshot];
        report.files = vec![file];
        report.assessment = Some(current);
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![
                condition(
                    GateScope::NewCode,
                    "security_hotspots_reviewed",
                    GateOperator::Gte,
                    100.0,
                ),
                condition(GateScope::NewCode, "violations", GateOperator::Lte, 0.0),
            ],
        };
        let gate = evaluate_gate(&config, &report);
        assert_eq!(gate.status, GateStatus::Fail);
        assert_eq!(gate.conditions[0].actual, Some(0.0));
        assert_eq!(gate.conditions[1].actual, Some(0.0));
        let gate = super::evaluate_gate_with_reviews(&config, &report, &BTreeSet::from([id]));
        assert_eq!(gate.status, GateStatus::Pass);
        assert_eq!(gate.conditions[0].actual, Some(100.0));
        report
            .assessment
            .as_mut()
            .unwrap()
            .new_code
            .as_mut()
            .unwrap()
            .findings[0]
            .status = FindingStatus::Uncertain;
        assert_eq!(
            evaluate_gate(&config, &report).status,
            GateStatus::Unavailable
        );
        report
            .assessment
            .as_mut()
            .unwrap()
            .new_code
            .as_mut()
            .unwrap()
            .findings[0]
            .status = FindingStatus::Existing;
        let empty = evaluate_gate(&config, &report);
        assert_eq!(empty.status, GateStatus::Pass);
        assert_eq!(empty.conditions[0].status, GateStatus::NoValue);
        assert_eq!(empty.conditions[0].actual, None);
        empty.validate().unwrap();
        let mut forged = empty;
        forged.conditions[1].status = GateStatus::NoValue;
        forged.conditions[1].actual = None;
        assert!(forged.validate().is_err());
        let mut missing = report.clone();
        missing.assessment.as_mut().unwrap().new_code = None;
        assert_eq!(
            evaluate_gate(&config, &missing).status,
            GateStatus::Unavailable
        );
        // Stripping the source and its findings must not certify a zero denominator.
        report.files.clear();
        let current = report.assessment.as_mut().unwrap();
        current.sources.clear();
        current.new_code.as_mut().unwrap().findings.clear();
        assert_eq!(
            evaluate_gate(&config, &report).status,
            GateStatus::Unavailable
        );
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

    #[test]
    fn new_code_gate_joins_normalized_inventory_paths_and_counts_changed_files_once() {
        let mut report = report(true);
        report.project.files[0].path = PathBuf::from("./src/main.rs");
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
            conditions: vec![
                condition(GateScope::NewCode, "files", GateOperator::Eq, 1.0),
                condition(GateScope::NewCode, "lines", GateOperator::Eq, 1.0),
            ],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Pass);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Pass);
        assert_eq!(evaluated.conditions[0].actual, Some(1.0));
        assert_eq!(evaluated.conditions[1].status, GateStatus::Pass);
        assert_eq!(evaluated.conditions[1].actual, Some(1.0));
    }

    #[test]
    fn unchanged_complete_new_code_counts_zero_on_aliased_inventory() {
        let mut report = report(true);
        report.project.files[0].path = PathBuf::from("./src/main.rs");
        let mut new_code = new_code_report(AssessmentStatus::Complete, Some(context()), Vec::new());
        new_code.lines.clear();
        report.assessment = Some(assessment(None, Some(new_code)));
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![
                condition(GateScope::NewCode, "files", GateOperator::Eq, 0.0),
                condition(GateScope::NewCode, "lines", GateOperator::Eq, 0.0),
            ],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Pass);
        for result in &evaluated.conditions {
            assert_eq!(result.status, GateStatus::Pass);
            assert_eq!(result.actual, Some(0.0));
        }
    }

    #[test]
    fn duplicate_normalized_inventory_aliases_fail_closed() {
        let mut report = report(true);
        report.project.files.push(project_file("src/main.rs", 10));
        report.project.files[0].path = PathBuf::from("./src/main.rs");
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
                "files",
                GateOperator::Gte,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].actual, None);
        assert!(
            evaluated
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("duplicate"))
        );
    }

    #[test]
    fn genuinely_absent_inventory_path_stays_unavailable() {
        let mut report = report(true);
        let mut new_code = new_code_report(AssessmentStatus::Complete, Some(context()), Vec::new());
        new_code.lines[0].path = PathBuf::from("other.py");
        report.assessment = Some(assessment(None, Some(new_code)));
        let config = GateConfig {
            schema_version: 1,
            conditions: vec![condition(
                GateScope::NewCode,
                "files",
                GateOperator::Gte,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].status, GateStatus::Unavailable);
        assert_eq!(evaluated.conditions[0].actual, None);
        assert!(
            evaluated
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("absent from project inventory"))
        );
    }

    #[test]
    fn new_code_duplication_scopes_normalize_occurrence_paths() {
        let mut report = report(true);
        report.project.duplications.push(DuplicateGroup {
            language: "python".to_string(),
            occurrences: vec![DuplicateOccurrence {
                path: PathBuf::from("./src/main.rs"),
                start_line: 1,
                end_line: 1,
                start_byte: 0,
                end_byte: 9,
            }],
        });
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
            conditions: vec![
                condition(
                    GateScope::NewCode,
                    "duplicated_lines",
                    GateOperator::Eq,
                    1.0,
                ),
                condition(
                    GateScope::NewCode,
                    "duplicated_blocks",
                    GateOperator::Eq,
                    1.0,
                ),
                condition(
                    GateScope::NewCode,
                    "duplicated_files",
                    GateOperator::Eq,
                    1.0,
                ),
                condition(
                    GateScope::NewCode,
                    "duplicated_lines_density",
                    GateOperator::Gte,
                    100.0,
                ),
            ],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Pass);
        assert_eq!(evaluated.conditions[0].actual, Some(1.0));
        assert_eq!(evaluated.conditions[1].actual, Some(1.0));
        assert_eq!(evaluated.conditions[2].actual, Some(1.0));
        assert_eq!(evaluated.conditions[3].actual, Some(100.0));
    }

    #[test]
    fn genuinely_unmatched_duplication_occurrences_are_not_new_code() {
        let mut report = report(true);
        report.project.duplications.push(DuplicateGroup {
            language: "python".to_string(),
            occurrences: vec![DuplicateOccurrence {
                path: PathBuf::from("src/main.rs"),
                start_line: 5,
                end_line: 6,
                start_byte: 40,
                end_byte: 80,
            }],
        });
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
                GateOperator::Eq,
                0.0,
            )],
        };
        let evaluated = evaluate_gate(&config, &report);
        assert_eq!(evaluated.status, GateStatus::Pass);
        assert_eq!(evaluated.conditions[0].actual, Some(0.0));
    }
}
