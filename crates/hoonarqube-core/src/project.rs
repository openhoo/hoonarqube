//! Project-level orchestration for source measurements and duplication.
//!
//! A [`ProjectFile`] owns the one in-memory snapshot used to produce both the
//! issue report and parsed [`SourceFacts`]. The builder consumes those facts
//! when constructing duplication input, so token streams are never cloned.
//! Project size aggregates only complete source files; tests remain visible in
//! the inventory and issue-oriented `AnalysisReport::files`, but are excluded
//! from project size and duplication. Explicitly excluded, generated, and
//! vendor files are inventoried without being analyzed and do not make a
//! report incomplete.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hoonarqube_ir::{
    AnalysisReport, DuplicateGroup, DuplicationMetrics, FileClassification, FileMetrics,
    FileReport, MeasurementStatus, ProjectFileMeasurement, ProjectMetrics, ProjectReport,
};

use crate::duplication::{
    DuplicationFile, DuplicationOptions, DuplicationResult, detect_duplications,
};

use crate::source_facts::{SourceFacts, collect_source_facts, source_exceeds_limits};
use crate::{AnalyzerOptions, analyze, is_razor_path};

/// One input file and the facts gathered from its single source snapshot.
///
/// `report` and `facts` are intentionally separate owners: callers can retain
/// issue output while moving facts into duplication detection. `error` records
/// read, parser, or analyzer failures without manufacturing zero metrics.
#[derive(Debug)]
pub struct ProjectFile {
    pub path: PathBuf,
    pub classification: FileClassification,
    pub report: Option<FileReport>,
    pub facts: Option<SourceFacts>,
    pub error: Option<String>,
    pub duplication_excluded: bool,
}

/// Analyzes one source snapshot and collects the facts used by project
/// measurement. The returned report metrics are replaced by the parsed-facts
/// metrics whenever facts exist, keeping issue and project views consistent.
///
/// A parser can provide physical metrics while still reporting `facts.error`;
/// such a file remains failed in project aggregation and is never counted as a
/// successful project measurement or duplication denominator.
#[must_use]
pub fn analyze_project_file(
    path: &Path,
    source: &str,
    options: &AnalyzerOptions,
    classification: FileClassification,
    duplication_excluded: bool,
) -> ProjectFile {
    if !matches!(
        classification,
        FileClassification::Source | FileClassification::Test
    ) {
        return ProjectFile {
            path: path.to_path_buf(),
            classification,
            report: None,
            facts: None,
            error: None,
            duplication_excluded,
        };
    }

    let mut report = if is_razor_path(path) || source_exceeds_limits(path, source) {
        // Razor and resource-sized input have no safe native-analysis path;
        // source facts still retain bounded metrics and the failure reason.
        None
    } else {
        analyze(path, source, options)
    };
    let facts = collect_source_facts(path, source);
    let mut error = None;
    if let Some(facts) = facts.as_ref() {
        if let Some(facts_error) = facts.error.as_ref() {
            error = Some(facts_error.clone());
        }
        if let Some(report) = report.as_mut() {
            report.metrics = facts.metrics.clone();
        }
    } else if report.is_some() {
        error = Some("source facts unavailable for analyzed file".to_string());
    }

    if report.is_none() && facts.is_some() && error.is_none() {
        error = Some("analyzer did not produce a report".to_string());
    }

    ProjectFile {
        path: path.to_path_buf(),
        classification,
        report,
        facts,
        error,
        duplication_excluded,
    }
}

/// Builds the versioned report from per-file outcomes.
///
/// Inputs, roots, and warnings are normalized into stable path/order form.
/// Successful project size includes complete `Source` files only; complete
/// `Test` reports remain in the file inventory but do not affect project size.
/// Duplication is attempted only while the report is complete and every
/// eligible source has complete facts; otherwise the report is explicitly
/// incomplete and duplication fields remain absent rather than presenting a
/// partial result as complete.
///
/// # Errors
/// Returns an error when duplication options are invalid. Runtime duplication
/// failures are retained in the returned report as `complete = false` with a
/// warning, so already collected issue reports and file inventory are not lost.
pub fn build_project_report(
    mut inputs: Vec<ProjectFile>,
    mut roots: Vec<PathBuf>,
    mut warnings: Vec<String>,
    options: &DuplicationOptions,
) -> Result<AnalysisReport, String> {
    options.validate()?;

    roots.sort();
    roots.dedup();
    warnings.sort();
    warnings.dedup();
    inputs.sort_by(|left, right| {
        left.path.cmp(&right.path).then_with(|| {
            classification_order(left.classification)
                .cmp(&classification_order(right.classification))
        })
    });
    if let Some(pair) = inputs.windows(2).find(|pair| pair[0].path == pair[1].path) {
        return Err(format!(
            "duplicate project file path: {}",
            pair[0].path.display()
        ));
    }

    let mut aggregation = ProjectAggregation::new(inputs.len(), warnings.is_empty());
    for input in inputs {
        aggregation.add_input(input, &mut warnings);
    }
    aggregation
        .reports
        .sort_by(|left, right| left.path.cmp(&right.path));
    aggregation.attach_duplication(options, &mut warnings);

    warnings.sort();
    warnings.dedup();
    aggregation.clear_incomplete_duplication();
    aggregation.measurements.sort_by(|left, right| {
        left.path.cmp(&right.path).then_with(|| {
            classification_order(left.classification)
                .cmp(&classification_order(right.classification))
        })
    });

    let ProjectAggregation {
        complete,
        reports,
        measurements,
        project_metrics,
        duplications,
        project_duplication,
        ..
    } = aggregation;

    Ok(AnalysisReport {
        schema_version: 1,
        files: reports,
        project: ProjectReport {
            metrics: project_metrics,
            files: measurements,
            duplications,
            duplication: project_duplication,
            complete,
            warnings,
            roots,
        },
        assessment: None,
    })
}

struct ProjectAggregation {
    complete: bool,
    reports: Vec<FileReport>,
    measurements: Vec<ProjectFileMeasurement>,
    project_metrics: ProjectMetrics,
    duplication: DuplicationState,
    duplications: Vec<DuplicateGroup>,
    project_duplication: Option<DuplicationMetrics>,
}

#[derive(Debug, Default)]
struct DuplicationState {
    files: Vec<DuplicationFile>,
    measurement_indices: Vec<usize>,
    has_failed_eligible_source: bool,
}

struct DuplicationAttachment {
    groups: Vec<DuplicateGroup>,
    metrics: DuplicationMetrics,
}

impl ProjectAggregation {
    fn new(input_capacity: usize, complete: bool) -> Self {
        Self {
            complete,
            reports: Vec::new(),
            measurements: Vec::with_capacity(input_capacity),
            project_metrics: ProjectMetrics {
                files: 0,
                lines: 0,
                code_lines: 0,
                comment_lines: 0,
            },
            duplication: DuplicationState::default(),
            duplications: Vec::new(),
            project_duplication: None,
        }
    }

    fn add_input(&mut self, input: ProjectFile, warnings: &mut Vec<String>) {
        if matches!(
            input.classification,
            FileClassification::Source | FileClassification::Test
        ) {
            self.add_analyzed_input(input, warnings);
        } else {
            self.add_excluded_input(input);
        }
    }

    fn add_excluded_input(&mut self, input: ProjectFile) {
        let ProjectFile {
            path,
            classification,
            ..
        } = input;
        self.measurements.push(ProjectFileMeasurement {
            path,
            classification,
            status: MeasurementStatus::Excluded,
            metrics: None,
            duplication: None,
            reason: Some(exclusion_reason(classification)),
        });
    }

    fn add_analyzed_input(&mut self, input: ProjectFile, warnings: &mut Vec<String>) {
        let ProjectFile {
            path,
            classification,
            report,
            facts,
            error,
            duplication_excluded,
        } = input;
        let report_available = report.is_some();
        let (report, facts) = Self::normalize_report_metrics(report, facts);
        if let Some(report) = report {
            self.reports.push(report);
        }

        let (facts, metrics, status, mut reason) =
            Self::prepare_measurement(report_available, facts, error);
        if classification == FileClassification::Source {
            self.add_source_measurement(
                &path,
                metrics.as_ref(),
                facts,
                duplication_excluded,
                &mut reason,
            );
        }

        if status != MeasurementStatus::Complete {
            self.complete = false;
            if let Some(reason_text) = reason.as_ref() {
                warnings.push(format!("{}: {reason_text}", path.display()));
            }
        }

        self.measurements.push(ProjectFileMeasurement {
            path,
            classification,
            status,
            metrics,
            duplication: None,
            reason,
        });
    }

    fn normalize_report_metrics(
        report: Option<FileReport>,
        facts: Option<SourceFacts>,
    ) -> (Option<FileReport>, Option<SourceFacts>) {
        match (report, facts) {
            (Some(mut report), Some(facts)) => {
                report.metrics = facts.metrics.clone();
                (Some(report), Some(facts))
            }
            (report, facts) => (report, facts),
        }
    }

    fn prepare_measurement(
        report_available: bool,
        facts: Option<SourceFacts>,
        error: Option<String>,
    ) -> (
        Option<SourceFacts>,
        Option<FileMetrics>,
        MeasurementStatus,
        Option<String>,
    ) {
        let facts_error = facts
            .as_ref()
            .and_then(|facts| facts.error.clone())
            .or(error);
        let metrics = if facts_error.is_none() && report_available {
            facts.as_ref().map(|facts| facts.metrics.clone())
        } else {
            None
        };
        let status = if metrics.is_some() {
            MeasurementStatus::Complete
        } else if facts.is_none() && facts_error.is_none() && !report_available {
            MeasurementStatus::Unsupported
        } else {
            MeasurementStatus::Failed
        };
        let reason = if metrics.is_some() {
            None
        } else if let Some(error) = facts_error {
            Some(error)
        } else if status == MeasurementStatus::Unsupported {
            Some("language is unsupported".to_string())
        } else {
            Some("file analysis did not produce complete facts".to_string())
        };

        (facts, metrics, status, reason)
    }

    fn add_source_measurement(
        &mut self,
        path: &Path,
        metrics: Option<&FileMetrics>,
        facts: Option<SourceFacts>,
        duplication_excluded: bool,
        reason: &mut Option<String>,
    ) {
        match (metrics, facts) {
            (Some(metrics_for_project), Some(facts)) => {
                add_project_metrics(&mut self.project_metrics, metrics_for_project);
                if duplication_excluded || is_razor_path(path) {
                    // Razor compiler facts carry truthful source metrics but
                    // no native token stream; never feed them to CPD.
                    *reason = Some("excluded from duplication".to_string());
                } else {
                    let measurement_index = self.measurements.len();
                    self.duplication
                        .add_file(measurement_index, path.to_path_buf(), facts);
                }
            }
            _ => {
                self.duplication.has_failed_eligible_source = true;
            }
        }
    }

    fn attach_duplication(&mut self, options: &DuplicationOptions, warnings: &mut Vec<String>) {
        if self.duplication.has_failed_eligible_source {
            self.complete = false;
            warnings.push(
                "duplication analysis skipped because one or more eligible source files failed"
                    .to_string(),
            );
        }
        if !self.complete {
            return;
        }

        match detect_duplications(&self.duplication.files, options) {
            Ok(result) => match attach_duplication_result(
                result,
                &mut self.measurements,
                &self.duplication.measurement_indices,
            ) {
                Ok(attachment) => {
                    self.duplications = attachment.groups;
                    self.project_duplication = Some(attachment.metrics);
                }
                Err(missing) => {
                    self.complete = false;
                    warnings.push(format!(
                        "duplication analysis omitted metrics for {missing} eligible file(s)"
                    ));
                }
            },
            Err(error) => {
                self.complete = false;
                warnings.push(format!("duplication analysis incomplete: {error}"));
            }
        }
    }

    fn clear_incomplete_duplication(&mut self) {
        if self.complete {
            return;
        }
        self.duplications.clear();
        self.project_duplication = None;
        for measurement in &mut self.measurements {
            measurement.duplication = None;
        }
    }
}

impl DuplicationState {
    fn add_file(&mut self, measurement_index: usize, path: PathBuf, facts: SourceFacts) {
        self.measurement_indices.push(measurement_index);
        self.files.push(DuplicationFile {
            path,
            language: facts.language,
            facts,
        });
    }
}

fn attach_duplication_result(
    result: DuplicationResult,
    measurements: &mut [ProjectFileMeasurement],
    measurement_indices: &[usize],
) -> Result<DuplicationAttachment, usize> {
    let mut by_path: BTreeMap<PathBuf, Vec<DuplicationMetrics>> = BTreeMap::new();
    for file in result.files {
        by_path.entry(file.path).or_default().push(file.metrics);
    }

    let mut assigned = Vec::with_capacity(measurement_indices.len());
    let mut missing = 0_usize;
    for &measurement_index in measurement_indices {
        let Some(measurement) = measurements.get(measurement_index) else {
            missing += 1;
            continue;
        };
        match by_path.get_mut(&measurement.path).and_then(Vec::pop) {
            Some(metrics) => assigned.push((measurement_index, metrics)),
            None => missing += 1,
        }
    }
    if missing != 0 {
        return Err(missing);
    }

    for (index, metrics) in assigned {
        if let Some(measurement) = measurements.get_mut(index) {
            measurement.duplication = Some(metrics);
        } else {
            return Err(1);
        }
    }

    Ok(DuplicationAttachment {
        groups: result.groups,
        metrics: result.metrics,
    })
}
fn classification_order(classification: FileClassification) -> u8 {
    match classification {
        FileClassification::Source => 0,
        FileClassification::Test => 1,
        FileClassification::Generated => 2,
        FileClassification::Vendor => 3,
        FileClassification::Excluded => 4,
    }
}

fn exclusion_reason(classification: FileClassification) -> String {
    match classification {
        FileClassification::Generated => "generated file".to_string(),
        FileClassification::Vendor => "vendor file".to_string(),
        FileClassification::Excluded => "explicitly excluded".to_string(),
        FileClassification::Source | FileClassification::Test => "excluded".to_string(),
    }
}

fn add_project_metrics(metrics: &mut ProjectMetrics, file: &FileMetrics) {
    metrics.files = metrics.files.saturating_add(1);
    metrics.lines = metrics.lines.saturating_add(u64::from(file.lines));
    metrics.code_lines = metrics
        .code_lines
        .saturating_add(u64::from(file.code_lines));
    metrics.comment_lines = metrics
        .comment_lines
        .saturating_add(u64::from(file.comment_lines));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Language, source_facts::NormalizedToken};

    fn facts(_path: &str, error: Option<&str>) -> SourceFacts {
        SourceFacts {
            metrics: FileMetrics {
                lines: 3,
                code_lines: 2,
                comment_lines: 1,
            },
            tokens: vec![NormalizedToken {
                symbol: 0,
                start_line: 1,
                end_line: 1,
                start_byte: 0,
                end_byte: 5,
            }],
            symbols: vec!["value".to_string()],
            error: error.map(str::to_string),
            language: Language::Python,
        }
    }

    fn input(
        path: &str,
        classification: FileClassification,
        facts: Option<SourceFacts>,
        error: Option<&str>,
    ) -> ProjectFile {
        ProjectFile {
            path: PathBuf::from(path),
            classification,
            report: Some(FileReport {
                path: PathBuf::from(path),
                language: "python".to_string(),
                issues: Vec::new(),
                metrics: FileMetrics {
                    lines: 99,
                    code_lines: 99,
                    comment_lines: 99,
                },
            }),
            facts,
            error: error.map(str::to_string),
            duplication_excluded: false,
        }
    }

    #[test]
    fn project_aggregates_source_only_and_keeps_test_excluded() {
        let report = build_project_report(
            vec![
                input(
                    "tests/test.py",
                    FileClassification::Test,
                    Some(facts("tests/test.py", None)),
                    None,
                ),
                input(
                    "src/app.py",
                    FileClassification::Source,
                    Some(facts("src/app.py", None)),
                    None,
                ),
                input(
                    "vendor/lib.py",
                    FileClassification::Vendor,
                    Some(facts("vendor/lib.py", None)),
                    None,
                ),
            ],
            vec![PathBuf::from("."), PathBuf::from("src"), PathBuf::from(".")],
            Vec::new(),
            &DuplicationOptions::default(),
        )
        .expect("valid options");

        assert_eq!(report.project.metrics.files, 1);
        assert_eq!(report.project.metrics.lines, 3);
        assert!(report.project.complete);
        assert_eq!(report.project.files.len(), 3);
        let source = report
            .project
            .files
            .iter()
            .find(|file| file.path == Path::new("src/app.py"))
            .expect("source inventory");
        assert_eq!(source.status, MeasurementStatus::Complete);
        assert_eq!(
            source
                .duplication
                .as_ref()
                .map(|metrics| metrics.duplicated_lines),
            Some(0)
        );
        let test = report
            .project
            .files
            .iter()
            .find(|file| file.path == Path::new("tests/test.py"))
            .expect("test inventory");
        assert_eq!(test.duplication, None);
        assert_eq!(
            report.project.roots,
            vec![PathBuf::from("."), PathBuf::from("src")]
        );
        assert_eq!(report.files.len(), 2);
        assert!(
            report
                .files
                .iter()
                .all(|file| file.path != Path::new("vendor/lib.py"))
        );
    }

    #[test]
    fn walker_warnings_make_report_incomplete_without_fake_duplication() {
        let report = build_project_report(
            vec![input(
                "src/app.py",
                FileClassification::Source,
                Some(facts("src/app.py", None)),
                None,
            )],
            Vec::new(),
            vec!["read failed".to_string()],
            &DuplicationOptions::default(),
        )
        .expect("valid options");

        assert!(!report.project.complete);
        assert_eq!(report.project.duplication, None);
        assert_eq!(report.project.files[0].duplication, None);
        assert_eq!(report.project.warnings, vec!["read failed".to_string()]);
    }

    #[test]
    fn failed_facts_are_not_project_measurements_or_duplication_zeroes() {
        let report = build_project_report(
            vec![input(
                "broken.py",
                FileClassification::Source,
                Some(facts("broken.py", Some("syntax error"))),
                None,
            )],
            Vec::new(),
            Vec::new(),
            &DuplicationOptions::default(),
        )
        .expect("valid options");

        assert!(!report.project.complete);
        assert_eq!(report.project.metrics.files, 0);
        assert_eq!(report.project.duplication, None);
        assert_eq!(report.project.files[0].status, MeasurementStatus::Failed);
        assert_eq!(report.project.files[0].metrics, None);
        assert_eq!(report.project.files[0].duplication, None);
    }
    #[test]
    fn report_without_facts_is_failed_not_unsupported() {
        let report = build_project_report(
            vec![input(
                "missing-facts.py",
                FileClassification::Source,
                None,
                None,
            )],
            Vec::new(),
            Vec::new(),
            &DuplicationOptions::default(),
        )
        .expect("valid options");

        assert!(!report.project.complete);
        assert_eq!(report.project.metrics.files, 0);
        assert_eq!(report.project.files[0].status, MeasurementStatus::Failed);
        assert_eq!(
            report.project.files[0].reason.as_deref(),
            Some("file analysis did not produce complete facts")
        );
        assert_eq!(report.project.duplication, None);
    }
    #[test]
    fn project_report_uses_javascript_semantic_line_metrics() {
        let path = Path::new("sample.js");
        let source = "// comment\r\nlet x = 1;\u{2028}let y = 2;\u{2029}";
        let input = analyze_project_file(
            path,
            source,
            &AnalyzerOptions::default(),
            FileClassification::Source,
            false,
        );
        let file_report = input.report.as_ref().expect("JavaScript report");
        assert_eq!(file_report.metrics.lines, 3);
        assert_eq!(file_report.metrics.code_lines, 2);
        assert_eq!(file_report.metrics.comment_lines, 1);

        let report = build_project_report(
            vec![input],
            Vec::new(),
            Vec::new(),
            &DuplicationOptions::default(),
        )
        .expect("valid options");
        assert!(report.project.complete);
        assert_eq!(report.project.metrics.files, 1);
        assert_eq!(report.project.metrics.lines, 3);
        assert_eq!(report.project.metrics.code_lines, 2);
        assert_eq!(report.project.metrics.comment_lines, 1);
        assert_eq!(report.files[0].metrics.lines, 3);
        assert_eq!(report.files[0].metrics.code_lines, 2);
        assert_eq!(report.files[0].metrics.comment_lines, 1);
    }
    #[test]
    fn resource_limited_source_skips_native_analyzer() {
        let source = "\n".repeat(4 * 1024 * 1024 + 1);
        let input = analyze_project_file(
            Path::new("too-many-lines.py"),
            &source,
            &AnalyzerOptions::default(),
            FileClassification::Source,
            false,
        );
        assert!(input.report.is_none());
        let facts = input.facts.as_ref().expect("bounded facts");
        assert!(facts.error.is_some());
        assert_eq!(facts.metrics.lines, 4 * 1024 * 1024 + 1);
        assert_eq!(facts.metrics.code_lines, 0);
        assert_eq!(facts.metrics.comment_lines, 0);

        let report = build_project_report(
            vec![input],
            Vec::new(),
            Vec::new(),
            &DuplicationOptions::default(),
        )
        .expect("valid options");
        assert!(!report.project.complete);
        assert_eq!(report.project.metrics.files, 0);
        assert_eq!(report.project.duplication, None);
        assert_eq!(report.project.files[0].status, MeasurementStatus::Failed);
    }
    #[test]
    fn syntax_errors_retain_issue_report_while_failing_measurement() {
        let input = analyze_project_file(
            Path::new("syntax-error.py"),
            "def broken(:\n    pass\n",
            &AnalyzerOptions::default(),
            FileClassification::Source,
            false,
        );
        assert!(input.report.is_some());
        assert!(
            input
                .facts
                .as_ref()
                .is_some_and(|facts| facts.error.is_some())
        );

        let report = build_project_report(
            vec![input],
            Vec::new(),
            Vec::new(),
            &DuplicationOptions::default(),
        )
        .expect("valid options");
        assert!(!report.project.complete);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.project.files[0].status, MeasurementStatus::Failed);
        assert_eq!(report.project.duplication, None);
    }
}
