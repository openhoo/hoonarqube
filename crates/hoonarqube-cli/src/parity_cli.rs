//! `sonar-parity` contract construction and optional reference comparison.
//!
//! The `sonar-parity` profile claims comparability with a pinned `SonarQube`
//! reference analysis. This module builds the machine-verifiable contract
//! attached to [`hoonarqube_ir::AnalysisReport::parity`] and, when
//! `--parity-reference` is supplied, compares the native finding identity
//! multiset against a pinned Generic Issue Import reference report.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;

use hoonarqube_catalog::{Catalog, RuleProfile};
use hoonarqube_ir::parity::{
    ParityActiveRule, ParityComparison, ParityComparisonStatus, ParityCompleteness,
    ParityContextStatus, ParityDivergence, ParityReference, ParityReport, ParityRuleParameter,
    ParityScope, ParitySemanticContext,
};
use hoonarqube_ir::{AnalysisReport, FileClassification};

use crate::analyze::{AnalyzerOptionsBundle, ProjectAnalysisOptions};
use crate::semantic_cli::ProjectSemanticContext;

/// Builds the `sonar-parity` contract for one completed analysis.
///
/// The contract is emitted only when the effective profile is `sonar-parity`;
/// every other profile leaves `report.parity` as `None`.
pub(crate) fn attach_parity_contract(
    report: &mut AnalysisReport,
    catalog: &Catalog,
    options: &AnalyzerOptionsBundle,
    project_options: &ProjectAnalysisOptions,
    semantic: Option<&ProjectSemanticContext>,
) {
    if options.profile != RuleProfile::SonarParity {
        return;
    }

    let active_rules = collect_active_rules(catalog, report);
    let scope = collect_scope(report, project_options);
    let semantic_context = collect_semantic_context(report, semantic);
    let rule_set_violations = collect_rule_set_violations(report, &active_rules);

    let completeness = if !report.project.complete
        || !rule_set_violations.is_empty()
        || semantic_context.typescript == ParityContextStatus::Missing
        || semantic_context.csharp == ParityContextStatus::Missing
    {
        ParityCompleteness::Incomplete
    } else {
        ParityCompleteness::CompleteNativeAnalysis
    };

    report.parity = Some(ParityReport {
        reference: ParityReference {
            sonarqube_version: catalog.snapshot().server_version.clone(),
            profile: "sonar-parity".to_owned(),
            captured_at_utc: catalog.snapshot().captured_at_utc.clone(),
            capture_sha256: catalog.snapshot().capture_sha256.clone(),
        },
        active_rules,
        scope,
        semantic_context,
        completeness,
        rule_set_violations,
        comparison: None,
    });
}

/// Compares this run against a pinned Generic Issue Import reference report
/// and records the outcome in the parity block.
///
/// The run's findings are projected through the same Generic Issue Import
/// export used by `--format sonar`, so both sides share the Sonar UTF-16
/// text-range contract and identities compare symmetrically. A matched
/// comparison upgrades `completeness` to `reference_parity_verified` only
/// when every prerequisite already held; a divergence fails closed with
/// `incomplete`.
///
/// # Errors
/// Returns an error when the run has no parity block (non-parity profile),
/// when the run's findings cannot be projected, or when the reference cannot
/// be read, parsed, or validated.
pub(crate) fn attach_comparison(
    report: &mut AnalysisReport,
    catalog: &Catalog,
    reference_path: &Path,
) -> Result<(), String> {
    if report.parity.is_none() {
        return Err("--parity-reference requires --profile sonar-parity".to_owned());
    }
    let native_document = crate::sonar_import_value(catalog, &report.files)
        .map_err(|error| format!("cannot project findings for parity comparison: {error}"))?;
    let comparison = compare_reference(&native_document, reference_path)?;
    let diverged = comparison.status == ParityComparisonStatus::Diverged;
    let parity = report.parity.as_mut().expect("parity block checked above");
    parity.completeness = if diverged {
        ParityCompleteness::Incomplete
    } else if parity.completeness == ParityCompleteness::CompleteNativeAnalysis {
        ParityCompleteness::ReferenceParityVerified
    } else {
        ParityCompleteness::Incomplete
    };
    parity.comparison = Some(comparison);
    Ok(())
}

/// Collects the catalog's `sonar-parity` membership for the languages present
/// in the analyzed scope, in ascending key order.
fn collect_active_rules(catalog: &Catalog, report: &AnalysisReport) -> Vec<ParityActiveRule> {
    let mut catalog_names = BTreeSet::new();
    for file in &report.project.files {
        if let Some(language) = hoonarqube_core::language_for_path(&file.path) {
            catalog_names.insert(language_catalog_name(language));
        }
    }

    let mut rules = Vec::new();
    for catalog_name in catalog_names {
        let Some(language_catalog) = catalog.language(catalog_name) else {
            continue;
        };
        for rule in language_catalog.rules() {
            if hoonarqube_core::SONAR_PARITY_INACTIVE_RULE_KEYS
                .contains(&rule.external_key.as_str())
            {
                continue;
            }
            rules.push(ParityActiveRule {
                key: rule.external_key.clone(),
                parameters: rule
                    .parameters
                    .iter()
                    .map(|parameter| ParityRuleParameter {
                        key: parameter.key.clone(),
                        default_value: parameter.default_value.clone(),
                        parameter_type: parameter.parameter_type.clone(),
                    })
                    .collect(),
                fidelity: rule.classification.clone(),
            });
        }
    }
    rules.sort_by(|left, right| left.key.cmp(&right.key));
    rules
}

/// Maps a core language to its embedded catalog name.
fn language_catalog_name(language: hoonarqube_core::Language) -> &'static str {
    match language {
        hoonarqube_core::Language::CSharp => "csharp",
        // Web templates run the JavaScript rule battery on their inline
        // scripts; the catalog has no separate `html` language.
        hoonarqube_core::Language::JavaScript | hoonarqube_core::Language::Html => "javascript",
        hoonarqube_core::Language::TypeScript => "typescript",
        hoonarqube_core::Language::Python => "python",
        hoonarqube_core::Language::Go => "go",
        hoonarqube_core::Language::Rust => "rust",
        hoonarqube_core::Language::Java => "java",
        hoonarqube_core::Language::Ruby => "ruby",
    }
}
/// Collects the normalized analysis scope and per-classification file counts.
fn collect_scope(report: &AnalysisReport, project_options: &ProjectAnalysisOptions) -> ParityScope {
    let mut file_counts = BTreeMap::new();
    for classification in [
        FileClassification::Source,
        FileClassification::Test,
        FileClassification::Generated,
        FileClassification::Vendor,
        FileClassification::Excluded,
    ] {
        file_counts.insert(classification_key(classification).to_owned(), 0_u64);
    }
    for file in &report.project.files {
        *file_counts
            .entry(classification_key(file.classification).to_owned())
            .or_insert(0) += 1;
    }

    ParityScope {
        roots: report.project.roots.clone(),
        test_include: project_options.raw_patterns.test_include.clone(),
        exclude: project_options.raw_patterns.exclude.clone(),
        generated_include: project_options.raw_patterns.generated_include.clone(),
        vendor_include: project_options.raw_patterns.vendor_include.clone(),
        duplication_exclude: project_options.raw_patterns.duplication_exclude.clone(),
        file_counts,
    }
}

fn classification_key(classification: FileClassification) -> &'static str {
    match classification {
        FileClassification::Source => "source",
        FileClassification::Test => "test",
        FileClassification::Generated => "generated",
        FileClassification::Vendor => "vendor",
        FileClassification::Excluded => "excluded",
    }
}

/// Collects semantic-context coverage for the language families whose
/// parity-relevant rules need compiler/project facts.
fn collect_semantic_context(
    report: &AnalysisReport,
    semantic: Option<&ProjectSemanticContext>,
) -> ParitySemanticContext {
    let mut jsts_files = Vec::new();
    let mut has_csharp = false;
    for file in &report.project.files {
        // Only analyzed classifications consume semantic context;
        // inventoried generated/vendor/excluded entries never reach an
        // analyzer.
        if !matches!(
            file.classification,
            FileClassification::Source | FileClassification::Test
        ) {
            continue;
        }
        match hoonarqube_core::language_for_path(&file.path) {
            Some(hoonarqube_core::Language::JavaScript | hoonarqube_core::Language::TypeScript) => {
                jsts_files.push(file.path.as_path());
            }
            Some(hoonarqube_core::Language::CSharp) => {
                has_csharp = true;
            }
            _ => {}
        }
    }

    // A JS/TS context counts as supplied only when a complete context
    // covered every analyzed file: either the explicit --typescript-project
    // context, or a complete auto-discovered tsconfig context per file.
    let typescript = if jsts_files.is_empty() {
        ParityContextStatus::NotApplicable
    } else if semantic.is_some_and(|context| {
        context
            .jsts()
            .is_some_and(hoonarqube_jsts::project_context::ProjectSemanticContext::is_complete)
            || jsts_files.iter().all(|path| {
                context
                    .jsts_auto()
                    .iter()
                    .any(|auto| auto.is_complete() && auto.file_facts(path).is_some())
            })
    }) {
        ParityContextStatus::Supplied
    } else {
        ParityContextStatus::Missing
    };

    let csharp = if !has_csharp {
        ParityContextStatus::NotApplicable
    } else if semantic.is_some_and(|context| {
        context
            .csharp()
            .is_some_and(hoonarqube_csharp::semantic::ProjectSemanticContext::is_complete)
    }) {
        ParityContextStatus::Supplied
    } else {
        ParityContextStatus::Missing
    };

    ParitySemanticContext { typescript, csharp }
}

/// Collects emitted rule keys outside the recorded active set.
fn collect_rule_set_violations(
    report: &AnalysisReport,
    active_rules: &[ParityActiveRule],
) -> Vec<String> {
    let active: BTreeSet<&str> = active_rules.iter().map(|rule| rule.key.as_str()).collect();
    let mut violations = BTreeSet::new();
    for file in &report.files {
        for issue in &file.issues {
            if !active.contains(issue.rule_key.as_str()) {
                violations.insert(issue.rule_key.clone());
            }
        }
    }
    violations.into_iter().collect()
}

/// Compares the projected Generic Issue Import document of this run against
/// a pinned reference report. Both sides share the same coordinate contract
/// (Sonar UTF-16 text ranges), so identities are symmetric.
///
/// # Errors
/// Returns an error when the reference cannot be read, is not valid JSON, or
/// does not satisfy the Generic Issue Import shape (`issues` array with
/// `ruleId` and `primaryLocation.filePath` per entry).
fn compare_reference(
    native_document: &serde_json::Value,
    reference_path: &Path,
) -> Result<ParityComparison, String> {
    let content = std::fs::read_to_string(reference_path).map_err(|error| {
        format!(
            "cannot read parity reference {}: {error}",
            reference_path.display()
        )
    })?;
    let reference: serde_json::Value = serde_json::from_str(&content).map_err(|error| {
        format!(
            "cannot parse parity reference {}: {error}",
            reference_path.display()
        )
    })?;

    let reference_issues = extract_sonar_issues(&reference).map_err(|error| {
        format!(
            "invalid parity reference {}: {error}",
            reference_path.display()
        )
    })?;
    let native_issues = extract_sonar_issues(native_document)
        .map_err(|error| format!("invalid native Sonar projection: {error}"))?;

    let mut divergences = Vec::new();
    let mut reference_counts: BTreeMap<_, u64> = BTreeMap::new();
    for issue in &reference_issues {
        *reference_counts.entry(issue.clone()).or_insert(0) += 1;
    }
    let mut native_counts: BTreeMap<_, u64> = BTreeMap::new();
    for issue in &native_issues {
        *native_counts.entry(issue.clone()).or_insert(0) += 1;
    }

    for (identity, count) in &reference_counts {
        let native_count = native_counts.get(identity).copied().unwrap_or(0);
        if *count > native_count {
            divergences.push(ParityDivergence {
                kind: "only_in_reference".to_owned(),
                rule: identity.rule.clone(),
                path: identity.path.clone(),
                start_line: identity.start_line,
                start_offset: identity.start_offset,
                end_line: identity.end_line,
                end_offset: identity.end_offset,
                count: count - native_count,
            });
        }
    }
    for (identity, count) in &native_counts {
        let reference_count = reference_counts.get(identity).copied().unwrap_or(0);
        if *count > reference_count {
            divergences.push(ParityDivergence {
                kind: "only_in_native".to_owned(),
                rule: identity.rule.clone(),
                path: identity.path.clone(),
                start_line: identity.start_line,
                start_offset: identity.start_offset,
                end_line: identity.end_line,
                end_offset: identity.end_offset,
                count: count - reference_count,
            });
        }
    }
    divergences.sort_by(|left, right| {
        (
            left.kind.as_str(),
            left.rule.as_str(),
            left.path.as_str(),
            left.start_line,
            left.start_offset,
        )
            .cmp(&(
                right.kind.as_str(),
                right.rule.as_str(),
                right.path.as_str(),
                right.start_line,
                right.start_offset,
            ))
    });

    Ok(ParityComparison {
        reference_path: reference_path.to_path_buf(),
        status: if divergences.is_empty() {
            ParityComparisonStatus::Matched
        } else {
            ParityComparisonStatus::Diverged
        },
        reference_issues: u64::try_from(reference_issues.len()).unwrap_or(u64::MAX),
        native_issues: u64::try_from(native_issues.len()).unwrap_or(u64::MAX),
        divergences,
    })
}

/// One finding identity used for multiset comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct IssueIdentity {
    rule: String,
    path: String,
    start_line: Option<u32>,
    start_offset: Option<u32>,
    end_line: Option<u32>,
    end_offset: Option<u32>,
}

/// Extracts finding identities from a Generic Issue Import document.
///
/// The document must be an object with an `issues` array; every issue needs
/// a string `ruleId` and a `primaryLocation` object with a string
/// `filePath`. `textRange` is optional (file-level findings omit it); when
/// present its four endpoints must be non-negative integers.
///
fn extract_sonar_issues(value: &serde_json::Value) -> Result<Vec<IssueIdentity>, String> {
    let array = value
        .get("issues")
        .and_then(|issues| issues.as_array())
        .ok_or_else(|| "document must contain an issues array".to_owned())?;
    let mut issues = Vec::with_capacity(array.len());
    for (index, issue) in array.iter().enumerate() {
        let context = format!("issue {index}");
        let rule = issue
            .get("ruleId")
            .and_then(|rule| rule.as_str())
            .ok_or_else(|| format!("{context}: ruleId must be a string"))?
            .to_owned();
        let location = issue
            .get("primaryLocation")
            .and_then(|location| location.as_object())
            .ok_or_else(|| format!("{context}: primaryLocation must be an object"))?;
        let path = location
            .get("filePath")
            .and_then(|path| path.as_str())
            .ok_or_else(|| format!("{context}: primaryLocation.filePath must be a string"))?
            .to_owned();
        let range = location.get("textRange");
        let endpoint = |range: &serde_json::Value, key: &str| -> Result<Option<u32>, String> {
            range
                .get(key)
                .and_then(serde_json::Value::as_u64)
                .map(|value| {
                    u32::try_from(value)
                        .map_err(|_| format!("{context}: textRange.{key} exceeds u32"))
                })
                .transpose()
        };
        let (start_line, start_offset, end_line, end_offset) = match range {
            None | Some(serde_json::Value::Null) => (None, None, None, None),
            Some(range) => (
                endpoint(range, "startLine")?,
                endpoint(range, "startColumn")?,
                endpoint(range, "endLine")?,
                endpoint(range, "endColumn")?,
            ),
        };
        issues.push(IssueIdentity {
            rule,
            path,
            start_line,
            start_offset,
            end_line,
            end_offset,
        });
    }
    Ok(issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use hoonarqube_ir::{
        FileMetrics, FileReport, Issue, Pos, ProjectFileMeasurement, ProjectMetrics, ProjectReport,
        Range,
    };

    use crate::analyze::{ProjectPatternLists, project_analysis_options};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "hoonarqube-parity-cli-{tag}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn issue(
        rule_key: &str,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> Issue {
        Issue {
            rule_key: rule_key.to_owned(),
            message: format!("finding for {rule_key}"),
            range: Range {
                start: Pos {
                    line: start_line,
                    column: start_column,
                },
                end: Pos {
                    line: end_line,
                    column: end_column,
                },
            },
            fix: None,
            alternatives: Vec::new(),
            flows: Vec::new(),
        }
    }

    fn file_report(path: &Path, language: &str, issues: Vec<Issue>) -> FileReport {
        FileReport {
            path: path.to_path_buf(),
            language: language.to_owned(),
            issues,
            metrics: FileMetrics {
                lines: 4,
                code_lines: 4,
                comment_lines: 0,
            },
        }
    }

    fn measurement(path: &Path, classification: FileClassification) -> ProjectFileMeasurement {
        ProjectFileMeasurement {
            path: path.to_path_buf(),
            classification,
            status: hoonarqube_ir::MeasurementStatus::Complete,
            metrics: None,
            duplication: None,
            reason: None,
        }
    }

    fn analysis_report(
        files: Vec<FileReport>,
        project_files: Vec<ProjectFileMeasurement>,
        complete: bool,
    ) -> AnalysisReport {
        AnalysisReport {
            schema_version: 1,
            files,
            project: ProjectReport {
                metrics: ProjectMetrics {
                    files: 0,
                    lines: 0,
                    code_lines: 0,
                    comment_lines: 0,
                },
                files: project_files,
                duplications: Vec::new(),
                duplication: None,
                complete,
                warnings: Vec::new(),
                roots: vec![PathBuf::from(".")],
            },
            assessment: None,
            parity: None,
        }
    }

    fn project_options() -> ProjectAnalysisOptions {
        project_analysis_options(
            ProjectPatternLists {
                exclude: &[],
                test_include: &[],
                generated_include: &[],
                vendor_include: &[],
                duplication_exclude: &[],
            },
            100,
            10,
            10,
        )
        .expect("default project options")
    }

    fn parity_options() -> AnalyzerOptionsBundle {
        AnalyzerOptionsBundle {
            profile: RuleProfile::SonarParity,
            ..AnalyzerOptionsBundle::default()
        }
    }

    /// A rule key guaranteed to be active in `sonar-parity` for the given
    /// embedded language catalog.
    fn active_rule_key(catalog: &Catalog, language: &str) -> String {
        catalog
            .language(language)
            .and_then(|language_catalog| {
                language_catalog.rules().iter().find(|rule| {
                    !hoonarqube_core::SONAR_PARITY_INACTIVE_RULE_KEYS
                        .contains(&rule.external_key.as_str())
                })
            })
            .map(|rule| rule.external_key.clone())
            .expect("language catalog has at least one parity-active rule")
    }

    #[test]
    fn non_parity_profile_emits_no_block() {
        let catalog = hoonarqube_catalog::embedded();
        let path = PathBuf::from("src/app.py");
        let mut report = analysis_report(
            vec![file_report(&path, "python", Vec::new())],
            vec![measurement(&path, FileClassification::Source)],
            true,
        );
        let options = AnalyzerOptionsBundle {
            profile: RuleProfile::Recommended,
            ..AnalyzerOptionsBundle::default()
        };
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);
        assert!(report.parity.is_none());
    }

    #[test]
    fn parity_block_records_scope_and_active_rules() {
        let catalog = hoonarqube_catalog::embedded();
        let source = PathBuf::from("src/app.py");
        let test = PathBuf::from("tests/test_app.py");
        let vendor = PathBuf::from("vendor/lib.py");
        let mut report = analysis_report(
            vec![file_report(&source, "python", Vec::new())],
            vec![
                measurement(&source, FileClassification::Source),
                measurement(&test, FileClassification::Test),
                measurement(&vendor, FileClassification::Vendor),
            ],
            true,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        let parity = report.parity.expect("parity block");
        assert_eq!(parity.reference.profile, "sonar-parity");
        assert_eq!(
            parity.reference.sonarqube_version,
            catalog.snapshot().server_version
        );
        assert_eq!(
            parity.reference.capture_sha256,
            catalog.snapshot().capture_sha256
        );
        assert_eq!(parity.scope.file_counts.get("source"), Some(&1));
        assert_eq!(parity.scope.file_counts.get("test"), Some(&1));
        assert_eq!(parity.scope.file_counts.get("vendor"), Some(&1));
        assert_eq!(parity.scope.file_counts.get("generated"), Some(&0));
        assert_eq!(parity.scope.file_counts.get("excluded"), Some(&0));
        assert_eq!(
            parity.semantic_context.typescript,
            ParityContextStatus::NotApplicable
        );
        assert_eq!(
            parity.semantic_context.csharp,
            ParityContextStatus::NotApplicable
        );
        assert_eq!(
            parity.completeness,
            ParityCompleteness::CompleteNativeAnalysis
        );
        assert!(parity.rule_set_violations.is_empty());
        assert!(parity.comparison.is_none());

        // The active set is the python catalog minus the two reference-inactive
        // keys, strictly sorted, each with catalog fidelity.
        let expected: Vec<String> = catalog
            .language("python")
            .expect("python catalog")
            .rules()
            .iter()
            .filter(|rule| {
                !hoonarqube_core::SONAR_PARITY_INACTIVE_RULE_KEYS
                    .contains(&rule.external_key.as_str())
            })
            .map(|rule| rule.external_key.clone())
            .collect();
        let actual: Vec<String> = parity
            .active_rules
            .iter()
            .map(|rule| rule.key.clone())
            .collect();
        assert_eq!(actual, expected);
        assert!(
            parity
                .active_rules
                .iter()
                .all(|rule| !rule.fidelity.is_empty())
        );
    }

    #[test]
    fn missing_typescript_context_marks_incomplete() {
        let catalog = hoonarqube_catalog::embedded();
        let path = PathBuf::from("src/app.ts");
        let mut report = analysis_report(
            vec![file_report(&path, "typescript", Vec::new())],
            vec![measurement(&path, FileClassification::Source)],
            true,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        let parity = report.parity.expect("parity block");
        assert_eq!(
            parity.semantic_context.typescript,
            ParityContextStatus::Missing
        );
        assert_eq!(
            parity.semantic_context.csharp,
            ParityContextStatus::NotApplicable
        );
        assert_eq!(parity.completeness, ParityCompleteness::Incomplete);
    }

    #[test]
    fn missing_csharp_context_marks_incomplete() {
        let catalog = hoonarqube_catalog::embedded();
        let path = PathBuf::from("src/App.cs");
        let mut report = analysis_report(
            vec![file_report(&path, "csharp", Vec::new())],
            vec![measurement(&path, FileClassification::Source)],
            true,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        let parity = report.parity.expect("parity block");
        assert_eq!(parity.semantic_context.csharp, ParityContextStatus::Missing);
        assert_eq!(parity.completeness, ParityCompleteness::Incomplete);
    }

    #[test]
    fn excluded_jsts_inventory_does_not_require_context() {
        let catalog = hoonarqube_catalog::embedded();
        let path = PathBuf::from("vendor/bundle.js");
        let mut report = analysis_report(
            Vec::new(),
            vec![measurement(&path, FileClassification::Vendor)],
            true,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        let parity = report.parity.expect("parity block");
        assert_eq!(
            parity.semantic_context.typescript,
            ParityContextStatus::NotApplicable
        );
        assert_eq!(
            parity.completeness,
            ParityCompleteness::CompleteNativeAnalysis
        );
    }

    #[test]
    fn emitted_rules_outside_active_set_are_violations() {
        let catalog = hoonarqube_catalog::embedded();
        let path = PathBuf::from("src/app.py");
        let mut report = analysis_report(
            vec![file_report(
                &path,
                "python",
                vec![issue("python:S99999", 1, 0, 1, 1)],
            )],
            vec![measurement(&path, FileClassification::Source)],
            true,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        let parity = report.parity.expect("parity block");
        assert_eq!(parity.rule_set_violations, vec!["python:S99999".to_owned()]);
        assert_eq!(parity.completeness, ParityCompleteness::Incomplete);
    }

    #[test]
    fn incomplete_project_marks_incomplete() {
        let catalog = hoonarqube_catalog::embedded();
        let path = PathBuf::from("src/app.py");
        let mut report = analysis_report(
            vec![file_report(&path, "python", Vec::new())],
            vec![measurement(&path, FileClassification::Source)],
            false,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        let parity = report.parity.expect("parity block");
        assert_eq!(parity.completeness, ParityCompleteness::Incomplete);
    }

    fn reference_document(path: &Path, rule: &str) -> serde_json::Value {
        serde_json::json!({
            "rules": [],
            "issues": [{
                "engineId": "hoonarqube",
                "ruleId": rule,
                "severity": "MAJOR",
                "type": "CODE_SMELL",
                "primaryLocation": {
                    "message": "finding",
                    "filePath": path.to_string_lossy(),
                    "textRange": {
                        "startLine": 1,
                        "startColumn": 0,
                        "endLine": 1,
                        "endColumn": 1,
                    }
                }
            }]
        })
    }

    #[test]
    fn matched_reference_verifies_parity() {
        let catalog = hoonarqube_catalog::embedded();
        let temp = TempDir::new("matched");
        let source = temp.0.join("app.py");
        std::fs::write(&source, "x = 1\n").expect("write source");
        let rule = active_rule_key(catalog, "python");

        let mut report = analysis_report(
            vec![file_report(
                &source,
                "python",
                vec![issue(&rule, 1, 0, 1, 1)],
            )],
            vec![measurement(&source, FileClassification::Source)],
            true,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        let reference = temp.0.join("reference.json");
        std::fs::write(
            &reference,
            serde_json::to_string(&reference_document(&source, &rule)).expect("serialize"),
        )
        .expect("write reference");

        attach_comparison(&mut report, catalog, &reference).expect("comparison");
        let parity = report.parity.expect("parity block");
        let comparison = parity.comparison.expect("comparison block");
        assert_eq!(comparison.status, ParityComparisonStatus::Matched);
        assert_eq!(comparison.reference_issues, 1);
        assert_eq!(comparison.native_issues, 1);
        assert!(comparison.divergences.is_empty());
        assert_eq!(
            parity.completeness,
            ParityCompleteness::ReferenceParityVerified
        );
    }

    #[test]
    fn diverged_reference_marks_incomplete() {
        let catalog = hoonarqube_catalog::embedded();
        let temp = TempDir::new("diverged");
        let source = temp.0.join("app.py");
        std::fs::write(&source, "x = 1\n").expect("write source");
        let rule = active_rule_key(catalog, "python");

        let mut report = analysis_report(
            vec![file_report(
                &source,
                "python",
                vec![issue(&rule, 1, 0, 1, 1)],
            )],
            vec![measurement(&source, FileClassification::Source)],
            true,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        // The reference carries the same finding at a different column.
        let mut reference_doc = reference_document(&source, &rule);
        reference_doc["issues"][0]["primaryLocation"]["textRange"]["startColumn"] =
            serde_json::json!(2);
        let reference = temp.0.join("reference.json");
        std::fs::write(
            &reference,
            serde_json::to_string(&reference_doc).expect("serialize"),
        )
        .expect("write reference");

        attach_comparison(&mut report, catalog, &reference).expect("comparison");
        let parity = report.parity.expect("parity block");
        let comparison = parity.comparison.expect("comparison block");
        assert_eq!(comparison.status, ParityComparisonStatus::Diverged);
        assert_eq!(comparison.divergences.len(), 2);
        assert!(
            comparison
                .divergences
                .iter()
                .any(|divergence| divergence.kind == "only_in_reference")
        );
        assert!(
            comparison
                .divergences
                .iter()
                .any(|divergence| divergence.kind == "only_in_native")
        );
        assert_eq!(parity.completeness, ParityCompleteness::Incomplete);
    }

    #[test]
    fn unreadable_reference_is_an_error() {
        let catalog = hoonarqube_catalog::embedded();
        let path = PathBuf::from("src/app.py");
        let mut report = analysis_report(
            vec![file_report(&path, "python", Vec::new())],
            vec![measurement(&path, FileClassification::Source)],
            true,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        let error = attach_comparison(&mut report, catalog, Path::new("missing.json"))
            .expect_err("missing reference must fail closed");
        assert!(error.contains("cannot read parity reference"));
        // The block stays honest: no comparison was recorded.
        assert!(report.parity.expect("parity block").comparison.is_none());
    }

    #[test]
    fn malformed_reference_is_an_error() {
        let catalog = hoonarqube_catalog::embedded();
        let temp = TempDir::new("malformed");
        let reference = temp.0.join("reference.json");
        std::fs::write(&reference, "{\"unexpected\": true}").expect("write reference");

        let path = PathBuf::from("src/app.py");
        let mut report = analysis_report(
            vec![file_report(&path, "python", Vec::new())],
            vec![measurement(&path, FileClassification::Source)],
            true,
        );
        let options = parity_options();
        attach_parity_contract(&mut report, catalog, &options, &project_options(), None);

        let error = attach_comparison(&mut report, catalog, &reference)
            .expect_err("malformed reference must fail closed");
        assert!(error.contains("invalid parity reference"));
    }

    #[test]
    fn comparison_requires_parity_block() {
        let catalog = hoonarqube_catalog::embedded();
        let path = PathBuf::from("src/app.py");
        let mut report = analysis_report(
            vec![file_report(&path, "python", Vec::new())],
            vec![measurement(&path, FileClassification::Source)],
            true,
        );
        // No attach_parity_contract: a non-parity profile report.
        let error = attach_comparison(&mut report, catalog, Path::new("reference.json"))
            .expect_err("non-parity report must reject comparison");
        assert!(error.contains("sonar-parity"));
    }
}
