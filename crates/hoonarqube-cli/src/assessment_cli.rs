//! Assessment orchestration for the project analysis CLI.
//!
//! The native issue/project report remains the primary artifact.  Assessment
//! data is optional and is attached only when explicitly requested, but every
//! requested prerequisite is represented in the report rather than causing the
//! CLI to discard an otherwise renderable analysis.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions, symlink_metadata};
use std::io::{ErrorKind, Read, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use hoonarqube_catalog::embedded;
use hoonarqube_core::assessment::coverage::{
    CoverageFile, CoverageFormat, CoverageSource, import_coverage,
};
use hoonarqube_core::assessment::gates::{GateConfig, evaluate_gate};
use hoonarqube_core::assessment::{build_assessment, compare_reports};
use hoonarqube_core::{
    CSharpAnalyzerOptions, GoAnalyzerOptions, JavaAnalyzerOptions, JstsAnalyzerOptions,
    PythonAnalyzerOptions, RubyAnalyzerOptions, RustAnalyzerOptions,
};
use hoonarqube_ir::AnalysisReport;
use hoonarqube_ir::assessment::{
    ASSESSMENT_SCHEMA_VERSION, AnalysisContext, AssessmentReport, AssessmentStatus,
    CoverageCounter, GateReport, GateStatus, NewCodeReport, SourceInput,
};
use sha2::{Digest as _, Sha256};

use crate::analyze::{AnalyzerOptionsBundle, ProjectAnalysisOptions};
use crate::project_features::{AnalyzedSource, ProjectFeatureOptions};

const MAX_ASSESSMENT_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ATOMIC_WRITE_ATTEMPTS: usize = 32;

/// Attaches the requested assessment artifacts to an already-built native
/// report.  Source bytes are borrowed from the exact snapshots captured by
/// project analysis; this function never opens an analyzed source file.
///
/// Assessment input failures become explicit artifact status/diagnostics.  The
/// native report remains available to the caller, so `Main` can render it
/// before applying the assessment exit status.
pub(crate) fn attach_assessment(
    report: &mut AnalysisReport,
    sources: &[AnalyzedSource],
    options: &AnalyzerOptionsBundle,
    project_options: &ProjectAnalysisOptions,
) {
    let features = &project_options.features;
    if !features.assessment_requested() {
        return;
    }

    let root = assessment_root(report);
    let context = analysis_context(options, project_options, &report.project.roots);
    let source_inputs = assessment_source_inputs(sources);
    let (mut assessment, assessment_build_error) =
        build_assessment_artifact(report, &context, &source_inputs);
    let gate_config = features.quality_gate.as_deref().map(load_gate_config);
    let gate_needs_new_code = gate_requests_new_code(gate_config.as_ref());

    if !features.coverage_lcov.is_empty() || !features.coverage_opencover.is_empty() {
        attach_coverage(&mut assessment, &root, sources, features);
    }

    if features.baseline.is_some() || gate_needs_new_code {
        assessment.new_code = Some(build_new_code_report(
            assessment_build_error.as_deref(),
            report.project.complete,
            &assessment,
            features.baseline.as_deref(),
        ));
    }

    if let Some(config_result) = gate_config {
        assessment = attach_gate(report, assessment, config_result);
    }
    report.assessment = Some(assessment);
    write_requested_baseline(report, features.write_baseline.as_deref(), &root, sources);
}

fn assessment_root(report: &mut AnalysisReport) -> PathBuf {
    match std::env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            report.project.complete = false;
            report
                .project
                .warnings
                .push(format!("cannot determine assessment root: {error}"));
            PathBuf::from(".")
        }
    }
}

fn assessment_source_inputs(sources: &[AnalyzedSource]) -> Vec<SourceInput<'_>> {
    sources
        .iter()
        .map(|source| SourceInput::new(&source.path, source.source.as_bytes()))
        .collect()
}

fn build_assessment_artifact(
    report: &mut AnalysisReport,
    context: &AnalysisContext,
    sources: &[SourceInput<'_>],
) -> (AssessmentReport, Option<String>) {
    match build_assessment(context.clone(), &report.files, sources) {
        Ok(assessment) => (assessment, None),
        Err(error) => {
            let diagnostic = format!("cannot build assessment source snapshots: {error}");
            report.project.complete = false;
            report.project.warnings.push(diagnostic.clone());
            (empty_assessment(context.clone()), Some(diagnostic))
        }
    }
}

fn gate_requests_new_code(gate_config: Option<&Result<GateConfig, String>>) -> bool {
    gate_config
        .and_then(|result| result.as_ref().ok())
        .is_some_and(|config| {
            config.conditions.iter().any(|condition| {
                matches!(
                    condition.scope,
                    hoonarqube_ir::assessment::GateScope::NewCode
                )
            })
        })
}

fn attach_coverage(
    assessment: &mut AssessmentReport,
    root: &Path,
    sources: &[AnalyzedSource],
    features: &ProjectFeatureOptions,
) {
    let (coverage_inputs, mut read_diagnostics) = load_coverage_inputs(features);
    let coverage_files = sources
        .iter()
        .map(|source| CoverageFile {
            path: &source.path,
            source: source.source.as_str(),
            classification: source.classification,
        })
        .collect::<Vec<_>>();
    let mut coverage = import_coverage(root, &coverage_inputs, &coverage_files);
    if !read_diagnostics.is_empty() {
        coverage.status = AssessmentStatus::Invalid;
        coverage.diagnostics.append(&mut read_diagnostics);
        sort_dedup(&mut coverage.diagnostics);
    }
    assessment.coverage = Some(coverage);
}

fn build_new_code_report(
    assessment_build_error: Option<&str>,
    project_complete: bool,
    assessment: &AssessmentReport,
    baseline: Option<&Path>,
) -> NewCodeReport {
    if let Some(error) = assessment_build_error {
        return unavailable_new_code(AssessmentStatus::Incomplete, error);
    }
    if !project_complete {
        return unavailable_new_code(
            AssessmentStatus::Incomplete,
            "native project analysis is incomplete; new-code status is indeterminate",
        );
    }
    match baseline {
        Some(path) => load_baseline_new_code(assessment, path),
        None => unavailable_new_code(
            AssessmentStatus::Missing,
            "new-code baseline is required by the selected quality gate",
        ),
    }
}

fn load_baseline_new_code(assessment: &AssessmentReport, path: &Path) -> NewCodeReport {
    match load_reference_report(path) {
        Ok(reference) => match reference.assessment.as_ref() {
            Some(reference_assessment) => compare_reports(assessment, Some(reference_assessment)),
            None => unavailable_new_code(
                AssessmentStatus::Invalid,
                "reference report has no assessment artifact",
            ),
        },
        Err(error) => unavailable_new_code(AssessmentStatus::Invalid, error),
    }
}

fn attach_gate(
    report: &mut AnalysisReport,
    assessment: AssessmentReport,
    config_result: Result<GateConfig, String>,
) -> AssessmentReport {
    match config_result {
        Ok(config) => {
            report.assessment = Some(assessment);
            let gate = evaluate_gate(&config, report);
            let mut assessment = report
                .assessment
                .take()
                .expect("assessment was attached for gate evaluation");
            assessment.gate = Some(gate);
            assessment
        }
        Err(error) => {
            let mut assessment = assessment;
            assessment.gate = Some(unavailable_gate(error));
            assessment
        }
    }
}

fn write_requested_baseline(
    report: &mut AnalysisReport,
    destination: Option<&Path>,
    root: &Path,
    sources: &[AnalyzedSource],
) {
    let Some(path) = destination else {
        return;
    };
    if let Err(error) = write_baseline_atomically(path, report, root, sources) {
        add_baseline_diagnostic(
            report,
            format!("cannot write baseline {}: {error}", path.display()),
        );
    }
}

/// Computes the deterministic context identity used by baseline matching.
fn analysis_context(
    options: &AnalyzerOptionsBundle,
    project_options: &ProjectAnalysisOptions,
    roots: &[PathBuf],
) -> AnalysisContext {
    let catalog_digest = embedded().snapshot().catalog_sha256.clone();
    let options_digest = analyzer_options_digest(options, &project_options.features.semantics);
    let scope_digest = project_options.assessment_scope_digest(roots);
    let source_revision = git_source_revision();
    AnalysisContext::new(
        concat!("hoonarqube-cli/", env!("CARGO_PKG_VERSION")),
        catalog_digest,
        options_digest,
        scope_digest,
        source_revision,
    )
}

/// Canonically encodes every effective analyzer option and hashes the typed
/// representation.  This intentionally does not use `Debug`, whose spelling
/// is not a public compatibility contract.
fn analyzer_options_digest(
    options: &AnalyzerOptionsBundle,
    semantics: &crate::project_features::SemanticOptions,
) -> String {
    let value = serde_json::json!([
        "hoonarqube-analyzer-options-v2",
        options.profile.to_string(),
        python_options_value(&options.python),
        jsts_options_value(&options.jsts),
        csharp_options_value(&options.csharp),
        go_options_value(&options.go),
        java_options_value(&options.java),
        rust_options_value(&options.rust),
        ruby_options_value(&options.ruby),
        semantic_options_value(semantics),
    ]);
    let encoded = serde_json::to_vec(&value).expect("JSON values are serializable");
    sha256_hex(&encoded)
}

fn python_options_value(options: &PythonAnalyzerOptions) -> serde_json::Value {
    serde_json::json!([
        "python-v1",
        options.maximum_line_length,
        options.maximum_lines_of_code,
        options.maximum_function_parameters,
        options.maximum_return_statements,
        options.maximum_function_length,
        options.maximum_nesting_depth,
        options.maximum_cognitive_complexity,
        options.maximum_class_complexity,
        options.maximum_file_complexity,
        options.maximum_function_complexity,
        options.copyright_header_format,
        options.duplicate_literal_threshold,
        options.duplicate_literal_exclusion_regex,
        options.legal_trailing_comment_pattern,
        options.require_type_hints,
        options.unused_local_ignore_pattern,
        options.enable_single_underscore_attribute_issues,
        options.regex_maximum_complexity,
    ])
}

fn jsts_options_value(options: &JstsAnalyzerOptions) -> serde_json::Value {
    serde_json::json!([
        "jsts-v1",
        options.maximum_line_length,
        options.maximum_lines_of_code,
        options.maximum_function_lines,
        options.header_format,
        options.header_is_regular_expression,
        options.comment_pattern,
        options.password_words,
        options.secret_words,
        options.format_functions,
        options.format_classes,
        options.format_variables,
        options.duplicate_string_threshold,
        options.ignored_strings,
        options.single_quotes,
        options.jsx_attribute_whitelist,
    ])
}

fn csharp_options_value(options: &CSharpAnalyzerOptions) -> serde_json::Value {
    serde_json::json!([
        "csharp-v1",
        options.maximum_line_length,
        options.maximum_file_loc_threshold,
        options.header_format,
        options.header_is_regular_expression,
        options.enum_naming_format,
        options.flags_enum_naming_format,
        options.logger_name_format,
        options.maximum_generic_parameters_for_types,
        options.maximum_generic_parameters_for_methods,
        options.maximum_switch_section_statements,
        options.maximum_switch_section_lines,
        options.maximum_nesting_level,
        options.maximum_function_lines,
        options.maximum_method_parameters,
        options.maximum_function_complexity_threshold,
        options.maximum_cognitive_complexity_threshold,
        options.maximum_accessor_complexity_threshold,
        options.maximum_logical_operators,
        options.duplicate_string_threshold,
        options.credential_words,
        options.secret_words,
        options.secret_randomness_sensibility,
    ])
}

fn go_options_value(options: &GoAnalyzerOptions) -> serde_json::Value {
    serde_json::json!([
        "go-v1",
        options.maximum_line_length,
        options.maximum_lines_of_code,
        options.maximum_expression_complexity,
        options.maximum_function_parameters,
        options.maximum_case_lines,
        options.duplicate_string_threshold,
        options.maximum_nesting_depth,
        options.maximum_function_lines,
        options.maximum_switch_cases,
        options.maximum_cognitive_complexity,
        options.header_format,
    ])
}

fn java_options_value(options: &JavaAnalyzerOptions) -> serde_json::Value {
    serde_json::json!([
        "java-v1",
        options.maximum_line_length,
        options.maximum_file_loc_threshold,
        options.maximum_function_parameters,
        options.maximum_function_lines,
        options.maximum_nesting_level,
        options.maximum_cognitive_complexity,
        options.maximum_expression_complexity,
    ])
}

fn rust_options_value(options: &RustAnalyzerOptions) -> serde_json::Value {
    serde_json::json!([
        "rust-v1",
        options.maximum_function_parameters,
        options.maximum_cognitive_complexity,
    ])
}

fn ruby_options_value(options: &RubyAnalyzerOptions) -> serde_json::Value {
    serde_json::json!([
        "ruby-v1",
        options.maximum_line_length,
        options.maximum_lines_of_code,
        options.maximum_function_parameters,
        options.maximum_function_lines,
        options.maximum_nesting_depth,
        options.maximum_cognitive_complexity,
        options.duplicate_string_threshold,
    ])
}

fn semantic_options_value(
    semantics: &crate::project_features::SemanticOptions,
) -> serde_json::Value {
    let context_sources = semantics
        .csharp_context_sources
        .iter()
        .map(|path| path_identity(Some(path)))
        .collect::<Vec<_>>();
    let mut values = vec![
        serde_json::json!("semantics-v2"),
        serde_json::json!(path_identity(semantics.typescript_project.as_deref())),
        serde_json::json!(path_identity(semantics.typescript_module.as_deref())),
        serde_json::json!(&semantics.typescript_dependency_whitelist),
        serde_json::json!(path_identity(semantics.csharp_project.as_deref())),
    ];
    if !context_sources.is_empty() {
        values.push(serde_json::json!(context_sources));
    }
    values.extend([
        serde_json::json!(semantics.csharp_s110_max),
        serde_json::json!(&semantics.csharp_s110_filtered_class),
        serde_json::json!(semantics.csharp_s1200_max),
        serde_json::json!(semantics.csharp_timeout_ms),
        serde_json::json!(semantics.allow_project_build),
        serde_json::json!(path_identity(semantics.python_project.as_deref())),
    ]);
    serde_json::Value::Array(values)
}
fn path_identity(path: Option<&Path>) -> Option<String> {
    path.map(|path| {
        let bytes = path.as_os_str().as_encoded_bytes();
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    })
}

fn git_source_revision() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = String::from_utf8(output.stdout).ok()?;
    let revision = revision.trim();
    (!revision.is_empty()).then(|| revision.to_owned())
}

fn load_coverage_inputs(features: &ProjectFeatureOptions) -> (Vec<CoverageSource>, Vec<String>) {
    let mut inputs =
        Vec::with_capacity(features.coverage_lcov.len() + features.coverage_opencover.len());
    let mut diagnostics = Vec::new();
    for path in &features.coverage_lcov {
        match read_bounded_text(path, "LCOV") {
            Ok(content) => inputs.push(CoverageSource {
                path: path.clone(),
                format: CoverageFormat::Lcov,
                content,
            }),
            Err(error) => diagnostics.push(error),
        }
    }
    for path in &features.coverage_opencover {
        match read_bounded_text(path, "OpenCover") {
            Ok(content) => inputs.push(CoverageSource {
                path: path.clone(),
                format: CoverageFormat::OpenCover,
                content,
            }),
            Err(error) => diagnostics.push(error),
        }
    }
    sort_dedup(&mut diagnostics);
    (inputs, diagnostics)
}

fn load_gate_config(path: &Path) -> Result<GateConfig, String> {
    let content = read_bounded_text(path, "quality-gate")?;
    let config: GateConfig = serde_json::from_str(&content)
        .map_err(|error| format!("invalid quality-gate {}: {error}", path.display()))?;
    config
        .validate()
        .map_err(|error| format!("invalid quality-gate {}: {error}", path.display()))?;
    Ok(config)
}

fn load_reference_report(path: &Path) -> Result<AnalysisReport, String> {
    let content = read_bounded_text(path, "baseline")?;
    let reference: AnalysisReport = serde_json::from_str(&content)
        .map_err(|error| format!("invalid baseline {}: {error}", path.display()))?;
    if reference.schema_version != 1 {
        return Err(format!(
            "unsupported native baseline schema version {}",
            reference.schema_version
        ));
    }
    let assessment = reference
        .assessment
        .as_ref()
        .ok_or_else(|| "baseline report has no assessment artifact".to_owned())?;
    assessment
        .validate()
        .map_err(|error| format!("invalid baseline assessment: {error}"))?;
    assessment
        .validate_against(&reference.files)
        .map_err(|error| format!("invalid baseline assessment/native report match: {error}"))?;
    Ok(reference)
}

fn read_bounded_text(path: &Path, label: &str) -> Result<String, String> {
    let metadata = symlink_metadata(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing to follow symlink for {label} {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "{label} path is not a regular file: {}",
            path.display()
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_ASSESSMENT_INPUT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_ASSESSMENT_INPUT_BYTES {
        return Err(format!(
            "{label} {} exceeds the bounded {}-MiB input limit",
            path.display(),
            MAX_ASSESSMENT_INPUT_BYTES / (1024 * 1024)
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| format!("{label} {} is not valid UTF-8: {error}", path.display()))
}

fn empty_assessment(context: AnalysisContext) -> AssessmentReport {
    AssessmentReport {
        schema_version: ASSESSMENT_SCHEMA_VERSION,
        context,
        sources: Vec::new(),
        coverage: None,
        new_code: None,
        gate: None,
    }
}

fn unavailable_new_code(status: AssessmentStatus, diagnostic: impl Into<String>) -> NewCodeReport {
    NewCodeReport {
        schema_version: ASSESSMENT_SCHEMA_VERSION,
        status,
        reference_context: None,
        findings: Vec::new(),
        resolved: Vec::new(),
        lines: Vec::new(),
        diagnostics: vec![diagnostic.into()],
    }
}
fn unavailable_gate(diagnostic: impl Into<String>) -> GateReport {
    GateReport {
        schema_version: ASSESSMENT_SCHEMA_VERSION,
        status: GateStatus::Unavailable,
        conditions: Vec::new(),
        diagnostics: vec![diagnostic.into()],
    }
}
fn add_baseline_diagnostic(report: &mut AnalysisReport, diagnostic: String) {
    let Some(assessment) = report.assessment.as_mut() else {
        report.project.complete = false;
        report.project.warnings.push(diagnostic);
        return;
    };
    if let Some(new_code) = assessment.new_code.as_mut() {
        new_code.status = AssessmentStatus::Invalid;
        new_code.diagnostics.push(diagnostic);
        sort_dedup(&mut new_code.diagnostics);
    } else {
        assessment.new_code = Some(unavailable_new_code(AssessmentStatus::Invalid, diagnostic));
    }
}

fn write_baseline_atomically(
    destination: &Path,
    report: &AnalysisReport,
    root: &Path,
    sources: &[AnalyzedSource],
) -> Result<(), String> {
    let destination = absolute_lexical_path(root, destination);
    ensure_safe_destination(&destination, root, sources, report)?;
    let parent = destination
        .parent()
        .ok_or_else(|| "baseline destination has no parent directory".to_owned())?;
    let parent_metadata = symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect baseline parent: {error}"))?;
    if !parent_metadata.is_dir() {
        return Err("baseline destination parent is not a directory".to_owned());
    }

    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("cannot serialize baseline report: {error}"))?;
    bytes.push(b'\n');

    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "baseline destination filename is not valid UTF-8".to_owned())?;
    let mut temporary = None;
    for attempt in 0..MAX_ATOMIC_WRITE_ATTEMPTS {
        let candidate = parent.join(format!(
            ".{file_name}.hoonarqube-{attempt}-{}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(mut file) => {
                let write_result = file
                    .write_all(&bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|error| format!("cannot write temporary baseline: {error}"));
                if let Err(error) = write_result {
                    let _ = fs::remove_file(&candidate);
                    return Err(error);
                }
                temporary = Some(candidate);
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create temporary baseline: {error}")),
        }
    }
    let temporary =
        temporary.ok_or_else(|| "cannot allocate a unique temporary baseline".to_owned())?;
    let rename_result = fs::rename(&temporary, &destination)
        .map_err(|error| format!("cannot atomically install baseline: {error}"));
    if rename_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    rename_result
}

fn ensure_safe_destination(
    destination: &Path,
    root: &Path,
    sources: &[AnalyzedSource],
    report: &AnalysisReport,
) -> Result<(), String> {
    let mut current = Some(destination);
    while let Some(path) = current {
        match symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "refusing to write through symlink {}",
                    path.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
        }
        current = path.parent();
    }
    for source in sources {
        if absolute_lexical_path(root, &source.path) == destination {
            return Err(format!(
                "baseline destination collides with analyzed source {}",
                source.path.display()
            ));
        }
    }
    for measurement in &report.project.files {
        if absolute_lexical_path(root, &measurement.path) == destination {
            return Err(format!(
                "baseline destination collides with analyzed source {}",
                measurement.path.display()
            ));
        }
    }
    for file in &report.files {
        if absolute_lexical_path(root, &file.path) == destination {
            return Err(format!(
                "baseline destination collides with analyzed source {}",
                file.path.display()
            ));
        }
    }
    Ok(())
}

fn absolute_lexical_path(root: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    lexical_normalize(&joined)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => output.push(prefix.as_os_str()),
            Component::RootDir => output.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => match output.components().next_back() {
                Some(Component::Normal(_)) => {
                    let _ = output.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                Some(Component::CurDir | Component::ParentDir) | None => {
                    output.push(component.as_os_str());
                }
            },
            Component::Normal(value) => output.push(value),
        }
    }
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort_unstable();
    values.dedup();
}

fn assessment_status_name(status: AssessmentStatus) -> &'static str {
    match status {
        AssessmentStatus::Complete => "complete",
        AssessmentStatus::Missing => "missing",
        AssessmentStatus::Invalid => "invalid",
        AssessmentStatus::Incomplete => "incomplete",
    }
}

fn gate_status_name(status: GateStatus) -> &'static str {
    match status {
        GateStatus::Pass => "pass",
        GateStatus::Fail => "fail",
        GateStatus::Unavailable => "unavailable",
    }
}

fn gate_scope_name(scope: hoonarqube_ir::assessment::GateScope) -> &'static str {
    match scope {
        hoonarqube_ir::assessment::GateScope::Overall => "overall",
        hoonarqube_ir::assessment::GateScope::NewCode => "new_code",
    }
}

fn gate_operator_name(operator: hoonarqube_ir::assessment::GateOperator) -> &'static str {
    match operator {
        hoonarqube_ir::assessment::GateOperator::Lt => "lt",
        hoonarqube_ir::assessment::GateOperator::Lte => "lte",
        hoonarqube_ir::assessment::GateOperator::Eq => "eq",
        hoonarqube_ir::assessment::GateOperator::Gte => "gte",
        hoonarqube_ir::assessment::GateOperator::Gt => "gt",
    }
}

fn counter_text(counter: &CoverageCounter) -> String {
    match counter.percentage() {
        Some(percentage) => format!(
            "{}/{} ({percentage:.2}%)",
            counter.covered, counter.eligible
        ),
        None => format!("{}/{} (n/a)", counter.covered, counter.eligible),
    }
}

/// Renders deterministic human-readable assessment lines appended after the
/// existing project summary.  Issue-only formats do not call this helper.
pub(crate) fn render_assessment_summary(report: &AnalysisReport) -> String {
    let Some(assessment) = report.assessment.as_ref() else {
        return String::new();
    };
    let mut output = String::new();
    let _ = writeln!(
        output,
        "assessment: schema_version={}, analyzer={}, catalog={}, options={}, scope={}, source_revision={}",
        assessment.schema_version,
        assessment.context.analyzer_version,
        assessment.context.catalog_digest,
        assessment.context.options_digest,
        assessment.context.scope_digest,
        assessment
            .context
            .source_revision
            .as_deref()
            .unwrap_or("none"),
    );
    let _ = writeln!(output, "assessment sources: {}", assessment.sources.len());
    append_coverage_summary(&mut output, assessment);
    append_new_code_summary(&mut output, assessment);
    append_gate_summary(&mut output, assessment);
    output
}

fn append_coverage_summary(output: &mut String, assessment: &AssessmentReport) {
    let Some(coverage) = assessment.coverage.as_ref() else {
        return;
    };
    let _ = writeln!(
        output,
        "coverage: status={}, lines={}, branches={}, file(s)={}",
        assessment_status_name(coverage.status),
        counter_text(&coverage.lines),
        counter_text(&coverage.branches),
        coverage.files.len(),
    );
    for diagnostic in &coverage.diagnostics {
        let _ = writeln!(output, "coverage diagnostic: {diagnostic}");
    }
}

fn append_new_code_summary(output: &mut String, assessment: &AssessmentReport) {
    let Some(new_code) = assessment.new_code.as_ref() else {
        return;
    };
    let new_count = new_code
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.status,
                hoonarqube_ir::assessment::FindingStatus::New
            )
        })
        .count();
    let existing_count = new_code
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.status,
                hoonarqube_ir::assessment::FindingStatus::Existing
            )
        })
        .count();
    let uncertain_count = new_code
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.status,
                hoonarqube_ir::assessment::FindingStatus::Uncertain
            )
        })
        .count();
    let _ = writeln!(
        output,
        "new code: status={}, new={}, existing={}, uncertain={}, resolved={}, line set(s)={}",
        assessment_status_name(new_code.status),
        new_count,
        existing_count,
        uncertain_count,
        new_code.resolved.len(),
        new_code.lines.len(),
    );
    for diagnostic in &new_code.diagnostics {
        let _ = writeln!(output, "new-code diagnostic: {diagnostic}");
    }
}

fn append_gate_summary(output: &mut String, assessment: &AssessmentReport) {
    let Some(gate) = assessment.gate.as_ref() else {
        return;
    };
    let _ = writeln!(
        output,
        "quality gate: status={}, condition(s)={}",
        gate_status_name(gate.status),
        gate.conditions.len(),
    );
    for condition in &gate.conditions {
        let _ = writeln!(
            output,
            "quality gate condition: scope={}, metric={}, operator={}, threshold={}, actual={}, status={}",
            gate_scope_name(condition.scope),
            condition.metric,
            gate_operator_name(condition.operator),
            condition.threshold,
            condition
                .actual
                .map_or_else(|| "n/a".to_owned(), |actual| actual.to_string()),
            gate_status_name(condition.status),
        );
        if let Some(diagnostic) = condition.diagnostic.as_deref() {
            let _ = writeln!(output, "quality gate diagnostic: {diagnostic}");
        }
    }
    for diagnostic in &gate.diagnostics {
        let _ = writeln!(output, "quality gate diagnostic: {diagnostic}");
    }
}

/// Returns the assessment-specific exit status.  `Main` combines this with
/// the native project-completeness status after rendering output.
pub(crate) fn assessment_exit_status(report: &AnalysisReport) -> u8 {
    let Some(assessment) = report.assessment.as_ref() else {
        return 0;
    };
    if assessment.validate().is_err() {
        return 2;
    }
    if assessment
        .coverage
        .as_ref()
        .is_some_and(|coverage| !matches!(coverage.status, AssessmentStatus::Complete))
        || assessment
            .new_code
            .as_ref()
            .is_some_and(|new_code| !matches!(new_code.status, AssessmentStatus::Complete))
        || assessment
            .gate
            .as_ref()
            .is_some_and(|gate| matches!(gate.status, GateStatus::Unavailable))
    {
        return 2;
    }
    if assessment
        .gate
        .as_ref()
        .is_some_and(|gate| matches!(gate.status, GateStatus::Fail))
    {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_rejects_missing_input_without_panicking() {
        let error = read_bounded_text(Path::new("/definitely/missing"), "coverage")
            .expect_err("missing input must be diagnosed");
        assert!(error.contains("cannot read coverage"));
    }

    #[test]
    fn status_precedence_is_unavailable_before_gate_fail() {
        let report = AnalysisReport {
            schema_version: 1,
            files: Vec::new(),
            project: hoonarqube_ir::ProjectReport {
                metrics: hoonarqube_ir::ProjectMetrics {
                    files: 0,
                    lines: 0,
                    code_lines: 0,
                    comment_lines: 0,
                },
                files: Vec::new(),
                duplications: Vec::new(),
                duplication: None,
                complete: true,
                warnings: Vec::new(),
                roots: Vec::new(),
            },
            assessment: Some(AssessmentReport {
                schema_version: ASSESSMENT_SCHEMA_VERSION,
                context: AnalysisContext::new("a", "c", "o", "s", None::<String>),
                sources: Vec::new(),
                coverage: None,
                new_code: None,
                gate: Some(GateReport {
                    schema_version: ASSESSMENT_SCHEMA_VERSION,
                    status: GateStatus::Unavailable,
                    conditions: Vec::new(),
                    diagnostics: vec!["unavailable".to_owned()],
                }),
            }),
        };
        assert_eq!(assessment_exit_status(&report), 2);
    }
}
