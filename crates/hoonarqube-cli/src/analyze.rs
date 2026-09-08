//! Path walking and per-file orchestration for the `analyze` subcommand.
//!
//! Walks requested paths, feeds each selected Python, JS/TS, C#, Go, Java,
//! Ruby, or Rust file to its language analyzer, and returns deterministic
//! issue reports plus project measurements. The project path keeps the
//! in-memory source snapshot shared by issue and source-facts analysis.
//! Non-fatal collection/read/parser problems are retained as warnings and
//! make the project report incomplete instead of being silently skipped.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use globset::{Glob, GlobSet, GlobSetBuilder};
use hoonarqube_catalog::Catalog;
use hoonarqube_core::{AnalyzerOptions as CoreOptions, Language};
use hoonarqube_ir::FileClassification;

use hoonarqube_core::duplication::DuplicationOptions;
use hoonarqube_core::project::{ProjectFile, analyze_project_file, build_project_report};

/// Per-language analyzer knobs shared by analyze and fix orchestration.
pub(crate) use hoonarqube_core::AnalyzerOptions as AnalyzerOptionsBundle;

/// Raw glob lists supplied by the analyze command.
#[derive(Clone, Copy)]
pub(crate) struct ProjectPatternLists<'a> {
    pub(crate) exclude: &'a [String],
    pub(crate) test_include: &'a [String],
    pub(crate) generated_include: &'a [String],
    pub(crate) vendor_include: &'a [String],
    pub(crate) duplication_exclude: &'a [String],
}

/// Validated project classification and duplication patterns.
#[derive(Clone)]
pub(crate) struct ProjectPatterns {
    exclude: GlobSet,
    exclude_scope: GlobSet,
    test_include: GlobSet,
    test_include_scope: GlobSet,
    generated_include: GlobSet,
    generated_include_scope: GlobSet,
    vendor_include: GlobSet,
    vendor_include_scope: GlobSet,
    duplication_exclude: GlobSet,
}

/// Validated project settings shared by the CLI's project analysis path.
pub(crate) struct ProjectAnalysisOptions {
    pub(crate) patterns: ProjectPatterns,
    pub(crate) duplication: DuplicationOptions,
}

impl ProjectPatterns {
    fn compile(lists: ProjectPatternLists<'_>) -> Result<Self, String> {
        Ok(Self {
            exclude: compile_globset("exclude", lists.exclude)?,
            exclude_scope: compile_scope_globset("exclude", lists.exclude)?,
            test_include: compile_globset("test-include", lists.test_include)?,
            test_include_scope: compile_scope_globset("test-include", lists.test_include)?,
            generated_include: compile_globset("generated-include", lists.generated_include)?,
            generated_include_scope: compile_scope_globset(
                "generated-include",
                lists.generated_include,
            )?,
            vendor_include: compile_globset("vendor-include", lists.vendor_include)?,
            vendor_include_scope: compile_scope_globset("vendor-include", lists.vendor_include)?,
            duplication_exclude: compile_globset("duplication-exclude", lists.duplication_exclude)?,
        })
    }

    fn matches(set: &GlobSet, normalized: &Path) -> bool {
        set.is_match(normalized)
    }

    fn classify_normalized(&self, normalized: &Path) -> FileClassification {
        if Self::matches(&self.exclude, normalized) {
            FileClassification::Excluded
        } else if Self::matches(&self.vendor_include, normalized) {
            FileClassification::Vendor
        } else if Self::matches(&self.generated_include, normalized) {
            FileClassification::Generated
        } else if Self::matches(&self.test_include, normalized) {
            FileClassification::Test
        } else {
            FileClassification::Source
        }
    }

    pub(crate) fn classify(&self, path: &Path) -> FileClassification {
        self.classify_normalized(&normalized_match_path(path))
    }

    /// Classifies a directory scope using only explicit directory-root globs.
    /// A recursive pattern such as `vendor/**` contributes `vendor` to the
    /// scope set; arbitrary fabricated descendants are never probed.
    pub(crate) fn classify_scope(&self, path: &Path) -> FileClassification {
        let normalized = normalized_match_path(path);
        if Self::matches(&self.exclude, &normalized)
            || Self::matches(&self.exclude_scope, &normalized)
        {
            FileClassification::Excluded
        } else if Self::matches(&self.vendor_include, &normalized)
            || Self::matches(&self.vendor_include_scope, &normalized)
        {
            FileClassification::Vendor
        } else if Self::matches(&self.generated_include, &normalized)
            || Self::matches(&self.generated_include_scope, &normalized)
        {
            FileClassification::Generated
        } else if Self::matches(&self.test_include, &normalized)
            || Self::matches(&self.test_include_scope, &normalized)
        {
            FileClassification::Test
        } else {
            FileClassification::Source
        }
    }

    pub(crate) fn duplication_excluded(&self, path: &Path) -> bool {
        Self::matches(&self.duplication_exclude, &normalized_match_path(path))
    }
}

pub(crate) fn project_analysis_options(
    lists: ProjectPatternLists<'_>,
    min_tokens: usize,
    min_lines: u32,
    min_statements: usize,
) -> Result<ProjectAnalysisOptions, String> {
    let duplication = DuplicationOptions {
        min_tokens,
        min_lines,
        min_statements,
        ..DuplicationOptions::default()
    };
    duplication.validate()?;
    Ok(ProjectAnalysisOptions {
        patterns: ProjectPatterns::compile(lists)?,
        duplication,
    })
}

fn compile_globset(label: &str, patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .map_err(|error| format!("invalid --{label} glob {pattern:?}: {error}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|error| format!("invalid --{label} globset: {error}"))
}

fn compile_scope_globset(label: &str, patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let Some(root) = pattern.strip_suffix("/**") else {
            continue;
        };
        let glob = Glob::new(root)
            .map_err(|error| format!("invalid --{label} scope glob {root:?}: {error}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|error| format!("invalid --{label} scope globset: {error}"))
}

fn normalized_match_path(path: &Path) -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_default();
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let absolute = lexical_normalize(&absolute);
    let cwd = lexical_normalize(&cwd);
    match absolute.strip_prefix(&cwd) {
        Ok(relative) if relative.as_os_str().is_empty() => PathBuf::from("."),
        Ok(relative) => relative.to_path_buf(),
        Err(_) => absolute,
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            std::path::Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

/// Runs the project measurement path. Each readable source is loaded once and
/// the same in-memory snapshot is passed to the core project facade.
pub(crate) fn analyze_project_paths(
    paths: &[PathBuf],
    options: &AnalyzerOptionsBundle,
    project_options: &ProjectAnalysisOptions,
    warnings: &mut Vec<String>,
) -> Result<hoonarqube_ir::AnalysisReport, String> {
    let (files, collection_failures) =
        collect_project_input_files(paths, &project_options.patterns, warnings);
    let mut project_files = Vec::with_capacity(files.len() + collection_failures.len());
    for (path, reason) in collection_failures {
        let classification = project_options.patterns.classify_scope(&path);
        project_files.push(ProjectFile {
            path,
            classification,
            report: None,
            facts: None,
            error: (!is_inventory_class(classification)).then_some(reason),
            duplication_excluded: false,
        });
    }

    let mut pending = Vec::new();
    for path in files {
        let classification = classify_collected_path(&project_options.patterns, &path);
        let duplication_excluded = project_options.patterns.duplication_excluded(&path);
        if is_inventory_class(classification) {
            project_files.push(ProjectFile {
                path,
                classification,
                report: None,
                facts: None,
                error: None,
                duplication_excluded,
            });
        } else if hoonarqube_core::language_for_path(&path).is_none() {
            // Explicit unsupported files are retained in the inventory. The
            // core builder distinguishes this no-error/no-measurement case
            // from a source read or parser failure.
            project_files.push(ProjectFile {
                path,
                classification,
                report: None,
                facts: None,
                error: None,
                duplication_excluded,
            });
        } else {
            pending.push(ProjectInput {
                path,
                classification,
                duplication_excluded,
            });
        }
    }

    let worker_count = thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(pending.len());
    project_files.extend(
        analyze_project_files(&pending, options, worker_count)
            .into_iter()
            .map(|(_, project_file)| project_file),
    );
    for project_file in &project_files {
        if let Some(error) = project_file.error.as_deref()
            && !warnings.iter().any(|warning| warning.contains(error))
        {
            warnings.push(format!(
                "cannot analyze {}: {error}",
                project_file.path.display()
            ));
        }
        if let Some(facts) = project_file.facts.as_ref()
            && let Some(error) = facts.error.as_deref()
        {
            warnings.push(format!(
                "incomplete source facts for {}: {error}",
                project_file.path.display()
            ));
        }
    }
    build_project_report(
        project_files,
        paths.to_vec(),
        warnings.clone(),
        &project_options.duplication,
    )
}

struct ProjectInput {
    path: PathBuf,
    classification: FileClassification,
    duplication_excluded: bool,
}

fn analyze_project_files(
    files: &[ProjectInput],
    options: &AnalyzerOptionsBundle,
    worker_count: usize,
) -> Vec<(usize, ProjectFile)> {
    if worker_count <= 1 {
        return files
            .iter()
            .enumerate()
            .map(|(index, file)| (index, read_and_analyze_project(file, options)))
            .collect();
    }

    let requires_jsts_stack = files.iter().any(|file| {
        matches!(
            hoonarqube_core::language_for_path(&file.path),
            Some(Language::JavaScript | Language::TypeScript)
        )
    });
    let next = AtomicUsize::new(0);
    let mut outcomes = thread::scope(|scope| {
        let background_worker_count = if requires_jsts_stack {
            worker_count
        } else {
            worker_count - 1
        };
        let mut workers = Vec::with_capacity(background_worker_count);
        for _ in 0..background_worker_count {
            let worker = if requires_jsts_stack {
                hoonarqube_core::spawn_analyzer_worker(
                    scope,
                    "hoonarqube-project-file-worker",
                    || analyze_project_pending(files, options, &next),
                )
            } else {
                thread::Builder::new()
                    .spawn_scoped(scope, || analyze_project_pending(files, options, &next))
            };
            let Ok(worker) = worker else {
                break;
            };
            workers.push(worker);
        }
        let mut outcomes = if requires_jsts_stack && !workers.is_empty() {
            Vec::new()
        } else {
            analyze_project_pending(files, options, &next)
        };
        for worker in workers {
            outcomes.extend(
                worker
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
            );
        }
        outcomes
    });
    outcomes.sort_unstable_by_key(|(index, _)| *index);
    outcomes
}

fn analyze_project_pending(
    files: &[ProjectInput],
    options: &AnalyzerOptionsBundle,
    next: &AtomicUsize,
) -> Vec<(usize, ProjectFile)> {
    let mut outcomes = Vec::new();
    loop {
        let index = next.fetch_add(1, Ordering::Relaxed);
        let Some(file) = files.get(index) else {
            return outcomes;
        };
        outcomes.push((index, read_and_analyze_project(file, options)));
    }
}

fn read_and_analyze_project(input: &ProjectInput, options: &AnalyzerOptionsBundle) -> ProjectFile {
    match fs::read_to_string(&input.path) {
        Ok(source) => analyze_project_file(
            &input.path,
            &source,
            options,
            input.classification,
            input.duplication_excluded,
        ),
        Err(error) if error.kind() == ErrorKind::InvalidData => ProjectFile {
            path: input.path.clone(),
            classification: input.classification,
            report: None,
            facts: None,
            error: Some("source is not valid UTF-8".to_owned()),
            duplication_excluded: input.duplication_excluded,
        },
        Err(error) => ProjectFile {
            path: input.path.clone(),
            classification: input.classification,
            report: None,
            facts: None,
            error: Some(format!("cannot read file: {error}")),
            duplication_excluded: input.duplication_excluded,
        },
    }
}

/// Resolves explicit file and directory arguments for `fix` without following
/// symlinked directories. Explicit ordinary files remain eligible for the
/// final-newline repair, while symlinked files are rejected before writes.
pub(crate) fn collect_input_files(paths: &[PathBuf], warnings: &mut Vec<String>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        collect_input_path(path, &mut files, warnings);
    }
    deduplicate_input_files(files)
}

/// Collects project inputs with classification applied before any filesystem
/// probe. Excluded/generated/vendor scopes are inventoried without reading and
/// recursive scopes are pruned before the walker can descend into them.
pub(crate) fn collect_project_input_files(
    paths: &[PathBuf],
    patterns: &ProjectPatterns,
    warnings: &mut Vec<String>,
) -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let mut files = Vec::new();
    let mut failures = Vec::new();
    for path in paths {
        collect_project_input_path(path, patterns, &mut files, warnings, &mut failures);
    }
    let files = deduplicate_input_files(files);
    let mut unique_failures = std::collections::BTreeMap::new();
    for (path, reason) in failures {
        unique_failures
            .entry(normalized_input_path(&path))
            .or_insert((path, reason));
    }
    (files, unique_failures.into_values().collect())
}

fn collect_project_input_path(
    path: &Path,
    patterns: &ProjectPatterns,
    files: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
    failures: &mut Vec<(PathBuf, String)>,
) {
    let classification = patterns.classify_scope(path);
    if is_inventory_class(classification) {
        // The scope root is itself the complete inventory entry. Do not
        // inspect or enumerate an excluded/generated/vendor subtree.
        files.push(path.to_path_buf());
        return;
    }

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let warning = format!("path does not exist: {}", path.display());
            warnings.push(warning.clone());
            failures.push((path.to_path_buf(), warning));
            return;
        }
        Err(error) => {
            let warning = format!("cannot inspect path: {}: {error}", path.display());
            warnings.push(warning.clone());
            failures.push((path.to_path_buf(), warning));
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        match fs::metadata(path) {
            Ok(target) if target.is_file() => files.push(path.to_path_buf()),
            Ok(target) if target.is_dir() => {
                let warning = format!("skipping symlinked directory: {}", path.display());
                warnings.push(warning);
            }
            Ok(_) => {
                let warning = format!("skipping unsupported path: {}", path.display());
                warnings.push(warning);
            }
            Err(error) => {
                let warning = format!("cannot inspect symlink target: {}: {error}", path.display());
                warnings.push(warning.clone());
                failures.push((path.to_path_buf(), warning));
            }
        }
    } else if metadata.is_dir() {
        collect_project_files(path, patterns, files, warnings);
    } else if metadata.is_file() {
        files.push(path.to_path_buf());
    } else {
        let warning = format!("skipping unsupported path: {}", path.display());
        warnings.push(warning);
    }
}

fn is_inventory_class(classification: FileClassification) -> bool {
    matches!(
        classification,
        FileClassification::Excluded | FileClassification::Generated | FileClassification::Vendor
    )
}
fn classify_collected_path(patterns: &ProjectPatterns, path: &Path) -> FileClassification {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => patterns.classify_scope(path),
        Ok(metadata) if metadata.file_type().is_symlink() => match fs::metadata(path) {
            Ok(target) if target.is_dir() => patterns.classify_scope(path),
            _ => patterns.classify(path),
        },
        Ok(_) => patterns.classify(path),
        Err(_) => patterns.classify_scope(path),
    }
}
fn should_visit_project_entry(
    entry: &ignore::DirEntry,
    patterns: &ProjectPatterns,
    skipped: &std::sync::Mutex<Vec<PathBuf>>,
) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let classification = match entry.file_type() {
        Some(file_type) if file_type.is_dir() => patterns.classify_scope(entry.path()),
        _ => patterns.classify(entry.path()),
    };
    if !is_inventory_class(classification) {
        return true;
    }
    if let Ok(mut paths) = skipped.lock() {
        paths.push(entry.path().to_path_buf());
    }
    false
}

fn collect_project_files(
    directory: &Path,
    patterns: &ProjectPatterns,
    files: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
) {
    let skipped = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let skipped_filter = std::sync::Arc::clone(&skipped);
    let filter_patterns = patterns.clone();
    let mut builder = ignore::WalkBuilder::new(directory);
    builder
        .follow_links(false)
        .git_global(false)
        .hidden(true)
        .require_git(false)
        .sort_by_file_name(std::cmp::Ord::cmp)
        .filter_entry(move |entry| {
            should_visit_project_entry(entry, &filter_patterns, skipped_filter.as_ref())
        });

    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!(
                    "cannot walk directory: {}: {error}",
                    directory.display()
                ));
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.into_path();
        let Some(file_type) = fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type())
            .map_err(|error| {
                warnings.push(format!("cannot inspect path: {}: {error}", path.display()));
            })
            .ok()
        else {
            continue;
        };
        if file_type.is_symlink() {
            match fs::metadata(&path) {
                Ok(metadata) if metadata.is_file() && is_analyzable_file(&path) => {
                    files.push(path);
                }
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => {}
                Err(error) => warnings.push(format!(
                    "cannot inspect symlink target: {}: {error}",
                    path.display()
                )),
            }
        } else if file_type.is_file() && is_analyzable_file(&path) {
            files.push(path);
        }
    }

    match skipped.lock() {
        Ok(mut skipped_paths) => files.extend(skipped_paths.drain(..)),
        Err(_) => warnings.push(format!(
            "cannot retain excluded project paths under {}",
            directory.display()
        )),
    }
}

fn collect_input_path(path: &Path, files: &mut Vec<PathBuf>, warnings: &mut Vec<String>) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            warnings.push(format!("path does not exist: {}", path.display()));
            return;
        }
        Err(error) => {
            warnings.push(format!("cannot inspect path: {}: {error}", path.display()));
            return;
        }
    };
    if reject_symlinked_ancestor(path, warnings) {
        return;
    }
    if metadata.file_type().is_symlink() {
        collect_explicit_symlink(path, warnings);
    } else if metadata.is_dir() {
        collect_files(path, files, warnings);
    } else if metadata.is_file() {
        collect_explicit_file(path, files);
    } else {
        warnings.push(format!("skipping unsupported path: {}", path.display()));
    }
}

fn deduplicate_input_files(files: Vec<PathBuf>) -> Vec<PathBuf> {
    // Resolve filesystem identity for deduplication while retaining the
    // lexically smallest original spelling for I/O and report paths.
    let mut unique = std::collections::BTreeMap::new();
    for file in files {
        let key = normalized_input_path(&file);
        match unique.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(file);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if file < *entry.get() {
                    entry.insert(file);
                }
            }
        }
    }
    let mut files: Vec<_> = unique.into_values().collect();
    files.sort();
    files
}

fn normalized_input_path(path: &Path) -> PathBuf {
    if let Some((parent, name)) = path.parent().zip(path.file_name())
        && let Ok(canonical_parent) = parent.canonicalize()
    {
        return canonical_parent.join(name);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_or_else(|_| path.to_path_buf(), |directory| directory.join(path))
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            std::path::Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

fn reject_symlinked_ancestor(path: &Path, warnings: &mut Vec<String>) -> bool {
    match crate::first_symlinked_ancestor(path) {
        Ok(Some(ancestor)) => {
            warnings.push(format!(
                "skipping path through symlinked directory {}: {}",
                ancestor.display(),
                path.display()
            ));
            true
        }
        Ok(None) => false,
        Err(error) => {
            warnings.push(format!(
                "cannot inspect path ancestors: {}: {error}",
                path.display()
            ));
            true
        }
    }
}

fn collect_explicit_symlink(path: &Path, warnings: &mut Vec<String>) {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            warnings.push(format!("skipping symlinked directory: {}", path.display()));
        }
        Ok(metadata) if metadata.is_file() => {
            warnings.push(format!("skipping symlinked file: {}", path.display()));
        }
        Ok(_) => {
            warnings.push(format!("skipping unsupported path: {}", path.display()));
        }
        Err(error) => {
            warnings.push(format!(
                "cannot inspect symlink target: {}: {error}",
                path.display()
            ));
        }
    }
}

fn collect_explicit_file(path: &Path, files: &mut Vec<PathBuf>) {
    files.push(path.to_path_buf());
}

/// Builds analyzer options from the frozen catalog's per-rule parameter
/// defaults (`python:LineLength`, `javascript:S103`, `typescript:S103`, and
/// configured C# rules);
/// any miss falls back to that language's library default so catalog edits
/// flow through without code changes.
pub(crate) fn analyzer_options_bundle(catalog: &Catalog) -> AnalyzerOptionsBundle {
    let maximum_line_length = |rule_key: &str| {
        catalog
            .rule(rule_key)
            .and_then(|rule| {
                rule.parameters
                    .iter()
                    .find(|parameter| parameter.key == "maximumLineLength")
            })
            .and_then(|parameter| parameter.default_value.as_deref())
            .and_then(|value| value.parse::<u32>().ok())
    };
    let parameter = |rule_key: &str, key: &str| {
        catalog
            .rule(rule_key)
            .and_then(|rule| {
                rule.parameters
                    .iter()
                    .find(|parameter| parameter.key == key)
            })
            .and_then(|parameter| parameter.default_value.as_deref())
    };
    let python = match maximum_line_length("python:LineLength") {
        Some(maximum_line_length) => hoonarqube_core::PythonAnalyzerOptions {
            maximum_line_length,
            ..hoonarqube_core::PythonAnalyzerOptions::default()
        },
        None => hoonarqube_core::PythonAnalyzerOptions::default(),
    };
    let jsts =
        match maximum_line_length("javascript:S103").or(maximum_line_length("typescript:S103")) {
            Some(maximum_line_length) => hoonarqube_core::JstsAnalyzerOptions {
                maximum_line_length,
                ..hoonarqube_core::JstsAnalyzerOptions::default()
            },
            None => hoonarqube_core::JstsAnalyzerOptions::default(),
        };
    let csharp = hoonarqube_core::CSharpAnalyzerOptions {
        maximum_line_length: maximum_line_length("csharpsquid:S103").unwrap_or(200),
        maximum_file_loc_threshold: parameter("csharpsquid:S104", "maximumFileLocThreshold")
            .and_then(|value| value.parse().ok())
            .unwrap_or(1000),
        ..hoonarqube_core::CSharpAnalyzerOptions::default()
    };
    let go = hoonarqube_core::GoAnalyzerOptions {
        maximum_line_length: maximum_line_length("go:S103").unwrap_or(120) as usize,
        maximum_lines_of_code: parameter("go:S104", "Max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(750),
        maximum_expression_complexity: parameter("go:S1067", "max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(3),
        maximum_function_parameters: parameter("go:S107", "Max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(7),
        maximum_case_lines: parameter("go:S1151", "max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(6),
        duplicate_string_threshold: parameter("go:S1192", "threshold")
            .and_then(|value| value.parse().ok())
            .unwrap_or(3),
        maximum_nesting_depth: parameter("go:S134", "max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(4),
        maximum_function_lines: parameter("go:S138", "max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(120),
        maximum_switch_cases: parameter("go:S1479", "maximum")
            .and_then(|value| value.parse().ok())
            .unwrap_or(30),
        maximum_cognitive_complexity: parameter("go:S3776", "threshold")
            .and_then(|value| value.parse().ok())
            .unwrap_or(15),
        header_format: parameter("go:S1451", "headerFormat")
            .unwrap_or_default()
            .to_string(),
    };
    let rust = hoonarqube_core::RustAnalyzerOptions {
        maximum_function_parameters: 7,
        maximum_cognitive_complexity: parameter("rust:S3776", "threshold")
            .and_then(|value| value.parse().ok())
            .unwrap_or(15),
    };
    CoreOptions {
        profile: hoonarqube_core::RuleProfile::SonarParity,
        python,
        jsts,
        csharp,
        go,
        java: hoonarqube_core::JavaAnalyzerOptions::default(),
        rust,
        ruby: hoonarqube_core::RubyAnalyzerOptions::default(),
    }
}

/// Iteratively collects supported source files under `directory` for `fix`.
///
/// Repository ignore files and dot entries are honored, entries are visited
/// in deterministic name order, symlinked directories are never followed, and
/// symlinked files are rejected before any possible write.
pub(crate) fn collect_files(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
) {
    let mut builder = ignore::WalkBuilder::new(directory);
    builder
        .follow_links(false)
        .git_global(false)
        .hidden(true)
        .require_git(false)
        .sort_by_file_name(std::cmp::Ord::cmp);
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!(
                    "cannot walk directory: {}: {error}",
                    directory.display()
                ));
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.into_path();
        let Some(file_type) = fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type())
            .map_err(|error| {
                warnings.push(format!("cannot inspect path: {}: {error}", path.display()));
            })
            .ok()
        else {
            continue;
        };
        if file_type.is_symlink() {
            match fs::metadata(&path) {
                Ok(metadata) if metadata.is_file() => {
                    warnings.push(format!("skipping symlinked file: {}", path.display()));
                }
                Ok(metadata) if metadata.is_dir() => {
                    warnings.push(format!("skipping symlinked directory: {}", path.display()));
                }
                Err(error) => warnings.push(format!(
                    "cannot inspect symlink target: {}: {error}",
                    path.display()
                )),
                Ok(_) => {}
            }
        } else if file_type.is_file() && is_analyzable_file(&path) {
            files.push(path);
        }
    }
}

/// One source of truth for extension dispatch, via the core registry:
/// [`hoonarqube_core::language_for_path`] covers all supported languages.
fn is_analyzable_file(path: &Path) -> bool {
    hoonarqube_core::language_for_path(path).is_some()
}
#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    /// Unique temp directory under `std::env::temp_dir()`; removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            const MAX_ATTEMPTS: u64 = 100;
            static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let pid = std::process::id();
            for _ in 0..MAX_ATTEMPTS {
                let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = env::temp_dir().join(format!("hoonarqube-cli-{label}-{pid}-{id}"));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => (),
                    Err(error) => panic!("create temp dir {} for {label}: {error}", path.display()),
                }
            }
            panic!("create temp dir for {label} (pid {pid}): exhausted {MAX_ATTEMPTS} attempts");
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
            fs::write(&path, contents).expect("write fixture");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
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
        .expect("valid project options")
    }

    fn run_project(
        paths: &[PathBuf],
        options: &ProjectAnalysisOptions,
        warnings: &mut Vec<String>,
    ) -> hoonarqube_ir::AnalysisReport {
        analyze_project_paths(paths, &AnalyzerOptionsBundle::default(), options, warnings)
            .expect("project report")
    }

    #[test]
    fn project_walk_selects_only_source_files_sorted_by_path() {
        let fix = TempDir::new("select");
        fix.write("b.py", "y = 2\n");
        fix.write("a.py", "x = 1\n");
        fix.write("c.txt", "not source\n");
        fix.write("d.ts", "eval('x');\n");
        fix.write("e.js", "eval('y');\n");
        fix.write("sub/inner.py", "z = 3\n");
        fix.write(".hidden/skipme.py", "exec('z')\n");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut warnings,
        );
        let paths: Vec<_> = report.files.iter().map(|file| file.path.clone()).collect();
        assert_eq!(
            paths,
            vec![
                fix.0.join("a.py"),
                fix.0.join("b.py"),
                fix.0.join("d.ts"),
                fix.0.join("e.js"),
                fix.0.join("sub").join("inner.py"),
            ]
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn project_walk_honors_gitignore_but_explicit_files_remain_analyzable() {
        let fix = TempDir::new("gitignore");
        fix.write(".gitignore", "target/\n");
        fix.write("src/kept.py", "value = 1\n");
        let ignored = fix.write("target/generated.py", "exec(user_input)\n");

        let mut walk_warnings = Vec::new();
        let walked = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut walk_warnings,
        );
        assert_eq!(walked.files.len(), 1);
        assert_eq!(walked.files[0].path, fix.0.join("src/kept.py"));
        assert!(walk_warnings.is_empty());

        let mut explicit_warnings = Vec::new();
        let explicit = run_project(
            std::slice::from_ref(&ignored),
            &project_options(),
            &mut explicit_warnings,
        );
        assert_eq!(explicit.files.len(), 1);
        assert_eq!(explicit.files[0].path, ignored);
        assert!(explicit_warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn project_walk_skips_symlinked_directories_but_reads_symlinked_files() {
        let fix = TempDir::new("symlink");
        let real = fix.write("real.py", "x = 1\n");
        fix.write("target/nested.py", "y = 2\n");
        std::os::unix::fs::symlink(fix.0.join("target"), fix.0.join("linked-dir"))
            .expect("symlink dir");
        std::os::unix::fs::symlink(&real, fix.0.join("alias.py")).expect("symlink file");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut warnings,
        );
        let paths: Vec<_> = report.files.iter().map(|file| file.path.clone()).collect();
        assert_eq!(
            paths,
            vec![fix.0.join("alias.py"), real, fix.0.join("target/nested.py"),]
        );
        assert!(warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn project_walk_warns_for_dangling_symlinks() {
        let fix = TempDir::new("dangling-symlink");
        let dangling = fix.0.join("dead.py");
        std::os::unix::fs::symlink(fix.0.join("missing.py"), &dangling).expect("dangling symlink");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut warnings,
        );

        assert!(report.files.is_empty());
        assert!(
            report
                .project
                .warnings
                .iter()
                .any(|warning| warning.starts_with("cannot inspect symlink target: "))
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains(&dangling.display().to_string()))
        );
    }

    #[test]
    fn project_reports_invalid_utf8_as_failed_inventory() {
        let fix = TempDir::new("invalid-utf8");
        let source = fix.0.join("invalid.py");
        fs::write(&source, [0xff, 0xfe, b'\n']).expect("write invalid source");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&source),
            &project_options(),
            &mut warnings,
        );

        assert!(report.files.is_empty());
        let measurement = report
            .project
            .files
            .iter()
            .find(|file| file.path == source)
            .expect("failed source inventory");
        assert_eq!(measurement.status, hoonarqube_ir::MeasurementStatus::Failed);
        assert!(measurement.metrics.is_none());
        assert!(
            report
                .project
                .warnings
                .iter()
                .any(|warning| warning.contains("source is not valid UTF-8"))
        );
    }

    #[test]
    fn project_warnings_are_deterministic_for_multiple_read_failures() {
        let fix = TempDir::new("parallel-warning-order");
        for name in ["a.py", "b.py", "c.py", "d.py"] {
            fs::write(fix.0.join(name), [0xff, b'\n']).expect("write invalid source");
        }

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut warnings,
        );
        assert!(
            report
                .project
                .warnings
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        );
        assert_eq!(report.project.files.len(), 4);
    }

    #[test]
    fn fix_collection_keeps_explicit_ordinary_files_for_newline_repairs() {
        let fix = TempDir::new("fix-ordinary");
        let readme = fix.write("README.md", "# notes");
        let source = fix.write("source.py", "value = 1");

        let mut warnings = Vec::new();
        let files = collect_input_files(&[readme.clone(), source.clone()], &mut warnings);

        assert_eq!(files, vec![readme, source]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn lexical_normalization_falls_back_when_parent_is_missing() {
        let fix = TempDir::new("lexical-fallback");
        let path = fix.0.join("missing-parent").join("..").join("b.py");

        assert_eq!(normalized_input_path(&path), fix.0.join("b.py"));
    }

    #[test]
    fn warns_when_an_explicit_child_has_a_non_directory_parent() {
        let fix = TempDir::new("non-directory-parent");
        let parent = fix.write("file", "not a directory");
        let child = parent.join("child.py");

        let mut warnings = Vec::new();
        let files = collect_input_files(&[child], &mut warnings);

        assert!(files.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("cannot inspect path: "));
    }

    #[test]
    fn project_deduplicates_overlapping_explicit_and_walked_paths() {
        let fix = TempDir::new("overlap");
        fix.write("a.py", "x = 1\n");
        fix.write("b.py", "y = 2\n");

        let mut warnings = Vec::new();
        let report = run_project(
            &[fix.0.clone(), fix.0.join("a.py"), fix.0.join("a.py")],
            &project_options(),
            &mut warnings,
        );

        let paths: Vec<_> = report.files.iter().map(|file| file.path.clone()).collect();
        assert_eq!(paths, vec![fix.0.join("a.py"), fix.0.join("b.py")]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn project_deduplicates_lexically_equivalent_paths() {
        let fix = TempDir::new("lexical-overlap");
        let source = fix.write("a.py", "x = 1\n");
        fs::create_dir(fix.0.join("nested")).expect("create nested directory");
        let equivalent = fix.0.join("nested").join("..").join("a.py");

        let mut warnings = Vec::new();
        let report = run_project(
            &[equivalent, source.clone()],
            &project_options(),
            &mut warnings,
        );

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, source);
        assert!(warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn fix_collection_rejects_explicit_and_walked_symlinked_files() {
        let target = TempDir::new("fix-symlink-target");
        target.write("outside.py", "value = 1\n");
        let fixture = TempDir::new("fix-symlink-input");
        let explicit = fixture.0.join("explicit.py");
        let walked = fixture.0.join("nested.py");
        std::os::unix::fs::symlink(target.0.join("outside.py"), &explicit)
            .expect("explicit symlink");
        std::os::unix::fs::symlink(target.0.join("outside.py"), &walked).expect("walked symlink");

        let mut explicit_warnings = Vec::new();
        let explicit_files =
            collect_input_files(std::slice::from_ref(&explicit), &mut explicit_warnings);
        assert!(explicit_files.is_empty());
        assert_eq!(explicit_warnings.len(), 1);
        assert!(explicit_warnings[0].starts_with("skipping symlinked file: "));

        let mut walked_warnings = Vec::new();
        let walked_files =
            collect_input_files(std::slice::from_ref(&fixture.0), &mut walked_warnings);
        assert!(walked_files.is_empty());
        assert_eq!(walked_warnings.len(), 2);
        assert!(
            walked_warnings
                .iter()
                .all(|warning| warning.starts_with("skipping symlinked file: "))
        );
    }

    #[cfg(unix)]
    #[test]
    fn fix_collection_rejects_files_reached_through_a_symlinked_parent() {
        let target = TempDir::new("fix-parent-symlink-target");
        let outside = target.write("nested/outside.py", "value = 1");
        let fixture = TempDir::new("fix-parent-symlink-input");
        let linked_parent = fixture.0.join("linked");
        std::os::unix::fs::symlink(target.0.join("nested"), &linked_parent)
            .expect("parent symlink");
        let linked_file = linked_parent.join("outside.py");

        let mut warnings = Vec::new();
        let files = collect_input_files(std::slice::from_ref(&linked_file), &mut warnings);

        assert!(files.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("skipping path through symlinked directory "));
        assert_eq!(fs::read_to_string(outside).expect("outside"), "value = 1");
    }

    #[test]
    fn project_warns_for_missing_paths() {
        let missing = env::temp_dir().join("hoonarqube-cli-does-not-exist");

        let mut warnings = Vec::new();
        let report = run_project(&[missing], &project_options(), &mut warnings);

        assert!(report.files.is_empty());
        assert!(
            report
                .project
                .warnings
                .iter()
                .any(|warning| { warning.starts_with("path does not exist: ") })
        );
        assert!(!report.project.complete);
    }

    #[cfg(unix)]
    #[test]
    fn project_keeps_distinct_paths_across_symlink_parent() {
        let fixture = TempDir::new("symlink-parent-dedup-input");
        let local = fixture.write("bar.py", "local = 1\n");
        let outside = TempDir::new("symlink-parent-dedup-target");
        fs::create_dir(outside.0.join("nested")).expect("create symlink target directory");
        outside.write("bar.py", "outside = 1\n");
        let linked = fixture.0.join("linked");
        std::os::unix::fs::symlink(outside.0.join("nested"), &linked)
            .expect("create directory symlink");

        let through_parent = linked.join("..").join("bar.py");
        let mut warnings = Vec::new();
        let report = run_project(
            &[through_parent.clone(), local.clone()],
            &project_options(),
            &mut warnings,
        );

        let paths: Vec<_> = report.files.iter().map(|file| file.path.clone()).collect();
        assert_eq!(paths, vec![local, through_parent]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn catalog_python_line_length_threshold_changes_project_report() {
        let fix = TempDir::new("line-length-threshold");
        let exact = fix.write("exact.py", &format!("value = \"{}\"\n", "a".repeat(110)));
        let over = fix.write("over.py", &format!("value = \"{}\"\n", "a".repeat(111)));

        let mut warnings = Vec::new();
        let options = project_options();
        let report = analyze_project_paths(
            &[exact, over],
            &analyzer_options_bundle(hoonarqube_catalog::embedded()),
            &options,
            &mut warnings,
        )
        .expect("project report");

        assert!(warnings.is_empty());
        let exact_report = report
            .files
            .iter()
            .find(|file| file.path.ends_with("exact.py"))
            .expect("exact threshold report");
        let over_report = report
            .files
            .iter()
            .find(|file| file.path.ends_with("over.py"))
            .expect("over threshold report");
        assert!(
            !exact_report
                .issues
                .iter()
                .any(|issue| issue.rule_key == "python:LineLength")
        );
        assert!(
            over_report
                .issues
                .iter()
                .any(|issue| issue.rule_key == "python:LineLength")
        );
    }

    #[test]
    fn explicit_unsupported_paths_remain_inventory_entries() {
        let fix = TempDir::new("nonsource");
        let readme = fix.write("README.md", "# notes\n");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&readme),
            &project_options(),
            &mut warnings,
        );

        assert!(report.files.is_empty());
        let measurement = report
            .project
            .files
            .iter()
            .find(|file| file.path == readme)
            .expect("unsupported inventory entry");
        assert_eq!(
            measurement.status,
            hoonarqube_ir::MeasurementStatus::Unsupported
        );
        assert!(measurement.metrics.is_none());
    }
    #[test]
    fn scope_globs_only_prune_explicit_recursive_roots() {
        let named = project_analysis_options(
            ProjectPatternLists {
                exclude: &["**/__hoonarqube_scope__".to_string()],
                test_include: &[],
                generated_include: &[],
                vendor_include: &[],
                duplication_exclude: &[],
            },
            100,
            10,
            10,
        )
        .expect("valid named-file glob");

        assert_eq!(
            named.patterns.classify_scope(Path::new("src")),
            FileClassification::Source
        );
        assert_eq!(
            named
                .patterns
                .classify(Path::new("src/__hoonarqube_scope__")),
            FileClassification::Excluded
        );
        assert_eq!(
            normalized_match_path(&env::current_dir().expect("current directory")),
            PathBuf::from(".")
        );
    }

    #[test]
    fn project_inventory_retains_pruned_directory_roots_without_descendants() {
        let fix = TempDir::new("inventory-roots");
        let source = fix.write("src/main.py", "value = 1\n");
        let excluded_file = fix.write("ignored/secret.py", "value = 2\n");
        let generated_file = fix.write("generated/build.py", "value = 3\n");
        let vendor_file = fix.write("vendor/library.py", "value = 4\n");
        let root_glob = |name: &str| format!("{}/{}", fix.0.display(), name);
        let exclude = vec![format!("{}/**", root_glob("ignored"))];
        let generated = vec![format!("{}/**", root_glob("generated"))];
        let vendor = vec![format!("{}/**", root_glob("vendor"))];
        let options = project_analysis_options(
            ProjectPatternLists {
                exclude: &exclude,
                test_include: &[],
                generated_include: &generated,
                vendor_include: &vendor,
                duplication_exclude: &[],
            },
            100,
            10,
            10,
        )
        .expect("valid inventory options");

        let mut warnings = Vec::new();
        let report = run_project(std::slice::from_ref(&fix.0), &options, &mut warnings);

        assert!(warnings.is_empty());
        assert!(report.files.iter().any(|file| file.path == source));
        assert!(!report.files.iter().any(|file| file.path == excluded_file));
        assert!(!report.files.iter().any(|file| file.path == generated_file));
        assert!(!report.files.iter().any(|file| file.path == vendor_file));
        for (path, classification) in [
            (fix.0.join("ignored"), FileClassification::Excluded),
            (fix.0.join("generated"), FileClassification::Generated),
            (fix.0.join("vendor"), FileClassification::Vendor),
        ] {
            let measurement = report
                .project
                .files
                .iter()
                .find(|file| file.path == path)
                .expect("pruned scope root");
            assert_eq!(measurement.classification, classification);
            assert_eq!(
                measurement.status,
                hoonarqube_ir::MeasurementStatus::Excluded
            );
            assert!(measurement.metrics.is_none());
        }
    }

    #[test]
    fn inaccessible_excluded_scope_remains_an_inventory_entry() {
        let fix = TempDir::new("inaccessible-inventory-root");
        let root = fix.0.join("missing");
        let exclude = vec![format!("{}/**", root.display())];
        let options = project_analysis_options(
            ProjectPatternLists {
                exclude: &exclude,
                test_include: &[],
                generated_include: &[],
                vendor_include: &[],
                duplication_exclude: &[],
            },
            100,
            10,
            10,
        )
        .expect("valid inaccessible scope options");

        let mut warnings = Vec::new();
        let report = run_project(std::slice::from_ref(&root), &options, &mut warnings);

        assert!(warnings.is_empty());
        let measurement = report
            .project
            .files
            .iter()
            .find(|file| file.path == root)
            .expect("inaccessible excluded root");
        assert_eq!(measurement.classification, FileClassification::Excluded);
        assert_eq!(
            measurement.status,
            hoonarqube_ir::MeasurementStatus::Excluded
        );
        assert!(measurement.metrics.is_none());
    }

    #[test]
    fn parses_catalog_line_length_defaults_per_language() {
        let catalog = hoonarqube_catalog::embedded();
        let options = analyzer_options_bundle(catalog);
        assert_eq!(options.python.maximum_line_length, 120);
        assert_eq!(options.jsts.maximum_line_length, 180);
    }

    #[test]
    fn csharp_header_defaults_remain_disabled() {
        let options = analyzer_options_bundle(hoonarqube_catalog::embedded());

        assert!(options.csharp.header_format.is_empty());
        assert!(!options.csharp.header_is_regular_expression);
    }

    #[test]
    fn project_patterns_use_explicit_precedence_and_validation() {
        let exclude = vec!["src/**".to_string()];
        let test_include = vec!["**/*_test.py".to_string()];
        let generated_include = vec!["**/generated/**".to_string()];
        let vendor_include = vec!["**/vendor/**".to_string()];
        let duplication_exclude = vec!["src/large.py".to_string()];
        let options = project_analysis_options(
            ProjectPatternLists {
                exclude: &exclude,
                test_include: &test_include,
                generated_include: &generated_include,
                vendor_include: &vendor_include,
                duplication_exclude: &duplication_exclude,
            },
            100,
            10,
            10,
        )
        .expect("valid project options");

        assert_eq!(
            options
                .patterns
                .classify(Path::new("src/vendor/generated/foo_test.py")),
            FileClassification::Excluded
        );
        assert_eq!(
            options
                .patterns
                .classify(Path::new("vendor/generated/foo_test.py")),
            FileClassification::Vendor
        );
        assert_eq!(
            options
                .patterns
                .classify(Path::new("generated/foo_test.py")),
            FileClassification::Generated
        );
        assert_eq!(
            options.patterns.classify(Path::new("unit/foo_test.py")),
            FileClassification::Test
        );
        assert_eq!(
            options.patterns.classify(Path::new("src/large.py")),
            FileClassification::Excluded
        );
        assert_eq!(
            options.patterns.classify_scope(Path::new("src")),
            FileClassification::Excluded
        );
        assert_eq!(
            options.patterns.classify_scope(Path::new("vendor")),
            FileClassification::Vendor
        );
        assert_eq!(
            options.patterns.classify_scope(Path::new("generated")),
            FileClassification::Generated
        );
        assert!(
            options
                .patterns
                .duplication_excluded(Path::new("src/large.py"))
        );
        assert!(
            project_analysis_options(
                ProjectPatternLists {
                    exclude: &[],
                    test_include: &[],
                    generated_include: &[],
                    vendor_include: &[],
                    duplication_exclude: &["[".to_string()],
                },
                100,
                10,
                10,
            )
            .is_err()
        );
        assert!(
            project_analysis_options(
                ProjectPatternLists {
                    exclude: &[],
                    test_include: &[],
                    generated_include: &[],
                    vendor_include: &[],
                    duplication_exclude: &[],
                },
                0,
                10,
                10,
            )
            .is_err()
        );
    }
}
