//! Path walking and per-file orchestration for the `analyze` subcommand.
//!
//! Walks requested paths, feeds each selected Python, JS/TS, C#, Go, Java,
//! Ruby, or Rust file to its language analyzer, and returns one
//! [`FileReport`]
//! per file, sorted by path. Non-fatal problems (missing paths, explicitly
//! passed non-source files, unreadable or non-UTF-8 files) are recorded as
//! warnings instead of aborting the run.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;

use hoonarqube_catalog::Catalog;
use hoonarqube_core::AnalyzerOptions as CoreOptions;
use hoonarqube_ir::FileReport;

/// Per-language analyzer knobs threaded through the walker.
pub(crate) use hoonarqube_core::AnalyzerOptions as AnalyzerOptionsBundle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputMode {
    Analyze,
    Fix,
}

impl InputMode {
    const fn include_unsupported_files(self) -> bool {
        matches!(self, Self::Fix)
    }

    const fn accepts_symlinked_files(self) -> bool {
        matches!(self, Self::Analyze)
    }
}

/// Walks `paths`, analyzes each selected file once (overlapping or repeated
/// input paths are deduplicated), and returns reports sorted by path.
///
/// `warnings` collects non-fatal skip notes (one line each, no trailing newline).
pub(crate) fn analyze_paths(
    paths: &[PathBuf],
    options: &AnalyzerOptionsBundle,
    warnings: &mut Vec<String>,
) -> Vec<FileReport> {
    let files = collect_input_files(paths, InputMode::Analyze, warnings);
    let mut reports = Vec::new();
    for path in &files {
        read_and_analyze(path, options, warnings, &mut reports);
    }
    reports.sort_by(|a, b| a.path.cmp(&b.path));
    reports
}

/// Resolves explicit file and directory arguments without following symlinked
/// directories. Fix mode retains explicitly named ordinary text files for
/// the final-newline repair, but rejects symlinked files so apply mode
/// cannot write through a link. Analyze mode selects known source extensions
/// and may read symlinked source files without modifying them.
pub(crate) fn collect_input_files(
    paths: &[PathBuf],
    mode: InputMode,
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        collect_input_path(path, mode, &mut files, warnings);
    }
    deduplicate_input_files(files)
}

fn collect_input_path(
    path: &Path,
    mode: InputMode,
    files: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
) {
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
    if mode == InputMode::Fix && reject_symlinked_ancestor(path, warnings) {
        return;
    }
    if metadata.file_type().is_symlink() {
        collect_explicit_symlink(path, mode, files, warnings);
    } else if metadata.is_dir() {
        collect_files(path, mode, files, warnings);
    } else if metadata.is_file() {
        collect_explicit_file(path, mode.include_unsupported_files(), files, warnings);
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

fn collect_explicit_symlink(
    path: &Path,
    mode: InputMode,
    files: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
) {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            warnings.push(format!("skipping symlinked directory: {}", path.display()));
        }
        Ok(metadata) if metadata.is_file() && mode.accepts_symlinked_files() => {
            collect_explicit_file(path, false, files, warnings);
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

fn collect_explicit_file(
    path: &Path,
    include_unsupported_files: bool,
    files: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
) {
    if include_unsupported_files || is_analyzable_file(path) {
        files.push(path.to_path_buf());
    } else {
        warnings.push(format!(
            "skipping unsupported file type: {}",
            path.display()
        ));
    }
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

/// Iteratively collects analyzable files under `directory` into `files`.
///
/// Shared by the `analyze` and `fix` commands. Preserves the walker's
/// deterministic order and skip rules: repository ignore files and dot entries
/// are honored, entries are visited sorted by name, symlinked directories are
/// never followed, and symlinked files are accepted for read-only analysis.
/// Walk errors are reported through `warnings`.
pub(crate) fn collect_files(
    directory: &Path,
    mode: InputMode,
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
            // Analysis may read symlinked source files. Fix mode rejects them
            // so `--apply` cannot write through a link outside the walk.
            match fs::metadata(&path) {
                Ok(metadata)
                    if metadata.is_file()
                        && mode.accepts_symlinked_files()
                        && is_analyzable_file(&path) =>
                {
                    files.push(path);
                }
                Ok(metadata) if metadata.is_file() && !mode.accepts_symlinked_files() => {
                    warnings.push(format!("skipping symlinked file: {}", path.display()));
                }
                Ok(metadata) if metadata.is_dir() && mode == InputMode::Fix => {
                    warnings.push(format!("skipping symlinked directory: {}", path.display()));
                }
                Err(error) if mode == InputMode::Fix => warnings.push(format!(
                    "cannot inspect symlink target: {}: {error}",
                    path.display()
                )),
                Ok(_) | Err(_) => {}
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

fn read_and_analyze(
    path: &Path,
    options: &AnalyzerOptionsBundle,
    warnings: &mut Vec<String>,
    reports: &mut Vec<FileReport>,
) {
    match fs::read_to_string(path) {
        Ok(source) => {
            let Some(report) = hoonarqube_core::analyze(path, &source, options) else {
                return;
            };
            reports.push(report);
        }
        Err(error) if error.kind() == ErrorKind::InvalidData => {
            warnings.push(format!("skipping non-UTF-8 file: {}", path.display()));
        }
        Err(error) => {
            warnings.push(format!("cannot read file: {}: {error}", path.display()));
        }
    }
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

    #[test]
    fn selects_only_source_files_sorted_by_path() {
        let fix = TempDir::new("select");
        fix.write("b.py", "y = 2\n");
        fix.write("a.py", "x = 1\n");
        fix.write("c.txt", "not source\n");
        fix.write("d.ts", "eval('x');\n");
        fix.write("e.js", "eval('y');\n");
        fix.write("sub/inner.py", "z = 3\n");
        fix.write(".hidden/skipme.py", "exec('z')\n");

        let mut warnings = Vec::new();
        let reports = analyze_paths(
            std::slice::from_ref(&fix.0),
            &AnalyzerOptionsBundle::default(),
            &mut warnings,
        );

        let paths: Vec<_> = reports.iter().map(|r| r.path.clone()).collect();
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
    fn repository_walk_honors_gitignore_but_explicit_files_remain_analyzable() {
        let fix = TempDir::new("gitignore");
        fix.write(".gitignore", "target/\n");
        fix.write("src/kept.py", "value = 1\n");
        let ignored = fix.write("target/generated.py", "exec(user_input)\n");

        let mut walk_warnings = Vec::new();
        let walked = analyze_paths(
            std::slice::from_ref(&fix.0),
            &AnalyzerOptionsBundle::default(),
            &mut walk_warnings,
        );
        assert_eq!(walked.len(), 1);
        assert_eq!(walked[0].path, fix.0.join("src/kept.py"));
        assert!(walk_warnings.is_empty());

        let mut explicit_warnings = Vec::new();
        let explicit = analyze_paths(
            &[ignored],
            &AnalyzerOptionsBundle::default(),
            &mut explicit_warnings,
        );
        assert_eq!(explicit.len(), 1);
        assert!(explicit_warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinked_directories_but_reads_symlinked_files() {
        let fix = TempDir::new("symlink");
        let real = fix.write("real.py", "x = 1\n");
        fix.write("target/nested.py", "y = 2\n");
        std::os::unix::fs::symlink(fix.0.join("target"), fix.0.join("linked-dir"))
            .expect("symlink dir");
        std::os::unix::fs::symlink(&real, fix.0.join("alias.py")).expect("symlink file");

        let mut warnings = Vec::new();
        let reports = analyze_paths(
            std::slice::from_ref(&fix.0),
            &AnalyzerOptionsBundle::default(),
            &mut warnings,
        );

        // `target/nested.py` appears once, via the real `target`
        // directory; a duplicate would mean `linked-dir` was followed.
        let mut names: Vec<_> = reports
            .iter()
            .map(|r| r.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["alias.py", "nested.py", "real.py"]);
        assert!(warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_symlinked_directories_are_not_followed() {
        let fix = TempDir::new("explicit-symlink-dir");
        fix.write("target/nested.py", "y = 2\n");
        let linked = fix.0.join("linked-dir");
        std::os::unix::fs::symlink(fix.0.join("target"), &linked).expect("symlink dir");

        let mut warnings = Vec::new();
        let reports = analyze_paths(&[linked], &AnalyzerOptionsBundle::default(), &mut warnings);

        assert!(reports.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("skipping symlinked directory: "));
    }

    #[cfg(unix)]
    #[test]
    fn fix_mode_rejects_explicit_and_walked_symlinked_files() {
        let target = TempDir::new("fix-symlink-target");
        target.write("outside.py", "value = 1\n");
        let fixture = TempDir::new("fix-symlink-input");
        let explicit = fixture.0.join("explicit.py");
        let walked = fixture.0.join("nested.py");
        std::os::unix::fs::symlink(target.0.join("outside.py"), &explicit)
            .expect("explicit symlink");
        std::os::unix::fs::symlink(target.0.join("outside.py"), &walked).expect("walked symlink");

        let mut explicit_warnings = Vec::new();
        let explicit_files = collect_input_files(
            std::slice::from_ref(&explicit),
            InputMode::Fix,
            &mut explicit_warnings,
        );
        assert!(explicit_files.is_empty());
        assert_eq!(explicit_warnings.len(), 1);
        assert!(explicit_warnings[0].starts_with("skipping symlinked file: "));

        let mut walked_warnings = Vec::new();
        let walked_files = collect_input_files(
            std::slice::from_ref(&fixture.0),
            InputMode::Fix,
            &mut walked_warnings,
        );
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
    fn fix_mode_rejects_files_reached_through_a_symlinked_parent() {
        let target = TempDir::new("fix-parent-symlink-target");
        let outside = target.write("nested/outside.py", "value = 1");
        let fixture = TempDir::new("fix-parent-symlink-input");
        let linked_parent = fixture.0.join("linked");
        std::os::unix::fs::symlink(target.0.join("nested"), &linked_parent)
            .expect("parent symlink");
        let linked_file = linked_parent.join("outside.py");

        let mut warnings = Vec::new();
        let files = collect_input_files(
            std::slice::from_ref(&linked_file),
            InputMode::Fix,
            &mut warnings,
        );

        assert!(files.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("skipping path through symlinked directory "));
        assert_eq!(fs::read_to_string(outside).expect("outside"), "value = 1");
    }

    #[test]
    fn warns_for_missing_paths() {
        let missing = env::temp_dir().join("hoonarqube-cli-does-not-exist");

        let mut warnings = Vec::new();
        let reports = analyze_paths(&[missing], &AnalyzerOptionsBundle::default(), &mut warnings);
        assert!(reports.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("path does not exist: "));
    }

    #[test]
    fn deduplicates_overlapping_explicit_and_walked_paths() {
        let fix = TempDir::new("overlap");
        fix.write("a.py", "x = 1\n");
        fix.write("b.py", "y = 2\n");

        let mut warnings = Vec::new();
        let reports = analyze_paths(
            &[fix.0.clone(), fix.0.join("a.py"), fix.0.join("a.py")],
            &AnalyzerOptionsBundle::default(),
            &mut warnings,
        );

        let paths: Vec<_> = reports.iter().map(|r| r.path.clone()).collect();
        assert_eq!(paths, vec![fix.0.join("a.py"), fix.0.join("b.py")]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn deduplicates_lexically_equivalent_paths() {
        let fix = TempDir::new("lexical-overlap");
        let source = fix.write("a.py", "x = 1\n");
        fs::create_dir(fix.0.join("nested")).expect("create nested directory");
        let equivalent = fix.0.join("nested").join("..").join("a.py");

        let mut warnings = Vec::new();
        let reports = analyze_paths(
            &[equivalent, source.clone()],
            &AnalyzerOptionsBundle::default(),
            &mut warnings,
        );

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].path, source);
        assert!(warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn distinct_paths_across_symlink_parent_are_not_collapsed() {
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
        let reports = analyze_paths(
            &[through_parent, local],
            &AnalyzerOptionsBundle::default(),
            &mut warnings,
        );

        assert_eq!(reports.len(), 2);
        assert!(warnings.is_empty());
    }

    #[test]
    fn warns_when_an_explicit_path_is_not_a_source_file() {
        let fix = TempDir::new("nonsource");
        let readme = fix.write("README.md", "# notes\n");

        let mut warnings = Vec::new();
        let reports = analyze_paths(&[readme], &AnalyzerOptionsBundle::default(), &mut warnings);

        assert!(reports.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("skipping unsupported file type: "));
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
}
