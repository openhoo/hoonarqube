//! Path walking and per-file orchestration for the `analyze` subcommand.
//!
//! Walks the requested paths, feeds every selected `.py`, `.js`-family, or
//! `.ts`-family file to its language analyzer, and returns one [`FileReport`]
//! per file, sorted by path. Non-fatal problems (missing paths, unreadable or
//! non-UTF-8 files) are recorded as warnings instead of aborting the run.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;

use hoonarqube_catalog::Catalog;
use hoonarqube_core::{self, AnalyzerOptions as CoreOptions};
use hoonarqube_ir::FileReport;

/// Result of analyzing one input file.
pub(crate) struct FileOutcome {
    pub report: FileReport,
}

/// Per-language analyzer knobs threaded through the walker.
pub(crate) use hoonarqube_core::AnalyzerOptions as AnalyzerOptionsBundle;

/// Walks `paths`, analyzes each selected file, returns reports sorted by path.
///
/// `warnings` collects non-fatal skip notes (one line each, no trailing newline).
pub(crate) fn analyze_paths(
    paths: &[PathBuf],
    options: &AnalyzerOptionsBundle,
    warnings: &mut Vec<String>,
) -> Vec<FileReport> {
    let mut reports = Vec::new();
    for path in paths {
        if !path.exists() {
            warnings.push(format!("path does not exist: {}", path.display()));
        } else if path.is_dir() {
            walk_directory(path, options, warnings, &mut reports);
        } else if is_analyzable_file(path) {
            read_and_analyze(path, options, warnings, &mut reports);
        }
    }
    let mut outcomes: Vec<FileOutcome> = reports
        .into_iter()
        .map(|report| FileOutcome { report })
        .collect();
    outcomes.sort_by(|a, b| a.report.path.cmp(&b.report.path));
    outcomes.into_iter().map(|outcome| outcome.report).collect()
}

/// Builds analyzer options from the frozen catalog's per-rule parameter
/// defaults (`python:LineLength`, `javascript:S103`, `typescript:S103`,
/// `csharpsquid:S103`);
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
            },
            None => hoonarqube_core::JstsAnalyzerOptions::default(),
        };
    let csharp = match maximum_line_length("csharpsquid:S103") {
        Some(maximum_line_length) => hoonarqube_core::CSharpAnalyzerOptions {
            maximum_line_length,
            ..hoonarqube_core::CSharpAnalyzerOptions::default()
        },
        None => hoonarqube_core::CSharpAnalyzerOptions::default(),
    };
    CoreOptions {
        python,
        jsts,
        csharp,
    }
}

fn walk_directory(
    directory: &Path,
    options: &AnalyzerOptionsBundle,
    warnings: &mut Vec<String>,
    reports: &mut Vec<FileReport>,
) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            warnings.push(format!(
                "cannot read directory: {}: {error}",
                directory.display()
            ));
            return;
        }
    };
    let mut children: Vec<_> = entries.filter_map(Result::ok).collect();
    children.sort_by_key(std::fs::DirEntry::file_name);
    for entry in children {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            // Symlinked source FILES are analyzed normally; symlinked
            // directories are never followed.
            let is_file = fs::metadata(&path).is_ok_and(|metadata| metadata.is_file());
            if is_file && is_analyzable_file(&path) {
                read_and_analyze(&path, options, warnings, reports);
            }
        } else if file_type.is_dir() {
            walk_directory(&path, options, warnings, reports);
        } else if is_analyzable_file(&path) {
            read_and_analyze(&path, options, warnings, reports);
        }
    }
}

/// One source of truth for extension dispatch:
/// [`hoonarqube_jsts::language_for_extension`] for JS/TS, `.cs` for C#.
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
            static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "hoonarqube-cli-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
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
    fn parses_catalog_line_length_defaults_per_language() {
        let catalog = hoonarqube_catalog::embedded();
        let options = analyzer_options_bundle(catalog);
        assert_eq!(options.python.maximum_line_length, 120);
        assert_eq!(options.jsts.maximum_line_length, 180);
    }
}
