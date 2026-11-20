//! Fixtures shared by command and report-format tests.

use hoonarqube_ir::{FileMetrics, FileReport, Issue};

pub(crate) fn sample_report(path: &str, language: &str, issues: Vec<Issue>) -> FileReport {
    FileReport {
        path: std::path::PathBuf::from(path),
        language: language.to_string(),
        issues,
        metrics: FileMetrics {
            lines: 2,
            code_lines: 2,
            comment_lines: 0,
        },
    }
}

/// Unique temp path for CLI tests; callers clean up after use.
pub(crate) fn temp_path(label: &str) -> std::path::PathBuf {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // macOS names its temporary directory through /var, a symlink to
    // /private/var. Use the real parent so safety tests reach their
    // intended late-change or symlink condition instead of refusing /var.
    std::env::temp_dir()
        .canonicalize()
        .expect("canonical temporary directory")
        .join(format!(
            "hoonarqube-cli-fix-{label}-{}-{id}",
            std::process::id()
        ))
}
