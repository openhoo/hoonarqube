//! Hoonarqube's public Rust facade: the single crate downstream users depend on.
//!
//! The workspace splits the analyzer into focused crates (`-core`, `-catalog`,
//! `-ir`, and one per language), but consumers should never need to track those
//! boundaries. This crate re-exports their public surface in one place:
//!
//! - [`analyze`] plus [`AnalyzerOptions`], [`Language`], and
//!   [`language_for_path`] from `hoonarqube-core` — the entry point for
//!   analyzing a source file end to end.
//! - [`catalog`] from `hoonarqube-catalog` — the frozen, integrity-verified
//!   `SonarQube` rule catalog that every finding's rule key resolves against.
//! - [`ir`] from `hoonarqube-ir` — the plain-data findings model
//!   ([`ir::AnalysisReport`], [`ir::FileReport`], [`ir::Issue`], ...).
//!
//! # Example
//!
//! ```no_run
//! use hoonarqube::{AnalyzerOptions, analyze};
//!
//! let report = analyze(
//!     std::path::Path::new("src/app.py"),
//!     "x = 1 \n",
//!     &AnalyzerOptions::default(),
//! );
//! if let Some(report) = report {
//!     for issue in &report.issues {
//!         println!("{} at {:?}", issue.rule_key, issue.range);
//!     }
//! }
//! ```
//!
//! Every [`ir::Issue::rule_key`] is an external key from the frozen catalog,
//! so severity and type always resolve through [`catalog::embedded`] rather
//! than being duplicated in findings.

/// The frozen, verified `SonarQube` rule catalog.
///
/// Re-exported from `hoonarqube-catalog`; see that crate's docs for capture
/// provenance and integrity guarantees.
pub mod catalog {
    /// The fully verified frozen catalog (rule lookups, snapshot metadata).
    pub use hoonarqube_catalog::Catalog;
    /// Returns the process-wide verified embedded catalog.
    pub use hoonarqube_catalog::embedded;
}

/// Findings-oriented intermediate representation of analyzer output.
///
/// Re-exported from `hoonarqube-ir`; positions follow the `SonarQube`
/// text-range convention (1-based lines, 0-based columns).
pub mod ir {
    /// Complete result of analyzing one target.
    pub use hoonarqube_ir::AnalysisReport;
    /// SonarQube-style size metrics for one file.
    pub use hoonarqube_ir::FileMetrics;
    /// Findings and metrics for one analyzed file.
    pub use hoonarqube_ir::FileReport;
    /// One finding whose `rule_key` references a frozen catalog external key.
    pub use hoonarqube_ir::Issue;
    /// Source position; `line` is 1-based, `column` is 0-based.
    pub use hoonarqube_ir::Pos;
    /// Half-open-inclusive source span.
    pub use hoonarqube_ir::Range;
}

/// Language dispatch knobs for [`analyze`]; defaults match analyzer defaults.
pub use hoonarqube_core::AnalyzerOptions;
pub use hoonarqube_core::Language;
/// Analyzes one source file end to end.
pub use hoonarqube_core::analyze;
/// Maps a file path to its analyzed [`Language`], or `None` if unknown.
pub use hoonarqube_core::language_for_path;

#[cfg(test)]
mod tests {
    use super::{AnalyzerOptions, analyze};
    use crate::catalog;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn unique_python_fixture(source: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-facade-smoke-{}-{}.py",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::write(&path, source).expect("write smoke-test fixture");
        path
    }

    /// Facade end-to-end contract: analyzing a Python fixture through this
    /// crate yields findings whose rule keys resolve in the re-exported
    /// embedded catalog, including a deterministic trailing-whitespace hit.
    #[test]
    fn analyze_finding_rule_keys_resolve_through_embedded_catalog() {
        let source = "x = 1 \n";
        let path = unique_python_fixture(source);

        let report =
            analyze(&path, source, &AnalyzerOptions::default()).expect(".py fixture must analyze");
        assert!(
            !report.issues.is_empty(),
            "fixture must produce at least one finding"
        );

        let embedded = catalog::embedded();
        for issue in &report.issues {
            let record = embedded.rule(&issue.rule_key).unwrap_or_else(|| {
                panic!(
                    "rule key {} must resolve through the embedded catalog",
                    issue.rule_key
                )
            });
            assert_eq!(record.external_key, issue.rule_key);
        }

        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.rule_key == "python:S1131"),
            "trailing-whitespace fixture must flag python:S1131"
        );

        let _ = std::fs::remove_file(&path);
    }
}
