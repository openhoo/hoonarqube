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
//!   `SonarQube` catalog plus the separate native rule catalog.
//! - [`ir`] from `hoonarqube-ir` — the plain-data findings model
//!   ([`ir::AnalysisReport`], [`ir::Issue`], [`ir::Fix`], [`ir::TextEdit`],
//!   ...).
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
//! Every [`ir::Issue::rule_key`] resolves through either [`catalog::embedded`]
//! or [`catalog::native_rule`]; metadata is never duplicated in findings.

/// The frozen, verified `SonarQube` rule catalog.
///
/// Re-exported from `hoonarqube-catalog`; see that crate's docs for capture
/// provenance and integrity guarantees.
pub mod catalog {
    /// The fully verified frozen catalog (rule lookups, snapshot metadata).
    pub use hoonarqube_catalog::Catalog;
    /// Native rule implementation capability.
    pub use hoonarqube_catalog::NativeImplementation;
    /// Native rule expected precision.
    pub use hoonarqube_catalog::NativePrecision;
    /// Native rule metadata and provenance.
    pub use hoonarqube_catalog::NativeRuleRecord;
    /// Returns the process-wide verified embedded catalog.
    pub use hoonarqube_catalog::embedded;
    /// Looks up an independently implemented native rule.
    pub use hoonarqube_catalog::native_rule;
    /// Iterates independently implemented native rules in stable key order.
    pub use hoonarqube_catalog::native_rules;
}

/// GitHub Code Quality metadata and lookup APIs.
///
/// This namespace is re-exported from `hoonarqube-catalog`, so facade
/// consumers can validate every key emitted by the isolated GitHub profile
/// without depending on workspace-internal crate boundaries.
pub mod github_quality {
    pub use hoonarqube_catalog::github_quality::{
        Category, EvidenceStatus, ImplementationStatus, LanguageFamily, QueryDefinition, Severity,
        queries, queries_for_language, query, verify, verify_json,
    };
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
    /// A human-readable machine-applicable remedy and its edits.
    pub use hoonarqube_ir::Fix;
    /// Validation failure returned while applying edits.
    pub use hoonarqube_ir::FixApplyError;
    /// One secondary location in an execution or data-flow trace.
    pub use hoonarqube_ir::FlowLocation;
    /// One finding whose `rule_key` references a frozen catalog external key.
    pub use hoonarqube_ir::Issue;
    /// One ordered execution or data-flow trace.
    pub use hoonarqube_ir::IssueFlow;
    /// Source position; `line` is 1-based, `column` is 0-based.
    pub use hoonarqube_ir::Pos;
    /// Half-open source span.
    pub use hoonarqube_ir::Range;
    /// One source-range replacement belonging to a fix.
    pub use hoonarqube_ir::TextEdit;
    /// Applies non-overlapping edits to one source string.
    pub use hoonarqube_ir::apply_fixes;
}

/// Language dispatch knobs for [`analyze`]; defaults match analyzer defaults.
pub use hoonarqube_core::AnalyzerOptions;
pub use hoonarqube_core::Language;
/// Cumulative native-rule profile.
pub use hoonarqube_core::RuleProfile;
/// Analyzes one source file end to end.
pub use hoonarqube_core::analyze;
/// Maps a file path to its analyzed [`Language`], or `None` if unknown.
pub use hoonarqube_core::language_for_path;

#[cfg(test)]
mod tests {
    use super::{AnalyzerOptions, RuleProfile, analyze};
    use crate::catalog;
    use std::path::Path;

    /// Facade end-to-end contract: analyzing a Python fixture through this
    /// crate yields findings whose rule keys resolve in the re-exported
    /// embedded catalog for every registered language.
    #[test]
    fn analyze_finding_rule_keys_resolve_through_embedded_catalog() {
        let embedded = catalog::embedded();
        let fixtures = [
            ("fixture.py", "x = 1 \n"),
            ("fixture.js", "eval('x');\n"),
            ("fixture.ts", "eval('x');\n"),
            ("fixture.cs", "\tint x;\nclass A\n{\n}\n"),
            ("fixture.go", "package p\nfunc bad_name() {}\n"),
            ("fixture.rs", "fn main() { println!(\"hello\"); }\n"),
        ];
        for (path, source) in fixtures {
            let report = analyze(Path::new(path), source, &AnalyzerOptions::default())
                .unwrap_or_else(|| panic!("{path} must be registered"));
            assert!(!report.issues.is_empty(), "{path} must produce a finding");
            for issue in &report.issues {
                let record = embedded.rule(&issue.rule_key).unwrap_or_else(|| {
                    panic!(
                        "rule key {} from {path} must resolve through the embedded catalog",
                        issue.rule_key
                    )
                });
                assert_eq!(record.external_key, issue.rule_key);
            }
        }
    }

    /// GitHub-profile findings must resolve through the facade's public
    /// metadata lookup, including the Java and Ruby families.
    #[test]
    fn github_findings_resolve_through_facade_lookup() {
        let options = AnalyzerOptions {
            profile: RuleProfile::GithubCodeQuality,
            ..AnalyzerOptions::default()
        };
        let fixtures = [
            (
                "fixture.cs",
                "using System; class C { void M() { GC.Collect(); } }",
            ),
            (
                "fixture.go",
                "package p\nfunc f(x int) { if x == 1 {} else if (x == 1) {} }\n",
            ),
            (
                "fixture.java",
                "class Main { void f() { new String(\"x\"); } }\n",
            ),
            ("fixture.js", "/*@cc_on @*/\n"),
            ("fixture.ts", "const n: number = 1; n = 2;\n"),
            ("fixture.py", "global value\n"),
            ("fixture.rb", "def f\n  value\nend\n"),
        ];
        for (path, source) in fixtures {
            let report = analyze(Path::new(path), source, &options)
                .unwrap_or_else(|| panic!("{path} must be registered"));
            assert!(
                !report.issues.is_empty(),
                "{path} must produce a GitHub finding"
            );
            for issue in &report.issues {
                assert!(
                    super::github_quality::query(&issue.rule_key).is_some(),
                    "facade lookup must resolve {} from {path}",
                    issue.rule_key
                );
            }
        }
    }
}
