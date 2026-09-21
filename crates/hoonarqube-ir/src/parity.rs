//! Machine-verifiable `sonar-parity` contract attached to [`crate::AnalysisReport`].
//!
//! The `sonar-parity` profile claims comparability with a pinned `SonarQube`
//! reference analysis. These types make that claim auditable: they record the
//! frozen catalog's capture provenance, the effective active-rule set with
//! parameters and fidelity, the analyzed scope, the semantic contexts that
//! parity-relevant rules require, and the completeness verdict. An optional
//! [`crate::parity::ParityComparison`] carries the result of comparing this run against a
//! pinned Generic Issue Import reference report.
//!
//! All types serialize deterministically: lists are sorted by their natural
//! key order before they are stored, and maps use `BTreeMap`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Parity contract for one `sonar-parity` analysis.
///
/// Emitted only when the analyzer profile is `sonar-parity`; absent from every
/// other profile's report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParityReport {
    /// Provenance of the frozen catalog capture this run claims parity with.
    pub reference: ParityReference,
    /// Effective active-rule set: the frozen catalog's `sonar-parity`
    /// membership for the languages present in the analyzed scope, in
    /// ascending key order.
    pub active_rules: Vec<ParityActiveRule>,
    /// Normalized analysis scope so a reference scan can be replayed against
    /// the same inputs.
    pub scope: ParityScope,
    /// Whether the semantic contexts required for parity were supplied for
    /// the languages that need them.
    pub semantic_context: ParitySemanticContext,
    /// Overall parity verdict for this run.
    pub completeness: ParityCompleteness,
    /// Emitted rule keys outside the recorded active set. Always empty in a
    /// correct run; a non-empty list is a defect signal and forces
    /// [`ParityCompleteness::Incomplete`].
    pub rule_set_violations: Vec<String>,
    /// Result of comparing this run against a pinned reference report
    /// supplied through `--parity-reference`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison: Option<ParityComparison>,
}

/// Provenance of the pinned `SonarQube` capture behind the frozen catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityReference {
    /// `SonarQube` server version that produced the captured catalog.
    pub sonarqube_version: String,
    /// Analyzer profile this block describes; always `sonar-parity`.
    pub profile: String,
    /// UTC timestamp of the catalog capture.
    pub captured_at_utc: String,
    /// SHA-256 digest of the captured catalog payload.
    pub capture_sha256: String,
}

/// One rule in the effective `sonar-parity` active set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityActiveRule {
    /// Repository-qualified rule key, e.g. `python:S1226`.
    pub key: String,
    /// Catalog-declared parameters with their defaults and types.
    pub parameters: Vec<ParityRuleParameter>,
    /// Captured catalog classification (`community-base` or
    /// `enterprise-unverified`). `enterprise-unverified` marks rules whose
    /// reference behavior the Community oracle cannot certify; they never
    /// count as verified parity on their own.
    pub fidelity: String,
}

/// One catalog-declared rule parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityRuleParameter {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_type: Option<String>,
}

/// Normalized scope of the analyzed inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityScope {
    /// Normalized analysis roots (CWD-relative where possible), sorted.
    pub roots: Vec<PathBuf>,
    /// Raw `--test-include` patterns.
    pub test_include: Vec<String>,
    /// Raw `--exclude` patterns.
    pub exclude: Vec<String>,
    /// Raw `--generated-include` patterns.
    pub generated_include: Vec<String>,
    /// Raw `--vendor-include` patterns.
    pub vendor_include: Vec<String>,
    /// Raw `--duplication-exclude` patterns.
    pub duplication_exclude: Vec<String>,
    /// Number of inventoried files per classification. Every
    /// [`crate::FileClassification`] key is present, including zero counts.
    pub file_counts: BTreeMap<String, u64>,
}

/// Semantic-context availability for the language families whose
/// parity-relevant rules need compiler/project facts. `missing` is an
/// explicit diagnostic recorded in the report; it does not by itself make
/// the run [`ParityCompleteness::Incomplete`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParitySemanticContext {
    /// JavaScript/TypeScript compiler context coverage.
    pub typescript: ParityContextStatus,
    /// C# project context coverage.
    pub csharp: ParityContextStatus,
}

/// Whether a required semantic context covered the analyzed inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityContextStatus {
    /// A complete context covered every analyzed file of this family.
    Supplied,
    /// Files of this family were analyzed without complete context coverage.
    Missing,
    /// No analyzed file belongs to this family.
    NotApplicable,
}

/// Parity verdict for the whole run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityCompleteness {
    /// A pinned reference comparison ran and matched while every parity
    /// prerequisite held.
    ReferenceParityVerified,
    /// The native analysis completed with every parity prerequisite
    /// satisfied, but no reference comparison was requested.
    CompleteNativeAnalysis,
    /// A parity prerequisite failed: the analysis itself is incomplete,
    /// emitted rules escaped the recorded active set, or a requested
    /// reference comparison diverged.
    Incomplete,
}

/// Outcome of comparing this run against a pinned reference report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParityComparison {
    /// Path of the reference report as supplied through `--parity-reference`.
    pub reference_path: PathBuf,
    /// `matched` when the finding identity multisets are equal.
    pub status: ParityComparisonStatus,
    /// Number of findings in the reference report.
    pub reference_issues: u64,
    /// Number of findings in this run's projected report.
    pub native_issues: u64,
    /// Identity differences between the two reports, sorted.
    pub divergences: Vec<ParityDivergence>,
}

/// Whether the reference comparison matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityComparisonStatus {
    Matched,
    Diverged,
}

/// One finding-identity difference between the reference and this run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityDivergence {
    /// `only_in_reference` or `only_in_native`.
    pub kind: String,
    /// Repository-qualified rule key.
    pub rule: String,
    /// Report-relative file path.
    pub path: String,
    /// Inclusive 1-based start line, absent for file-level findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    /// 0-based start offset in the reference coordinate contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_offset: Option<u32>,
    /// Inclusive 1-based end line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// 0-based end offset in the reference coordinate contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_offset: Option<u32>,
    /// How many times this identity exceeds the other side's count.
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_parity() -> ParityReport {
        ParityReport {
            reference: ParityReference {
                sonarqube_version: "2025.4.4.119049".to_owned(),
                profile: "sonar-parity".to_owned(),
                captured_at_utc: "2026-08-22T14:45:03.705491626Z".to_owned(),
                capture_sha256: "f423f0d8b8001af94dbf28bb8e3af368702447a9318b1200650cb3f9b3a332f0"
                    .to_owned(),
            },
            active_rules: vec![ParityActiveRule {
                key: "python:S1226".to_owned(),
                parameters: Vec::new(),
                fidelity: "community-base".to_owned(),
            }],
            scope: ParityScope {
                roots: vec![PathBuf::from(".")],
                test_include: vec!["**/tests/**".to_owned()],
                exclude: Vec::new(),
                generated_include: Vec::new(),
                vendor_include: Vec::new(),
                duplication_exclude: Vec::new(),
                file_counts: BTreeMap::from([
                    ("source".to_owned(), 3),
                    ("test".to_owned(), 1),
                    ("generated".to_owned(), 0),
                    ("vendor".to_owned(), 0),
                    ("excluded".to_owned(), 0),
                ]),
            },
            semantic_context: ParitySemanticContext {
                typescript: ParityContextStatus::Missing,
                csharp: ParityContextStatus::NotApplicable,
            },
            completeness: ParityCompleteness::Incomplete,
            rule_set_violations: Vec::new(),
            comparison: None,
        }
    }

    #[test]
    fn parity_block_serializes_machine_readable_contract() {
        let value = serde_json::to_value(sample_parity()).expect("serialize parity");
        assert_eq!(value["reference"]["sonarqube_version"], "2025.4.4.119049");
        assert_eq!(value["reference"]["profile"], "sonar-parity");
        assert_eq!(
            value["reference"]["capture_sha256"],
            "f423f0d8b8001af94dbf28bb8e3af368702447a9318b1200650cb3f9b3a332f0"
        );
        assert_eq!(value["active_rules"][0]["key"], "python:S1226");
        assert_eq!(value["active_rules"][0]["fidelity"], "community-base");
        assert_eq!(value["scope"]["file_counts"]["source"], 3);
        assert_eq!(value["semantic_context"]["typescript"], "missing");
        assert_eq!(value["semantic_context"]["csharp"], "not_applicable");
        assert_eq!(value["completeness"], "incomplete");
        assert!(value.get("comparison").is_none());
    }

    #[test]
    fn parity_block_round_trips_with_comparison() {
        let mut parity = sample_parity();
        parity.completeness = ParityCompleteness::ReferenceParityVerified;
        parity.comparison = Some(ParityComparison {
            reference_path: PathBuf::from("pinned/sonar.json"),
            status: ParityComparisonStatus::Matched,
            reference_issues: 2,
            native_issues: 2,
            divergences: Vec::new(),
        });
        let json = serde_json::to_string(&parity).expect("serialize");
        let decoded: ParityReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, parity);
        assert_eq!(
            decoded.completeness,
            ParityCompleteness::ReferenceParityVerified
        );
        assert_eq!(
            decoded.comparison.expect("comparison").status,
            ParityComparisonStatus::Matched
        );
    }

    #[test]
    fn parity_divergence_omits_absent_range_fields() {
        let divergence = ParityDivergence {
            kind: "only_in_native".to_owned(),
            rule: "python:S1226".to_owned(),
            path: "src/a.py".to_owned(),
            start_line: None,
            start_offset: None,
            end_line: None,
            end_offset: None,
            count: 1,
        };
        let value = serde_json::to_value(&divergence).expect("serialize");
        assert_eq!(value["kind"], "only_in_native");
        assert!(value.get("start_line").is_none());
    }
}
