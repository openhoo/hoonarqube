//! Overall findings from the native scan under one measured Community Go profile.
//! This gate does not change the scanner profile or certify detector equivalence.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use hoonarqube_ir::parity::{GO_GATE_DETECTORS_V1, ParityCompleteness, ParityReport};
use hoonarqube_ir::{
    AnalysisReport, FileClassification, MeasurementStatus, assessment::normalize_path,
};
use serde::Deserialize;

pub(super) const CORE: &str = "community_26_11_go_core_violations";
pub(super) const EXTENDED: &str = "community_26_11_go_extended_violations";
pub(super) const COMPREHENSIVE: &str = "community_26_11_go_comprehensive_violations";
const TABLE: &str = include_str!("../../../catalog/reference/community-26.11-go-profiles.json");

#[derive(Deserialize)]
struct Capture {
    server: String,
    profiles: BTreeMap<String, Profile>,
}
#[derive(Deserialize)]
struct Profile {
    name: String,
    active_count: usize,
    rules: BTreeMap<String, Rule>,
}
#[derive(Deserialize)]
struct Rule {
    #[serde(rename = "type")]
    kind: String,
    scope: String,
    parameters: BTreeMap<String, String>,
}

fn profile(metric: &str) -> Result<&'static Profile, String> {
    static CAPTURE: OnceLock<Result<Capture, String>> = OnceLock::new();
    let capture = CAPTURE
        .get_or_init(|| serde_json::from_str(TABLE).map_err(|e| e.to_string()))
        .as_ref()
        .map_err(Clone::clone)?;
    let (name, size) = match metric {
        CORE => ("core", 6),
        EXTENDED => ("extended", 9),
        COMPREHENSIVE => ("comprehensive", 23),
        _ => return Err("unknown Community Go gate".into()),
    };
    let p = capture
        .profiles
        .get(name)
        .ok_or("missing measured Community Go profile")?;
    if capture.server != "26.11.0.134175"
        || p.active_count != size
        || p.rules.len() != size
        || p.name != format!("Sonar way {name}")
    {
        return Err("invalid Community Go profile inventory".into());
    }
    Ok(p)
}

fn require_rules(p: &Profile, parity: &ParityReport) -> Result<BTreeSet<String>, String> {
    let catalog = hoonarqube_catalog::embedded();
    let rules = catalog.language("go").ok_or("missing Go catalog")?;
    let expected: BTreeSet<_> = rules
        .rules()
        .iter()
        .map(|r| r.external_key.as_str())
        .filter(|k| !hoonarqube_catalog::SONAR_PARITY_INACTIVE_RULE_KEYS.contains(k))
        .collect();
    let declared: BTreeSet<_> = parity.active_rules.iter().map(|r| r.key.as_str()).collect();
    if expected != declared || declared.len() != parity.active_rules.len() {
        return Err("native Go active-rule inventory differs from the scanner catalog".into());
    }
    let evidence = parity
        .go_gate_evidence
        .as_ref()
        .ok_or("missing scanner Go detector evidence; rescan with a compatible CLI")?;
    if evidence.catalog_sha256 != catalog.snapshot().catalog_sha256 {
        return Err("Go scanner catalog differs from gate evaluator".into());
    }
    let mut blockers = Vec::new();
    for (key, rule) in &p.rules {
        if !matches!(rule.kind.as_str(), "BUG" | "CODE_SMELL" | "VULNERABILITY")
            || !matches!(rule.scope.as_str(), "MAIN" | "ALL")
        {
            blockers.push(format!("{key}: unsupported type or scope"));
        } else if !declared.contains(key.as_str()) {
            blockers.push(format!("{key}: absent from native profile"));
        } else if !GO_GATE_DETECTORS_V1.contains(&key.as_str()) {
            blockers.push(format!("{key}: no qualified runtime detector"));
        } else if let Some(runtime) = evidence.detectors.get(key) {
            if runtime.main_only != (rule.scope == "MAIN") {
                blockers.push(format!("{key}: runtime scope differs from {}", rule.scope));
            }
            if runtime.parameters != rule.parameters {
                blockers.push(format!(
                    "{key}: expected parameters {:?}, scanner used {:?}",
                    rule.parameters, runtime.parameters
                ));
            }
        } else {
            blockers.push(format!("{key}: missing scanner evidence"));
        }
    }
    if blockers.is_empty() {
        Ok(declared.into_iter().map(str::to_owned).collect())
    } else {
        Err(format!("{} unavailable: {}", p.name, blockers.join("; ")))
    }
}

pub(super) fn count(metric: &str, report: &AnalysisReport) -> Result<u64, String> {
    let profile = profile(metric)?;
    if report.files.is_empty() || report.files.iter().any(|f| f.language != "go") {
        return Err("Community 26.11 Go profile gates require a nonempty Go-only scan".into());
    }
    let parity = report
        .parity
        .as_ref()
        .ok_or("Community Go projection requires a native sonar-parity scan")?;
    let snapshot = hoonarqube_catalog::embedded().snapshot();
    if parity.reference.profile != "sonar-parity"
        || parity.reference.capture_sha256 != snapshot.capture_sha256
        || parity.reference.sonarqube_version != snapshot.server_version
        || !parity.rule_set_violations.is_empty()
        || parity.completeness == ParityCompleteness::Incomplete
    {
        return Err("incomplete or incompatible native parity report".into());
    }
    let declared = require_rules(profile, parity)?;
    let mut files = super::measurement_index(report)?.files;
    // A directory walk may omit files of unknown languages. A Go-only gate
    // must account for each selected file, including an unmeasured one.
    let selected: BTreeSet<_> = report
        .project
        .roots
        .iter()
        .map(|r| normalize_path(r))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    if selected.is_empty() || !selected.iter().eq(files.keys()) {
        return Err("Go profile projection requires an explicit list of selected .go files matching the complete inventory".into());
    }
    if report
        .assessment
        .as_ref()
        .is_some_and(|a| a.context.catalog_digest != snapshot.catalog_sha256)
    {
        return Err("assessment catalog differs from gate evaluator".into());
    }
    let mut count = 0;
    for file in &report.files {
        let path = normalize_path(&file.path).map_err(|e| e.to_string())?;
        let measure = files
            .remove(&path)
            .ok_or("missing or duplicate native Go source")?;
        if path.extension().is_none_or(|e| e != "go")
            || measure.status != MeasurementStatus::Complete
            || !matches!(
                measure.classification,
                FileClassification::Source | FileClassification::Test
            )
            || measure.metrics.as_ref() != Some(&file.metrics)
        {
            return Err("incomplete or inconsistent Go measurements".into());
        }
        for issue in &file.issues {
            if !declared.contains(&issue.rule_key) || issue.rule_key == "go:S2260" {
                return Err(format!(
                    "unqualified or unparsed Go source: {}",
                    issue.rule_key
                ));
            }
            if let Some(rule) = profile.rules.get(&issue.rule_key) {
                if rule.scope == "MAIN" && measure.classification == FileClassification::Test {
                    return Err(format!(
                        "MAIN-only Go detector reported on a test: {}",
                        issue.rule_key
                    ));
                }
                count += 1;
            }
        }
    }
    if !files.is_empty() {
        return Err("Go projection cannot account for every inventory entry".into());
    }
    Ok(count)
}
