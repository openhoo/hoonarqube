//! Active rule types for a named reference profile. Native review identities and
//! rule kinds keep the classification of their own catalog.
mod controls;

pub use controls::community_detector_controls_sha256;

use hoonarqube_ir::{AnalysisReport, assessment::normalize_path, parity::ParityCompleteness};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::OnceLock,
};

const TABLE: &str = include_str!("../../../catalog/reference/community-26.9-sonar-way-types.tsv");
pub(super) const VIOLATIONS: &str = "community_26_9_violations";
pub(super) const STRICT_VIOLATIONS: &str = "community_26_9_qualified_violations";
pub(super) const HOTSPOTS: &str = "community_26_9_security_hotspots_reviewed";

pub(super) const CORE_2611_HOTSPOTS: &str = "community_26_11_core_security_hotspots_reviewed";
const CORE_2611: &str =
    include_str!("../../../catalog/reference/community-26.11-core-hotspot-types.tsv");

struct Profile {
    // The older type table was joined to a specific native catalog. The
    // 26.11 table enumerates all active reference keys independently.
    native_catalog: Option<&'static str>,
    languages: BTreeMap<&'static str, BTreeMap<&'static str, &'static str>>,
}

fn profile() -> Result<&'static Profile, String> {
    static PROFILE: OnceLock<Result<Profile, String>> = OnceLock::new();
    PROFILE
        .get_or_init(|| parse_profile(TABLE, "26.9.0.129388", "Sonar way"))
        .as_ref()
        .map_err(Clone::clone)
}

fn core_2611() -> Result<&'static Profile, String> {
    static PROFILE: OnceLock<Result<Profile, String>> = OnceLock::new();
    PROFILE
        .get_or_init(|| parse_profile(CORE_2611, "26.11.0.134175", "Sonar way core"))
        .as_ref()
        .map_err(Clone::clone)
}

fn parse_profile(table: &'static str, version: &str, name: &str) -> Result<Profile, String> {
    let mut lines = table.lines();
    let mut fields = lines.next().unwrap_or_default().split('\t');
    if fields.next() != Some(version) || fields.next() != Some(name) {
        return Err("wrong Community rule map header".into());
    }
    let native_catalog = match (fields.next(), fields.next()) {
        (Some("complete-active-set"), None) => None,
        (Some(digest), None)
            if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Some(digest)
        }
        _ => return Err("invalid Community rule map source".into()),
    };
    let mut languages = BTreeMap::<_, BTreeMap<_, _>>::new();
    for line in lines {
        let mut row = line.split('\t');
        let (Some(lang), Some(key), Some(kind), None) =
            (row.next(), row.next(), row.next(), row.next())
        else {
            return Err("invalid Community rule map row".into());
        };
        if !matches!(
            kind,
            "NOT_ACTIVE" | "CODE_SMELL" | "BUG" | "VULNERABILITY" | "SECURITY_HOTSPOT"
        ) || languages
            .entry(lang)
            .or_default()
            .insert(key, kind)
            .is_some()
        {
            return Err("invalid or duplicate Community rule type".into());
        }
    }
    Ok(Profile {
        native_catalog,
        languages,
    })
}

pub(super) struct Qualified<'a> {
    files: BTreeMap<PathBuf, &'a str>,
    profile: &'static Profile,
}

/// Returns the manifest digest only for a complete scan with the frozen native
/// membership and exercised controls for every active reference violation key.
#[must_use]
pub fn qualified_community_detector_digest(report: &AnalysisReport) -> Option<&'static str> {
    let profile = Qualified::new(report, profile().ok()?).ok()?;
    profile.require_coverage(report).ok()?;
    Some(community_detector_controls_sha256())
}

impl<'a> Qualified<'a> {
    pub(super) fn for_metric(
        metric: &str,
        report: &'a AnalysisReport,
    ) -> Result<Option<Self>, String> {
        match metric {
            STRICT_VIOLATIONS => {
                let profile = Self::new(report, profile()?)?;
                profile.require_detector_coverage(report)?;
                Ok(Some(profile))
            }
            VIOLATIONS => Self::new(report, profile()?).map(Some),
            HOTSPOTS | CORE_2611_HOTSPOTS => {
                let profile = if metric == HOTSPOTS {
                    profile()?
                } else {
                    core_2611()?
                };
                let measured = Self::new(report, profile)?;
                measured.require_empty_hotspot_rule_set()?;
                Ok(Some(measured))
            }
            _ => Ok(None),
        }
    }

    fn require_empty_hotspot_rule_set(&self) -> Result<(), String> {
        if self
            .files
            .values()
            .copied()
            .collect::<BTreeSet<_>>()
            .iter()
            .any(|lang| {
                self.profile.languages[*lang]
                    .values()
                    .any(|kind| *kind == "SECURITY_HOTSPOT")
            })
        {
            return Err(
                "active reference hotspots require verified detector and review coverage".into(),
            );
        }
        Ok(())
    }

    fn new(report: &'a AnalysisReport, p: &'static Profile) -> Result<Self, String> {
        let catalog = hoonarqube_catalog::embedded();
        let parity = report
            .parity
            .as_ref()
            .ok_or("Community rule mapping requires the native sonar-parity profile")?;
        let snapshot = catalog.snapshot();
        if p.native_catalog
            .is_some_and(|digest| digest != snapshot.catalog_sha256)
            || parity.reference.profile != "sonar-parity"
            || parity.reference.capture_sha256 != snapshot.capture_sha256
            || parity.reference.sonarqube_version != snapshot.server_version
            || !parity.rule_set_violations.is_empty()
        {
            return Err(
                "unqualified source catalog or analysis profile for Community rule mapping".into(),
            );
        }
        if report.project.files.iter().any(|f| {
            matches!(
                f.status,
                hoonarqube_ir::MeasurementStatus::Failed
                    | hoonarqube_ir::MeasurementStatus::Unsupported
            )
        }) {
            return Err(
                "Community rule mapping cannot qualify unsupported or failed source inventory"
                    .into(),
            );
        }
        let mut files = BTreeMap::new();
        let mut languages = BTreeSet::new();
        for file in &report.files {
            let lang = file.language.as_str();
            if !p.languages.contains_key(lang) {
                return Err(format!("unqualified Community language: {lang}"));
            }
            languages.insert(lang);
            let path = normalize_path(&file.path).map_err(|err| err.to_string())?;
            if files.insert(path, lang).is_some() {
                return Err("duplicate source in Community language inventory".into());
            }
        }
        if languages.is_empty() {
            return Err("missing Community language inventory".into());
        }
        let mut expected = BTreeSet::new();
        for lang in languages {
            let rules = catalog
                .language(lang)
                .ok_or("unknown source rule catalog")?;
            expected.extend(
                rules
                    .rules()
                    .iter()
                    .map(|r| r.external_key.as_str())
                    .filter(|k| !hoonarqube_catalog::SONAR_PARITY_INACTIVE_RULE_KEYS.contains(k)),
            );
        }
        let declared: BTreeSet<_> = parity.active_rules.iter().map(|r| r.key.as_str()).collect();
        if declared.len() != parity.active_rules.len() || expected != declared {
            return Err("native rule profile does not match the frozen mapping source".into());
        }
        if let Some(issue) = report
            .files
            .iter()
            .flat_map(|file| &file.issues)
            .find(|issue| !declared.contains(issue.rule_key.as_str()))
        {
            return Err(format!(
                "finding outside declared source profile: {}",
                issue.rule_key
            ));
        }
        Ok(Self { files, profile: p })
    }

    fn require_detector_coverage(&self, report: &AnalysisReport) -> Result<(), String> {
        self.require_coverage(report)?;
        let assessment = report
            .assessment
            .as_ref()
            .ok_or("missing candidate assessment")?;
        let baseline = assessment
            .new_code
            .as_ref()
            .and_then(|n| n.reference_context.as_ref())
            .ok_or("qualified Community violations require a baseline context")?;
        for (label, ctx) in [("candidate", &assessment.context), ("baseline", baseline)] {
            if ctx.community_detector_controls_sha256.as_deref()
                != Some(community_detector_controls_sha256())
            {
                return Err(format!(
                    "{label} scanner lacks the matching Community detector-control digest"
                ));
            }
        }
        Ok(())
    }

    fn require_coverage(&self, report: &AnalysisReport) -> Result<(), String> {
        let parity = report
            .parity
            .as_ref()
            .ok_or("missing native parity inventory")?;
        let declared = parity.active_rules.iter().map(|r| r.key.as_str()).collect();
        self.require_controls(&declared)?;
        if parity.completeness == ParityCompleteness::Incomplete {
            return Err(
                "qualified Community violations require a complete native parity analysis".into(),
            );
        }
        Ok(())
    }

    fn require_controls(&self, declared: &BTreeSet<&str>) -> Result<(), String> {
        let controls = controls::keys()?;
        let mut missing = BTreeSet::new();
        let mut unproved = BTreeSet::new();
        let langs: BTreeSet<_> = self.files.values().copied().collect();
        for lang in langs {
            for (&key, _) in self.profile.languages[lang]
                .iter()
                .filter(|(_, kind)| matches!(**kind, "VULNERABILITY" | "BUG" | "CODE_SMELL"))
            {
                if !declared.contains(key) {
                    missing.insert(key);
                } else if !controls.contains(&(lang, key)) {
                    unproved.insert(key);
                }
            }
        }
        let blockers: Vec<_> = [
            (
                "active Community violation rules absent from native profile",
                missing,
            ),
            (
                "active Community violation rules without verified detector controls",
                unproved,
            ),
        ]
        .into_iter()
        .filter(|(_, keys)| !keys.is_empty())
        .map(|(reason, keys)| {
            format!(
                "{reason} ({}): {}",
                keys.len(),
                keys.into_iter().collect::<Vec<_>>().join(", ")
            )
        })
        .collect();
        if blockers.is_empty() {
            Ok(())
        } else {
            Err(blockers.join("; "))
        }
    }

    pub(super) fn hotspot(
        &self,
        path: &std::path::Path,
        key: &str,
    ) -> Result<Option<bool>, String> {
        let result = self
            .files
            .get(path)
            .and_then(|lang| self.profile.languages.get(lang));
        match result.and_then(|rules| rules.get(key)).copied() {
            None if result.is_some() && self.profile.native_catalog.is_none() => Ok(None),
            Some("NOT_ACTIVE") => Ok(None),
            Some("SECURITY_HOTSPOT") => Ok(Some(true)),
            Some("VULNERABILITY" | "BUG" | "CODE_SMELL") => Ok(Some(false)),
            _ => Err(format!(
                "no captured rule classification for {key} in {}",
                path.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn active_inactive_reference_only_unknown_and_foreign_keys_stay_distinct() {
        let report = Qualified {
            files: BTreeMap::from([(PathBuf::from("a.js"), "javascript")]),
            profile: profile().unwrap(),
        };
        let kind = |key| report.hotspot(Path::new("a.js"), key);
        assert_eq!(kind("javascript:S2245").unwrap(), Some(false));
        assert_eq!(kind("javascript:S109").unwrap(), None);
        assert_eq!(kind("javascript:S6861").unwrap(), Some(false));
        assert!(kind("javascript:S999999").is_err());
        assert!(kind("python:S2245").is_err());
        assert!(
            report
                .hotspot(Path::new("other.js"), "javascript:S2245")
                .is_err()
        );
    }
    #[test]
    fn every_scanned_language_requires_active_violation_controls_even_without_findings() {
        let p = profile().unwrap();
        let go = Qualified {
            files: BTreeMap::from([(PathBuf::from("api.go"), "go")]),
            profile: p,
        };
        let declared = p.languages["go"].keys().copied().collect();
        go.require_controls(&declared).unwrap();
        let mixed = Qualified {
            files: BTreeMap::from([
                (PathBuf::from("api.go"), "go"),
                (PathBuf::from("untouched.js"), "javascript"),
            ]),
            profile: p,
        };
        let both = declared.into_iter().chain(["javascript:S2245"]).collect();
        let reason = mixed.require_controls(&both).unwrap_err();
        let (absent, unverified) = reason.split_once("; ").unwrap();
        assert!(absent.contains("javascript:S7724"));
        assert!(unverified.contains("javascript:S2245"));
        assert!(!reason.contains("go:"));
    }
}
