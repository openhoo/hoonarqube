//! Active rule types for a named reference profile. Native review identities and
//! rule kinds keep the classification of their own catalog.
use hoonarqube_ir::{AnalysisReport, assessment::normalize_path};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::OnceLock,
};

const TABLE: &str = include_str!("../../../catalog/reference/community-26.9-sonar-way-types.tsv");
pub(super) const VIOLATIONS: &str = "community_26_9_violations";
pub(super) const HOTSPOTS: &str = "community_26_9_security_hotspots_reviewed";

struct Profile {
    catalog: &'static str,
    languages: BTreeMap<&'static str, BTreeMap<&'static str, &'static str>>,
}

fn profile() -> Result<&'static Profile, String> {
    static PROFILE: OnceLock<Result<Profile, String>> = OnceLock::new();
    PROFILE
        .get_or_init(|| {
            let mut lines = TABLE.lines();
            let mut fields = lines.next().unwrap_or_default().split('\t');
            if fields.next() != Some("26.9.0.129388") || fields.next() != Some("Sonar way") {
                return Err("wrong Community rule map header".into());
            }
            let catalog = fields.next().ok_or("missing frozen native catalog")?;
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
            Ok(Profile { catalog, languages })
        })
        .as_ref()
        .map_err(Clone::clone)
}

pub(super) struct Qualified<'a> {
    files: BTreeMap<PathBuf, &'a str>,
    profile: &'static Profile,
}

impl<'a> Qualified<'a> {
    pub(super) fn new(report: &'a AnalysisReport) -> Result<Self, String> {
        let p = profile()?;
        let catalog = hoonarqube_catalog::embedded();
        let parity = report
            .parity
            .as_ref()
            .ok_or("Community rule mapping requires the native sonar-parity profile")?;
        let snapshot = catalog.snapshot();
        if snapshot.catalog_sha256 != p.catalog
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

    pub(super) fn hotspot(
        &self,
        path: &std::path::Path,
        key: &str,
    ) -> Result<Option<bool>, String> {
        let result = self
            .files
            .get(path)
            .and_then(|lang| self.profile.languages.get(lang))
            .and_then(|rules| rules.get(key))
            .copied();
        match result {
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
}
