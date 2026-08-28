//! Compile-time frozen `SonarQube` rule catalog with evidence-first integrity verification.
//!
//! The crate embeds `catalog/snapshot.toml` plus the four per-language rule files at
//! compile time. [`Catalog::embedded`] replays the exact audit semantics of
//! `xtask catalog audit` once per process; every accessor afterwards relies on the
//! established invariants (verified hashes, verified counts, strictly key-sorted rules).
//!
//! Because the embedded bytes are frozen at compile time, a verification failure can
//! only mean corrupted build artifacts. [`Catalog::embedded`] therefore panics with a
//! precise message instead of ever exposing unverified catalog data.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Embedded languages in canonical audit order: `(catalog name, language id)`.
const LANGUAGES: [(&str, &str); 4] = [
    ("csharp", "cs"),
    ("javascript", "js"),
    ("typescript", "ts"),
    ("python", "py"),
];

const SCOPE_CLASSIFICATION: &str = "community-plus-enterprise-unverified";
const COMMUNITY_CLASSIFICATION: &str = "community-base";
const ENTERPRISE_UNVERIFIED_CLASSIFICATION: &str = "enterprise-unverified";

const SNAPSHOT_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../catalog/snapshot.toml"
));
const COMMUNITY_EVIDENCE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../catalog/community-artifact-resolution.json"
));
const CSHARP_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../catalog/rules/csharp.json"
));
const JAVASCRIPT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../catalog/rules/javascript.json"
));
const TYPESCRIPT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../catalog/rules/typescript.json"
));
const PYTHON_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../catalog/rules/python.json"
));

/// Frozen capture evidence for one `SonarQube` server instance.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u16,
    pub capture_sha256: String,
    pub captured_at_utc: String,
    pub server_version: String,
    pub edition: String,
    pub oracle_edition: String,
    pub instance_mode: String,
    pub page_size: u64,
    pub scope_classification: String,
    pub community_evidence_sha256: String,
    pub catalog_sha256: String,
    /// Rule count in the immutable source capture.
    pub source_total_rules: usize,
    /// Rule count exposed by the shipped catalog.
    pub total_rules: usize,
    pub unverified_rules: BTreeMap<String, Vec<String>>,
    pub languages: BTreeMap<String, SnapshotLanguage>,
    pub endpoints: BTreeMap<String, ResponseReceipt>,
    pub plugins: Vec<PluginFact>,
    pub rule_files: BTreeMap<String, String>,
}

/// Per-language capture receipt recorded in the snapshot.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotLanguage {
    pub language: String,
    pub repository: String,
    pub source_total: u64,
    pub total: u64,
    pub unique_keys: usize,
    pub page_count: usize,
    pub show_count: usize,
    pub query_sha256: String,
    pub pages_sha256: String,
    pub keys_sha256: String,
    pub shows_sha256: String,
}

/// Byte-level receipt for one captured HTTP response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseReceipt {
    pub status: u16,
    pub bytes: usize,
    pub sha256: String,
}

/// Installed-plugin fact recorded in the snapshot.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginFact {
    pub key: String,
    pub version: Option<String>,
    pub hash: Option<String>,
    pub implementation_build: Option<String>,
    pub edition_bundled: Option<bool>,
    pub plugin_type: Option<String>,
    pub required_for_languages: Vec<String>,
}

/// One embedded per-language rule file.
///
/// `deny_unknown_fields` subsumes the xtask `reject_forbidden_output` check: every
/// forbidden prose key (`name`, `description`, `message`, `htmlDesc`, ...) is absent
/// from these structs, so any occurrence fails parsing before verification proceeds.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCatalog {
    pub schema_version: u16,
    pub language: String,
    pub source_capture_sha256: String,
    pub classification: String,
    pub rules: Vec<RuleRecord>,
}

/// One `SonarQube` rule, stripped to classification-safe facts.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRecord {
    pub external_key: String,
    pub language: String,
    pub repository: String,
    pub status: String,
    pub scope: String,
    pub severity: String,
    pub rule_type: String,
    pub clean_code_attribute: Option<String>,
    pub clean_code_attribute_category: Option<String>,
    pub impacts: Vec<ImpactFact>,
    pub is_external: bool,
    pub is_template: bool,
    pub parameters: Vec<ParameterFact>,
    pub sys_tags: Vec<String>,
    pub tags: Vec<String>,
    pub education_principles: Vec<String>,
    pub classification: String,
    pub provenance_id: String,
}

/// Software-quality impact of a rule.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactFact {
    pub software_quality: String,
    pub severity: String,
}

/// Rule parameter fact.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterFact {
    pub key: String,
    pub default_value: Option<String>,
    pub parameter_type: Option<String>,
}

/// A verified per-language view of the embedded catalog.
#[derive(Debug)]
pub struct LanguageCatalog {
    name: &'static str,
    language_id: &'static str,
    catalog: RuleCatalog,
}

/// The fully verified frozen catalog.
#[derive(Debug)]
pub struct Catalog {
    snapshot: Snapshot,
    languages: Vec<LanguageCatalog>,
}

/// Returns the process-wide verified embedded catalog.
///
/// Verification replays the `xtask catalog audit` semantics once; the result is cached
/// and every later call is a cheap lookup.
///
/// # Panics
///
/// Panics if the embedded frozen catalog fails integrity verification. The embedded
/// bytes are fixed at compile time, so this can only mean corrupted build artifacts.
#[must_use]
pub fn embedded() -> &'static Catalog {
    static EMBEDDED: OnceLock<Catalog> = OnceLock::new();
    EMBEDDED.get_or_init(|| {
        verify(
            SNAPSHOT_TOML,
            [CSHARP_JSON, JAVASCRIPT_JSON, TYPESCRIPT_JSON, PYTHON_JSON],
        )
        .expect("embedded catalog failed integrity verification: frozen build inputs are corrupt")
    })
}

impl Catalog {
    /// Verified snapshot metadata: server identity, edition, and provenance hashes.
    #[must_use]
    pub const fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Per-language view for one embedded catalog name, if it exists.
    #[must_use]
    pub fn language(&self, name: &str) -> Option<&LanguageCatalog> {
        self.languages.iter().find(|language| language.name == name)
    }

    /// Cross-language lookup by rule key.
    ///
    /// Keys are unique across languages because every key carries its language prefix,
    /// and each language's rules are verified strictly sorted, so this is a binary
    /// search per language.
    #[must_use]
    pub fn rule(&self, external_key: &str) -> Option<&RuleRecord> {
        self.languages.iter().find_map(|language| {
            let index = language
                .catalog
                .rules
                .binary_search_by(|rule| rule.external_key.as_str().cmp(external_key))
                .ok()?;
            Some(&language.catalog.rules[index])
        })
    }

    /// Iterates all embedded languages in canonical audit order.
    pub fn languages(&self) -> impl Iterator<Item = (&'static str, &LanguageCatalog)> {
        self.languages
            .iter()
            .map(|language| (language.name, language))
    }
}

impl LanguageCatalog {
    /// Embedded catalog name (`csharp`, `javascript`, `typescript`, or `python`).
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// `SonarQube` language id (`cs`, `js`, `ts`, or `py`).
    #[must_use]
    pub const fn language_id(&self) -> &'static str {
        self.language_id
    }

    /// Verified rules, strictly sorted by `external_key`.
    #[must_use]
    pub fn rules(&self) -> &[RuleRecord] {
        &self.catalog.rules
    }

    /// Number of verified rules.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.catalog.rules.len()
    }

    /// Whether this language embeds no rules.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.catalog.rules.is_empty()
    }
}

/// Verifies snapshot and rule texts against the full audit contract.
///
/// The rule texts must be given in [`LANGUAGES`] order. Error messages mirror the
/// `xtask catalog audit` failures byte for byte.
fn verify(snapshot_text: &str, rule_texts: [&str; 4]) -> Result<Catalog, String> {
    let snapshot: Snapshot = toml::from_str(snapshot_text)
        .map_err(|error| format!("catalog snapshot is invalid: {error}"))?;
    if snapshot.schema_version != 3 {
        return Err("unsupported catalog snapshot schema".to_owned());
    }
    if snapshot.scope_classification != SCOPE_CLASSIFICATION {
        return Err("snapshot has invalid scope classification".to_owned());
    }
    if snapshot.oracle_edition != "community" {
        return Err("snapshot oracle is not Community".to_owned());
    }
    if snapshot.community_evidence_sha256 != sha256(COMMUNITY_EVIDENCE_JSON.as_bytes()) {
        return Err("Community scope evidence hash mismatch".to_owned());
    }

    let mut source_total = 0_usize;
    let mut scoped_total = 0_usize;
    let mut catalog_hasher = Sha256::new();
    let mut languages = Vec::with_capacity(LANGUAGES.len());
    for ((language_name, language_id), rule_text) in LANGUAGES.iter().copied().zip(rule_texts) {
        let catalog: RuleCatalog = serde_json::from_str(rule_text)
            .map_err(|error| format!("invalid catalog file {language_name}.json: {error}"))?;
        if catalog.language != language_id {
            return Err("catalog language mismatch".to_owned());
        }
        if catalog.classification != SCOPE_CLASSIFICATION {
            return Err("catalog classification mismatch".to_owned());
        }
        if catalog.source_capture_sha256 != snapshot.capture_sha256 {
            return Err("catalog capture provenance mismatch".to_owned());
        }
        if !is_strictly_sorted(&catalog.rules) {
            return Err("catalog rules are not strictly key-sorted".to_owned());
        }
        if catalog
            .rules
            .iter()
            .any(|rule| rule.is_external || rule.is_template)
        {
            return Err("catalog contains external or template rule".to_owned());
        }
        let receipt = snapshot
            .languages
            .get(language_name)
            .ok_or_else(|| format!("snapshot lacks {language_name}"))?;
        let unverified = snapshot
            .unverified_rules
            .get(language_name)
            .ok_or_else(|| format!("snapshot lacks {language_name} unverified rules"))?;
        if !unverified.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err("unverified rules are not strictly key-sorted".to_owned());
        }
        if unverified.iter().any(|key| {
            !key.starts_with(&format!("{}:", receipt.repository))
                || catalog.rules.iter().all(|rule| &rule.external_key != key)
        }) {
            return Err("invalid or missing unverified rule".to_owned());
        }
        if catalog.rules.iter().any(|rule| {
            let expected = if unverified.binary_search(&rule.external_key).is_ok() {
                ENTERPRISE_UNVERIFIED_CLASSIFICATION
            } else {
                COMMUNITY_CLASSIFICATION
            };
            rule.classification != expected
        }) {
            return Err("rule verification classification mismatch".to_owned());
        }
        if !counts_match(receipt.source_total, catalog.rules.len())
            || !counts_match(receipt.total, catalog.rules.len())
        {
            return Err("catalog count mismatch".to_owned());
        }
        if snapshot.rule_files.get(language_name) != Some(&sha256(rule_text.as_bytes())) {
            return Err("catalog file hash mismatch".to_owned());
        }
        hash_record(&mut catalog_hasher, language_name.as_bytes());
        hash_record(&mut catalog_hasher, rule_text.as_bytes());
        source_total += catalog.rules.len();
        scoped_total += catalog.rules.len();
        languages.push(LanguageCatalog {
            name: language_name,
            language_id,
            catalog,
        });
    }
    if source_total != snapshot.source_total_rules {
        return Err("snapshot total rule count mismatch".to_owned());
    }
    if scoped_total != snapshot.total_rules {
        return Err("snapshot scoped rule count mismatch".to_owned());
    }
    if hex::encode(catalog_hasher.finalize()) != snapshot.catalog_sha256 {
        return Err("catalog aggregate hash mismatch".to_owned());
    }
    Ok(Catalog {
        snapshot,
        languages,
    })
}

/// Whether `rules` are strictly ascending by `external_key`.
fn is_strictly_sorted(rules: &[RuleRecord]) -> bool {
    rules
        .windows(2)
        .all(|pair| pair[0].external_key < pair[1].external_key)
}

/// Folds one length-prefixed byte record into the aggregate hasher.
fn hash_record(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Lowercase hex SHA-256 over `bytes`.
fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Whether a `usize` count equals a `u64` receipt total without lossy casts.
fn counts_match(total: u64, count: usize) -> bool {
    u64::try_from(count).is_ok_and(|count| count == total)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        CSHARP_JSON, JAVASCRIPT_JSON, LANGUAGES, PYTHON_JSON, SNAPSHOT_TOML, TYPESCRIPT_JSON,
        verify,
    };

    const PRISTINE: [&str; 4] = [CSHARP_JSON, JAVASCRIPT_JSON, TYPESCRIPT_JSON, PYTHON_JSON];

    #[test]
    fn embedded_catalog_passes_full_verification() {
        let catalog = super::embedded();
        let snapshot = catalog.snapshot();
        assert_eq!(snapshot.schema_version, 3);
        assert_eq!(snapshot.oracle_edition, "community");
        assert_eq!(snapshot.scope_classification, super::SCOPE_CLASSIFICATION);
        assert_eq!(snapshot.server_version, "2025.4.4.119049");
        assert_eq!(catalog.languages().count(), LANGUAGES.len());
        assert!(catalog.language("python").is_some());
        assert!(catalog.language("java").is_none());
    }

    #[test]
    fn verify_accepts_pristine_embedded_texts() {
        let catalog = verify(SNAPSHOT_TOML, PRISTINE).expect("pristine texts must verify");
        assert_eq!(catalog.snapshot().source_total_rules, 1620);
        assert_eq!(catalog.snapshot().total_rules, 1620);
    }

    #[test]
    fn embedded_rule_counts_match_snapshot_evidence() {
        let catalog = super::embedded();
        assert_eq!(catalog.snapshot().source_total_rules, 1620);
        assert_eq!(catalog.snapshot().total_rules, 1620);
        let expected = [
            ("csharp", 467),
            ("javascript", 406),
            ("typescript", 412),
            ("python", 335),
        ];
        for (name, count) in expected {
            let language = catalog
                .language(name)
                .unwrap_or_else(|| panic!("language {name} missing"));
            assert_eq!(language.len(), count, "rule count mismatch for {name}");
        }
    }

    #[test]
    fn external_keys_are_unique_across_languages() {
        let catalog = super::embedded();
        let mut seen = BTreeSet::new();
        for (_, language) in catalog.languages() {
            for rule in language.rules() {
                assert!(
                    rule.external_key
                        .strip_prefix(rule.repository.as_str())
                        .and_then(|rest| rest.strip_prefix(':'))
                        .is_some(),
                    "key {key} lacks repository {repo}: prefix",
                    key = rule.external_key,
                    repo = rule.repository,
                );
                assert!(
                    seen.insert(rule.external_key.as_str()),
                    "duplicate key {key}",
                    key = rule.external_key,
                );
            }
        }
        assert_eq!(seen.len(), 1620);
    }

    #[test]
    fn rule_lookup_round_trip_resolves_repository() {
        let catalog = super::embedded();
        let rule = catalog
            .rule("python:BackticksUsage")
            .expect("known key resolves");
        assert_eq!(rule.repository, "python");
        assert_eq!(rule.language, "py");
        assert!(catalog.rule("java:NoSuchRule").is_none());
    }

    /// Flips the first hex digit of the 64-character hash following `marker`.
    fn flip_leading_hash_digit(snapshot_text: &str, marker: &str) -> String {
        let hash_start = snapshot_text.find(marker).expect("marker present") + marker.len();
        let hash = &snapshot_text[hash_start..hash_start + 64];
        assert!(
            hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "not a hash: {hash}"
        );
        let flipped = if hash.starts_with('0') { "1" } else { "0" };
        snapshot_text.replacen(hash, &format!("{flipped}{}", &hash[1..]), 1)
    }

    #[test]
    fn tampered_per_file_hash_fails_verification() {
        let snapshot_text = flip_leading_hash_digit(SNAPSHOT_TOML, "csharp = \"");
        let error = verify(&snapshot_text, PRISTINE).expect_err("tampered per-file hash must fail");
        assert_eq!(error, "catalog file hash mismatch");
    }

    #[test]
    fn tampered_aggregate_hash_fails_verification() {
        let snapshot_text = flip_leading_hash_digit(SNAPSHOT_TOML, "catalog_sha256 = \"");
        let error =
            verify(&snapshot_text, PRISTINE).expect_err("tampered aggregate hash must fail");
        assert_eq!(error, "catalog aggregate hash mismatch");
    }

    #[test]
    fn mismatched_catalog_capture_provenance_fails_verification() {
        let marker = "\"source_capture_sha256\": \"";
        let start = PYTHON_JSON.find(marker).expect("provenance field present") + marker.len();
        assert!(
            PYTHON_JSON[start..start + 64]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
            "not a hash"
        );
        let mut tampered = PYTHON_JSON.to_owned();
        let flipped = if tampered[start..].starts_with('0') {
            "1"
        } else {
            "0"
        };
        tampered.replace_range(start..=start, flipped);
        let mut rule_texts = PRISTINE;
        rule_texts[3] = &tampered;
        let error =
            verify(SNAPSHOT_TOML, rule_texts).expect_err("mismatched capture provenance must fail");
        assert_eq!(error, "catalog capture provenance mismatch");
    }

    #[test]
    fn unsorted_rules_fail_verification() {
        let tampered = PYTHON_JSON.replacen(
            "\"external_key\": \"python:BackticksUsage\"",
            "\"external_key\": \"python:ZzBackticksUsage\"",
            1,
        );
        assert_ne!(tampered, PYTHON_JSON);
        let mut rule_texts = PRISTINE;
        rule_texts[3] = &tampered;
        let error = verify(SNAPSHOT_TOML, rule_texts).expect_err("unsorted rules must fail");
        assert_eq!(error, "catalog rules are not strictly key-sorted");
    }

    #[test]
    fn forbidden_prose_fields_fail_strict_parsing() {
        let tampered = PYTHON_JSON.replacen(
            "\"external_key\": \"python:BackticksUsage\",",
            "\"external_key\": \"python:BackticksUsage\",\n      \"name\": \"backticks\",",
            1,
        );
        assert_ne!(tampered, PYTHON_JSON);
        let mut rule_texts = PRISTINE;
        rule_texts[3] = &tampered;
        let error = verify(SNAPSHOT_TOML, rule_texts).expect_err("prose field must fail");
        assert!(
            error.contains("unknown field `name`"),
            "unexpected error: {error}"
        );
    }
}
