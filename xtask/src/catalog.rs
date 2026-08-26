use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const LANGUAGES: [(&str, &str); 4] = [
    ("csharp", "cs"),
    ("javascript", "js"),
    ("typescript", "ts"),
    ("python", "py"),
];
const CLASSIFICATION: &str = "licensed-only-unclassified";

#[derive(Debug, Deserialize)]
struct RawManifest {
    schema_version: u16,
    captured_at_utc: String,
    server_version: String,
    page_size: u64,
    endpoints: BTreeMap<String, RawResponseReceipt>,
    languages: BTreeMap<String, RawLanguageReceipt>,
    snapshot_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawResponseReceipt {
    status: u16,
    bytes: usize,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawLanguageReceipt {
    language: String,
    repository: String,
    query_sha256: String,
    total: u64,
    unique_keys: usize,
    page_count: usize,
    pages_sha256: String,
    keys_sha256: String,
    show_count: usize,
    shows_sha256: String,
}

#[derive(Debug, Deserialize)]
struct CommunityResolution {
    schema_version: u16,
    target_server_version: String,
    result: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RuleCatalog {
    schema_version: u16,
    language: String,
    source_capture_sha256: String,
    classification: String,
    rules: Vec<RuleRecord>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RuleRecord {
    external_key: String,
    language: String,
    repository: String,
    status: String,
    scope: String,
    severity: String,
    rule_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    clean_code_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    clean_code_attribute_category: Option<String>,
    impacts: Vec<ImpactFact>,
    is_external: bool,
    is_template: bool,
    parameters: Vec<ParameterFact>,
    sys_tags: Vec<String>,
    tags: Vec<String>,
    education_principles: Vec<String>,
    classification: String,
    provenance_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ImpactFact {
    software_quality: String,
    severity: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ParameterFact {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameter_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Snapshot {
    schema_version: u16,
    capture_sha256: String,
    captured_at_utc: String,
    server_version: String,
    edition: String,
    instance_mode: String,
    valid_license: bool,
    page_size: u64,
    community_classification: String,
    community_evidence_sha256: String,
    catalog_sha256: String,
    total_rules: usize,
    languages: BTreeMap<String, SnapshotLanguage>,
    endpoints: BTreeMap<String, RawResponseReceipt>,
    plugins: Vec<PluginFact>,
    rule_files: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SnapshotLanguage {
    language: String,
    repository: String,
    total: u64,
    unique_keys: usize,
    page_count: usize,
    show_count: usize,
    query_sha256: String,
    pages_sha256: String,
    keys_sha256: String,
    shows_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PluginFact {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    implementation_build: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edition_bundled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_type: Option<String>,
    required_for_languages: Vec<String>,
}

pub fn import(capture: &Path, community_resolution: &Path, output: &Path) -> Result<()> {
    let manifest_bytes = read(capture.join("manifest.json"))?;
    let manifest: RawManifest =
        serde_json::from_slice(&manifest_bytes).context("raw capture manifest is invalid")?;
    ensure!(
        manifest.schema_version == 1,
        "unsupported raw capture schema"
    );
    ensure!(manifest.page_size > 0, "raw capture page size is zero");
    ensure!(
        manifest.languages.len() == LANGUAGES.len(),
        "raw capture language count mismatch"
    );
    verify_raw_manifest(capture, &manifest, &manifest_bytes)?;

    let community_bytes =
        validated_community_resolution(community_resolution, &manifest.server_version)?;

    let rules_dir = output.join("rules");
    fs::create_dir_all(&rules_dir)?;
    let mut rule_files = BTreeMap::new();
    let mut catalog_hasher = Sha256::new();
    let mut total_rules = 0_usize;
    for (language_name, language_id) in LANGUAGES {
        let receipt = manifest
            .languages
            .get(language_name)
            .with_context(|| format!("raw capture lacks {language_name} receipt"))?;
        validate_receipt(
            capture,
            language_name,
            receipt,
            language_id,
            manifest.page_size,
        )?;
        let catalog = extract_language(capture, language_name, receipt, &manifest.snapshot_sha256)?;
        total_rules += catalog.rules.len();
        let bytes = serde_json::to_vec_pretty(&catalog)?;
        reject_forbidden_output(&bytes)?;
        hash_record(&mut catalog_hasher, language_name.as_bytes());
        hash_record(&mut catalog_hasher, &bytes);
        let digest = sha256(&bytes);
        write_atomic_same(&rules_dir.join(format!("{language_name}.json")), &bytes)?;
        rule_files.insert(language_name.to_owned(), digest);
    }

    let (edition, mode, license) = imported_instance_evidence(capture, &manifest.server_version)?;
    let plugins = extract_plugins(&read_json(capture.join("plugins-installed.json"))?)?;

    let languages = manifest
        .languages
        .iter()
        .map(|(name, receipt)| {
            (
                name.clone(),
                SnapshotLanguage {
                    language: receipt.language.clone(),
                    repository: receipt.repository.clone(),
                    total: receipt.total,
                    unique_keys: receipt.unique_keys,
                    page_count: receipt.page_count,
                    show_count: receipt.show_count,
                    query_sha256: receipt.query_sha256.clone(),
                    pages_sha256: receipt.pages_sha256.clone(),
                    keys_sha256: receipt.keys_sha256.clone(),
                    shows_sha256: receipt.shows_sha256.clone(),
                },
            )
        })
        .collect();
    let snapshot = Snapshot {
        schema_version: 1,
        capture_sha256: manifest.snapshot_sha256,
        captured_at_utc: manifest.captured_at_utc,
        server_version: manifest.server_version,
        edition,
        instance_mode: mode,
        valid_license: license,
        page_size: manifest.page_size,
        community_classification: CLASSIFICATION.to_owned(),
        community_evidence_sha256: sha256(&community_bytes),
        catalog_sha256: hex::encode(catalog_hasher.finalize()),
        total_rules,
        languages,
        endpoints: manifest.endpoints,
        plugins,
        rule_files,
    };
    let snapshot_bytes = toml::to_string_pretty(&snapshot)?.into_bytes();
    write_atomic_same(&output.join("snapshot.toml"), &snapshot_bytes)
}

fn validated_community_resolution(path: &Path, server_version: &str) -> Result<Vec<u8>> {
    let bytes = read(path)?;
    let evidence: CommunityResolution = serde_json::from_slice(&bytes)
        .context("Community artifact-resolution evidence is invalid")?;
    ensure!(
        evidence.schema_version == 1,
        "unsupported Community evidence schema"
    );
    ensure!(
        evidence.target_server_version == server_version,
        "Community evidence targets a different server version"
    );
    ensure!(
        evidence.result == "exact-community-artifact-unavailable",
        "Community evidence does not prove exact artifact unavailability"
    );
    Ok(bytes)
}

fn imported_instance_evidence(
    capture: &Path,
    server_version: &str,
) -> Result<(String, String, bool)> {
    let navigation = read_json(capture.join("navigation-global.json"))?;
    ensure!(
        same_server_version(&json_string(&navigation, "version")?, server_version),
        "edition evidence belongs to a different server build"
    );
    let system_status = read_json(capture.join("system-status.json"))?;
    ensure!(
        json_string(&system_status, "version")? == server_version,
        "system status belongs to a different server version"
    );
    ensure!(
        !json_string(&system_status, "id")?.is_empty(),
        "system status lacks instance identity"
    );
    let edition = json_string(&navigation, "edition")?;
    ensure!(
        edition != "community",
        "licensed snapshot reports Community edition"
    );
    let mode = instance_mode(&read_json(capture.join("instance-mode.json"))?)?;
    let license = read_json(capture.join("license-validity.json"))?
        .get("isValidLicense")
        .and_then(Value::as_bool)
        .context("license-validity evidence lacks isValidLicense")?;
    ensure!(license, "licensed snapshot lacks valid license evidence");
    Ok((edition, mode, license))
}

pub fn audit(snapshot_path: &Path, require_pages_complete: bool) -> Result<()> {
    let snapshot_text = fs::read_to_string(snapshot_path)
        .with_context(|| format!("failed to read {}", snapshot_path.display()))?;
    let snapshot: Snapshot =
        toml::from_str(&snapshot_text).context("catalog snapshot is invalid")?;
    ensure!(
        snapshot.schema_version == 1,
        "unsupported catalog snapshot schema"
    );
    ensure!(
        snapshot.valid_license,
        "snapshot lacks valid license evidence"
    );
    ensure!(
        snapshot.community_classification == CLASSIFICATION,
        "snapshot has invalid Community classification"
    );
    let root = snapshot_path
        .parent()
        .context("snapshot path has no parent")?;
    let mut total = 0_usize;
    let mut catalog_hasher = Sha256::new();
    for (language_name, language_id) in LANGUAGES {
        let path = root.join("rules").join(format!("{language_name}.json"));
        let bytes = read(&path)?;
        reject_forbidden_output(&bytes)?;
        let catalog: RuleCatalog = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid catalog file {}", path.display()))?;
        ensure!(catalog.language == language_id, "catalog language mismatch");
        ensure!(
            catalog.classification == CLASSIFICATION,
            "catalog classification mismatch"
        );
        ensure!(
            catalog.source_capture_sha256 == snapshot.capture_sha256,
            "catalog capture provenance mismatch"
        );
        ensure!(
            is_strictly_sorted(&catalog.rules),
            "catalog rules are not strictly key-sorted"
        );
        ensure!(
            catalog
                .rules
                .iter()
                .all(|rule| !rule.is_external && !rule.is_template),
            "catalog contains external or template rule"
        );
        let receipt = snapshot
            .languages
            .get(language_name)
            .with_context(|| format!("snapshot lacks {language_name}"))?;
        ensure!(
            catalog.rules.len() as u64 == receipt.total,
            "catalog count mismatch"
        );
        if require_pages_complete {
            let expected_pages = if receipt.total == 0 {
                1
            } else {
                receipt.total.div_ceil(snapshot.page_size)
            };
            ensure!(
                receipt.page_count as u64 == expected_pages,
                "page count mismatch"
            );
            ensure!(
                receipt.unique_keys as u64 == receipt.total,
                "unique-key count mismatch"
            );
            ensure!(
                receipt.show_count as u64 == receipt.total,
                "show count mismatch"
            );
        }
        ensure!(
            snapshot.rule_files.get(language_name) == Some(&sha256(&bytes)),
            "catalog file hash mismatch"
        );
        hash_record(&mut catalog_hasher, language_name.as_bytes());
        hash_record(&mut catalog_hasher, &bytes);
        total += catalog.rules.len();
    }
    ensure!(
        total == snapshot.total_rules,
        "snapshot total rule count mismatch"
    );
    ensure!(
        hex::encode(catalog_hasher.finalize()) == snapshot.catalog_sha256,
        "catalog aggregate hash mismatch"
    );
    Ok(())
}

/// Audits implemented-rule coverage of the analyzer crates against the frozen catalogs.
///
/// A frozen rule counts as implemented when its distinguishing key marker (the part
/// after the repository prefix, such as `S103` or `BackticksUsage`) occurs anywhere in
/// the owning analyzer crate's source. The report prints one table row per language
/// followed by the missing-key lists. The command always exits successfully once the
/// inputs are readable; `strict` turns any coverage gap into exit code 1.
pub fn coverage(lang: Option<&str>, strict: bool) -> Result<()> {
    if let Some(lang) = lang {
        ensure!(
            LANGUAGES.iter().any(|(name, _)| *name == lang),
            "unknown language {lang}; expected one of csharp, javascript, typescript, python"
        );
    }
    let mut rows = Vec::new();
    for (name, language_id) in LANGUAGES {
        if lang.is_some_and(|filter| filter != name) {
            continue;
        }
        rows.push(coverage_language(name, language_id)?);
    }
    print_coverage(&rows);
    if strict && rows.iter().any(LanguageCoverage::has_gaps) {
        std::process::exit(1);
    }
    Ok(())
}

/// One language's rule classification against its analyzer crate source.
struct LanguageCoverage {
    name: &'static str,
    /// Keys with an implementation marker.
    implemented: usize,
    /// Keys without a marker that are actionable in-repository.
    missing: Vec<String>,
    /// Keys requiring out-of-repository infrastructure; documented skips.
    infra: Vec<String>,
}

impl LanguageCoverage {
    fn total(&self) -> usize {
        self.implemented + self.missing.len() + self.infra.len()
    }

    /// Whether any actionable frozen rule lacks an implementation marker.
    fn has_gaps(&self) -> bool {
        !self.missing.is_empty()
    }

    /// Coverage percentage over actionable rules; empty catalog = covered.
    fn percent(&self) -> f64 {
        let total = self.implemented + self.missing.len();
        if total == 0 {
            return 100.0;
        }
        let implemented = u32::try_from(self.implemented).unwrap_or(u32::MAX);
        let total = u32::try_from(total).unwrap_or(u32::MAX);
        f64::from(implemented) * 100.0 / f64::from(total)
    }
}

fn coverage_language(name: &'static str, language_id: &str) -> Result<LanguageCoverage> {
    let source_dir = coverage_source_dir(name)
        .with_context(|| format!("no analyzer crate maps language {name}"))?;
    let mut source = String::new();
    let mut sources = Vec::new();
    collect_rust_sources(Path::new(source_dir), &mut sources);
    for path in &sources {
        source.push_str(
            &fs::read_to_string(path)
                .with_context(|| format!("failed to read analyzer source {}", path.display()))?,
        );
        source.push('\n');
    }
    if sources.is_empty() {
        return Err(anyhow::anyhow!(
            "no Rust sources under analyzer directory {source_dir}"
        ));
    }
    let keys = coverage_keys(name, language_id)?;
    // Markers are matched against the full source (comments included): rule
    // keys legitimately appear in doc comments, section markers, and test
    // fixtures. Keys known to require out-of-repository infrastructure are
    // reported separately instead of as plain gaps.
    // Infra classification takes precedence over marker matching: a key that
    // only appears in a documented skip note must not count as implemented.
    let (infra_keys, actionable_keys): (Vec<_>, Vec<_>) = keys
        .iter()
        .partition(|key| infra_rules(name).contains(&key.as_str()));
    let infra = infra_keys.into_iter().cloned().collect::<Vec<_>>();
    let actionable: Vec<String> = actionable_keys.into_iter().cloned().collect();
    let missing = missing_rules(&actionable, &source);
    let implemented = actionable.len() - missing.len();
    Ok(LanguageCoverage {
        name,
        implemented,
        missing,
        infra,
    })
}

/// Rule keys excluded from the actionable gap count and listed separately:
/// implementations requiring infrastructure outside this repository (external
/// datasets, real type-checker engines, cross-file or runtime-configuration
/// context), or deliberate non-emissions rooted in parser-fidelity limits
/// (each documented as a skip note next to the nearest implementation).
fn infra_rules(name: &str) -> &'static [&'static str] {
    match name {
        "javascript" => &["javascript:S1438", "javascript:S1874", "javascript:S6627"],
        "typescript" => &[
            "typescript:S1438",
            "typescript:S1874",
            "typescript:S4325",
            "typescript:S4328",
            "typescript:S6606",
            "typescript:S6627",
        ],
        "python" => &["python:S6786"],
        "csharp" => &[
            "csharpsquid:S110",
            "csharpsquid:S1200",
            "csharpsquid:S1944",
            "csharpsquid:S3242",
            "csharpsquid:S3246",
            "csharpsquid:S4047",
            "csharpsquid:S6802",
        ],
        _ => &[],
    }
}

/// Recursively collects `*.rs` paths under one analyzer crate's `src` tree.
fn collect_rust_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Analyzer crate source tree scanned for rule markers, by catalog name.
///
/// `javascript` and `typescript` share the single `hoonarqube-jsts` crate.
fn coverage_source_dir(name: &str) -> Option<&'static str> {
    match name {
        "csharp" => Some("crates/hoonarqube-csharp/src"),
        "javascript" | "typescript" => Some("crates/hoonarqube-jsts/src"),
        "python" => Some("crates/hoonarqube-python/src"),
        _ => None,
    }
}

/// Frozen external keys for one language, reusing the audit catalog contract.
fn coverage_keys(name: &str, language_id: &str) -> Result<Vec<String>> {
    let path = Path::new("catalog")
        .join("rules")
        .join(format!("{name}.json"));
    let bytes = read(&path)?;
    let catalog: RuleCatalog = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid catalog file {}", path.display()))?;
    ensure!(catalog.language == language_id, "catalog language mismatch");
    Ok(catalog
        .rules
        .into_iter()
        .map(|rule| rule.external_key)
        .collect())
}

/// Missing rule keys whose implementation marker never occurs in `source`.
///
/// Keys arrive strictly sorted from the frozen catalog, so the result preserves
/// that order without re-sorting.
fn missing_rules(keys: &[String], source: &str) -> Vec<String> {
    keys.iter()
        .map(String::as_str)
        .filter(|key| !contains_marker(source, rule_key_marker(key)))
        .map(str::to_owned)
        .collect()
}

/// The distinguishing source marker for one rule key.
///
/// Strips the repository prefix (`python:BackticksUsage` -> `BackticksUsage`,
/// `csharpsquid:S103` -> `S103`); a prefix-less key marks itself.
fn rule_key_marker(external_key: &str) -> &str {
    match external_key.split_once(':') {
        Some((_, marker)) => marker,
        None => external_key,
    }
}

/// Whether `marker` occurs in `source` on identifier boundaries.
///
/// Stops `S112` from counting as implemented because `S1128` exists.
fn contains_marker(source: &str, marker: &str) -> bool {
    let mut from = 0;
    while let Some(offset) = source[from..].find(marker) {
        let begin = from + offset;
        let end = begin + marker.len();
        let id_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
        if !source[..begin].chars().next_back().is_some_and(id_char)
            && !source[end..].chars().next().is_some_and(id_char)
        {
            return true;
        }
        from = begin + 1;
    }
    false
}

fn print_coverage(rows: &[LanguageCoverage]) {
    println!("language      implemented  missing  infra  total  coverage");
    for row in rows {
        println!(
            "{:<12} {:>11} {:>7} {:>5} {:>6} {:>8.1}%",
            row.name,
            row.implemented,
            row.missing.len(),
            row.infra.len(),
            row.total(),
            row.percent(),
        );
    }
    for row in rows {
        if row.missing.is_empty() && row.infra.is_empty() {
            continue;
        }
        println!("\n{}:", row.name);
        for key in &row.missing {
            println!("  {key}");
        }
        for key in &row.infra {
            println!("  {key} (requires out-of-repository infrastructure)");
        }
    }
}

fn extract_language(
    capture: &Path,
    language_name: &str,
    receipt: &RawLanguageReceipt,
    capture_sha256: &str,
) -> Result<RuleCatalog> {
    let language_dir = capture.join("rules").join(language_name);
    let keys_value = read_json(language_dir.join("keys.json"))?;
    let keys = keys_value
        .as_array()
        .context("keys.json must be an array")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .context("rule key is not a string")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        keys.len() as u64 == receipt.total,
        "keys.json count mismatch"
    );
    ensure!(
        keys.windows(2).all(|pair| pair[0] < pair[1]),
        "keys.json is not strictly sorted"
    );
    let mut rules = Vec::with_capacity(keys.len());
    for (ordinal, expected_key) in keys.iter().enumerate() {
        let value = read_json(language_dir.join("show").join(format!("{ordinal:04}.json")))?;
        let rule = value.get("rule").context("rule show response lacks rule")?;
        rules.push(extract_rule(rule, expected_key, capture_sha256)?);
    }
    Ok(RuleCatalog {
        schema_version: 1,
        language: receipt.language.clone(),
        source_capture_sha256: capture_sha256.to_owned(),
        classification: CLASSIFICATION.to_owned(),
        rules,
    })
}

fn extract_rule(rule: &Value, expected_key: &str, capture_sha256: &str) -> Result<RuleRecord> {
    let external_key = json_string(rule, "key")?;
    ensure!(external_key == expected_key, "rule show key mismatch");
    let is_external = json_bool(rule, "isExternal")?;
    let is_template = json_bool(rule, "isTemplate")?;
    ensure!(
        !is_external && !is_template,
        "external/template rule crossed query boundary"
    );
    let impacts = rule
        .get("impacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|impact| {
            Ok(ImpactFact {
                software_quality: json_string(impact, "softwareQuality")?,
                severity: json_string(impact, "severity")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let parameters = rule
        .get("params")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|parameter| {
            Ok(ParameterFact {
                key: json_string(parameter, "key")?,
                default_value: optional_string(parameter, "defaultValue")?,
                parameter_type: optional_string(parameter, "type")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(RuleRecord {
        external_key,
        language: json_string(rule, "lang")?,
        repository: json_string(rule, "repo")?,
        status: json_string(rule, "status")?,
        scope: json_string(rule, "scope")?,
        severity: json_string(rule, "severity")?,
        rule_type: json_string(rule, "type")?,
        clean_code_attribute: optional_string(rule, "cleanCodeAttribute")?,
        clean_code_attribute_category: optional_string(rule, "cleanCodeAttributeCategory")?,
        impacts,
        is_external,
        is_template,
        parameters,
        sys_tags: string_array(rule, "sysTags")?,
        tags: string_array(rule, "tags")?,
        education_principles: string_array(rule, "educationPrinciples")?,
        classification: CLASSIFICATION.to_owned(),
        provenance_id: capture_sha256.to_owned(),
    })
}

fn extract_plugins(value: &Value) -> Result<Vec<PluginFact>> {
    let plugins = value
        .get("plugins")
        .and_then(Value::as_array)
        .context("plugins-installed response lacks plugins")?;
    let mut facts = plugins
        .iter()
        .map(|plugin| {
            Ok(PluginFact {
                key: json_string(plugin, "key")?,
                version: optional_string(plugin, "version")?,
                hash: optional_string(plugin, "hash")?,
                implementation_build: optional_string(plugin, "implementationBuild")?,
                edition_bundled: optional_bool(plugin, "editionBundled")?,
                plugin_type: optional_string(plugin, "type")?,
                required_for_languages: string_array(plugin, "requiredForLanguages")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    facts.sort_by(|left, right| left.key.cmp(&right.key));
    ensure!(
        facts.windows(2).all(|pair| pair[0].key < pair[1].key),
        "duplicate plugin key"
    );
    Ok(facts)
}

fn validate_receipt(
    capture: &Path,
    language_name: &str,
    receipt: &RawLanguageReceipt,
    language: &str,
    page_size: u64,
) -> Result<()> {
    ensure!(receipt.language == language, "language receipt mismatch");
    ensure!(
        receipt.unique_keys as u64 == receipt.total,
        "unique key closure mismatch"
    );
    ensure!(
        receipt.show_count as u64 == receipt.total,
        "show closure mismatch"
    );
    let expected_pages = if receipt.total == 0 {
        1
    } else {
        receipt.total.div_ceil(page_size)
    };
    ensure!(
        receipt.page_count as u64 == expected_pages,
        "page closure mismatch"
    );

    let language_dir = capture.join("rules").join(language_name);
    let query_bytes = read(language_dir.join("query.json"))?;
    ensure!(
        sha256(&query_bytes) == receipt.query_sha256,
        "query hash mismatch"
    );
    let keys_bytes = read(language_dir.join("keys.json"))?;
    ensure!(
        sha256(&keys_bytes) == receipt.keys_sha256,
        "keys hash mismatch"
    );
    let keys_value: Value = serde_json::from_slice(&keys_bytes).context("keys.json is invalid")?;
    let keys = keys_value
        .as_array()
        .context("keys.json must be an array")?
        .iter()
        .map(|value| value.as_str().context("rule key is not a string"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(keys.len() as u64 == receipt.total, "keys count mismatch");

    let mut pages_hasher = Sha256::new();
    for page in 1..=receipt.page_count {
        let bytes = read(language_dir.join(format!("page-{page:04}.json")))?;
        serde_json::from_slice::<Value>(&bytes).context("captured rule page is invalid")?;
        hash_record(&mut pages_hasher, &bytes);
    }
    ensure!(
        count_files_with_prefix(&language_dir, "page-", ".json")? == receipt.page_count,
        "captured page file count mismatch"
    );
    ensure!(
        hex::encode(pages_hasher.finalize()) == receipt.pages_sha256,
        "captured page aggregate hash mismatch"
    );

    let shows_dir = language_dir.join("show");
    let mut shows_hasher = Sha256::new();
    for (ordinal, key) in keys.iter().enumerate() {
        let bytes = read(shows_dir.join(format!("{ordinal:04}.json")))?;
        serde_json::from_slice::<Value>(&bytes).context("captured rule show is invalid")?;
        hash_record(&mut shows_hasher, key.as_bytes());
        hash_record(&mut shows_hasher, &bytes);
    }
    ensure!(
        count_regular_files(&shows_dir)? == receipt.show_count,
        "captured show file count mismatch"
    );
    ensure!(
        hex::encode(shows_hasher.finalize()) == receipt.shows_sha256,
        "captured show aggregate hash mismatch"
    );
    Ok(())
}

fn verify_raw_manifest(
    capture: &Path,
    manifest: &RawManifest,
    manifest_bytes: &[u8],
) -> Result<()> {
    let mut manifest_value: Value =
        serde_json::from_slice(manifest_bytes).context("raw capture manifest is invalid")?;
    let object = manifest_value
        .as_object_mut()
        .context("raw capture manifest must be an object")?;
    object.remove("snapshot_sha256");
    object.remove("captured_at_utc");
    ensure!(
        sha256(&canonical_json(&manifest_value)?) == manifest.snapshot_sha256,
        "raw capture manifest identity mismatch"
    );

    for (endpoint, file) in [
        ("api/server/version", "server-version.txt"),
        ("api/system/status", "system-status.json"),
        ("api/plugins/installed", "plugins-installed.json"),
        ("api/webservices/list", "webservices-list.json"),
        ("api/navigation/global", "navigation-global.json"),
        (
            "api/settings/values?keys=sonar.multi-quality-mode.enabled",
            "instance-mode.json",
        ),
        ("api/editions/is_valid_license", "license-validity.json"),
    ] {
        let receipt = manifest
            .endpoints
            .get(endpoint)
            .with_context(|| format!("raw capture lacks endpoint receipt {endpoint}"))?;
        ensure!(
            (200..300).contains(&receipt.status),
            "raw capture endpoint {endpoint} was not successful"
        );
        let bytes = read(capture.join(file))?;
        ensure!(bytes.len() == receipt.bytes, "endpoint byte count mismatch");
        ensure!(sha256(&bytes) == receipt.sha256, "endpoint hash mismatch");
    }
    Ok(())
}

fn count_files_with_prefix(directory: &Path, prefix: &str, suffix: &str) -> Result<usize> {
    Ok(fs::read_dir(directory)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_file())
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(prefix) && name.ends_with(suffix))
        })
        .count())
}

fn count_regular_files(directory: &Path) -> Result<usize> {
    Ok(fs::read_dir(directory)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .count())
}

pub(crate) fn same_server_version(left: &str, right: &str) -> bool {
    left.split(|character: char| !character.is_ascii_digit())
        .filter(|component| !component.is_empty())
        .eq(right
            .split(|character: char| !character.is_ascii_digit())
            .filter(|component| !component.is_empty()))
}

pub(crate) fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(sort).collect()),
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), sort(value)))
                    .collect(),
            ),
            scalar => scalar.clone(),
        }
    }

    serde_json::to_vec(&sort(value)).context("failed to canonicalize JSON")
}

fn instance_mode(value: &Value) -> Result<String> {
    value
        .get("settings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|setting| {
            setting.get("key").and_then(Value::as_str) == Some("sonar.multi-quality-mode.enabled")
        })
        .and_then(|setting| setting.get("value"))
        .and_then(Value::as_str)
        .map(|enabled| if enabled == "true" { "mqr" } else { "standard" }.to_owned())
        .context("instance-mode evidence is missing")
}

fn is_strictly_sorted(rules: &[RuleRecord]) -> bool {
    rules
        .windows(2)
        .all(|pair| pair[0].external_key < pair[1].external_key)
}

fn reject_forbidden_output(bytes: &[u8]) -> Result<()> {
    fn walk(value: &Value) -> Result<()> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    ensure!(
                        !matches!(
                            key.as_str(),
                            "name"
                                | "description"
                                | "descriptionSections"
                                | "message"
                                | "content"
                                | "htmlDesc"
                                | "mdDesc"
                                | "remFnBaseEffort"
                                | "defaultRemFnBaseEffort"
                        ),
                        "forbidden prose field {key} in generated catalog"
                    );
                    walk(child)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    walk(child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    let value: Value =
        serde_json::from_slice(bytes).context("generated catalog JSON is invalid")?;
    walk(&value)
}

fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn read_json(path: impl AsRef<Path>) -> Result<Value> {
    let path = path.as_ref();
    serde_json::from_slice(&read(path)?).with_context(|| format!("invalid JSON {}", path.display()))
}

fn json_string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .with_context(|| format!("required string field {key} is missing"))
}

fn optional_string(value: &Value, key: &str) -> Result<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => bail!("optional string field {key} has wrong type"),
    }
}

fn json_bool(value: &Value, key: &str) -> Result<bool> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .with_context(|| format!("required boolean field {key} is missing"))
}

fn optional_bool(value: &Value, key: &str) -> Result<Option<bool>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => bail!("optional boolean field {key} has wrong type"),
    }
}

fn string_array(value: &Value, key: &str) -> Result<Vec<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .with_context(|| format!("array field {key} contains non-string"))
            })
            .collect(),
        Some(_) => bail!("array field {key} has wrong type"),
    }
}

fn write_atomic_same(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(existing) = fs::read(path) {
        ensure!(
            existing == bytes,
            "refusing conflicting generated file {}",
            path.display()
        );
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = temporary_path(path);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".tmp-{}", std::process::id()));
    PathBuf::from(name)
}

pub(crate) fn hash_record(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_marker_strips_repository_prefix() {
        assert_eq!(rule_key_marker("python:BackticksUsage"), "BackticksUsage");
        assert_eq!(rule_key_marker("csharpsquid:S103"), "S103");
        assert_eq!(rule_key_marker("javascript:S1523"), "S1523");
    }

    #[test]
    fn rule_marker_keeps_prefixless_key() {
        assert_eq!(rule_key_marker("S103"), "S103");
    }

    #[test]
    fn missing_rules_split_implemented_and_missing_in_order() {
        let keys = vec![
            "javascript:S100".to_owned(),
            "javascript:S122".to_owned(),
            "javascript:S1523".to_owned(),
        ];
        // Markers are matched case-sensitively: lowercase `s122` does not count.
        let source = "fn check_s122() {} // S1523 marker";
        assert_eq!(
            missing_rules(&keys, source),
            vec!["javascript:S100", "javascript:S122"]
        );
    }

    #[test]
    fn missing_rules_rejects_longer_rule_id_collisions() {
        // `python:S112` must stay missing even though `python:S1128`'s
        // marker occurs: digit-suffixed ids otherwise satisfy shorter ones.
        let keys = vec!["python:S112".to_owned(), "python:S1128".to_owned()];
        let source = "// python:S1128 implementation";
        assert_eq!(missing_rules(&keys, source), vec!["python:S112"]);
    }

    #[test]
    fn every_catalog_language_maps_to_analyzer_source() {
        for (name, _) in LANGUAGES {
            assert!(coverage_source_dir(name).is_some());
        }
        assert_eq!(coverage_source_dir("unknown"), None);
    }

    #[test]
    fn percent_counts_empty_catalog_as_complete() {
        let row = LanguageCoverage {
            name: "python",
            implemented: 0,
            missing: Vec::new(),
            infra: Vec::new(),
        };
        assert!((row.percent() - 100.0).abs() < 1e-9);
        assert!(!row.has_gaps());
    }
}
