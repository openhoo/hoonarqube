use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use syn::parse::Parser as _;
use syn::visit::{self, Visit as _};

const LANGUAGES: [(&str, &str, &str); 6] = [
    ("csharp", "cs", "csharpsquid"),
    ("javascript", "js", "javascript"),
    ("typescript", "ts", "typescript"),
    ("python", "py", "python"),
    ("go", "go", "go"),
    ("rust", "rust", "rust"),
];
const REQUIRED_ENDPOINTS: [&str; 6] = [
    "api/navigation/global",
    "api/plugins/installed",
    "api/server/version",
    "api/settings/values?keys=sonar.multi-quality-mode.enabled",
    "api/system/status",
    "api/webservices/list",
];
const COMMUNITY_CLASSIFICATION: &str = "community-base";
const ENTERPRISE_UNVERIFIED_CLASSIFICATION: &str = "enterprise-unverified";
const SCOPE_CLASSIFICATION: &str = "community-plus-enterprise-unverified";
const INFRA_BOUNDARIES_JSON: &str = include_str!("../../catalog/infra-boundaries.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InfraBoundaryManifest {
    schema_version: u16,
    boundaries: BTreeMap<String, InfraBoundary>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InfraBoundary {
    reason: String,
    implementation_gap: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema_version: u16,
    captured_at_utc: String,
    approval_id: String,
    instance: String,
    base_origin: String,
    server_version: String,
    page_size: u64,
    project_prefix: String,
    endpoints: BTreeMap<String, RawResponseReceipt>,
    languages: BTreeMap<String, RawLanguageReceipt>,
    snapshot_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawResponseReceipt {
    status: u16,
    bytes: usize,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    target: CommunityTarget,
    enterprise_unverified_rules: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommunityTarget {
    oracle_edition: String,
    requires_license: bool,
    includes_enterprise_rules: bool,
    classification: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuleCatalog {
    schema_version: u16,
    language: String,
    source_capture_sha256: String,
    classification: String,
    rules: Vec<RuleRecord>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
struct ImpactFact {
    software_quality: String,
    severity: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ParameterFact {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameter_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u16,
    capture_sha256: String,
    captured_at_utc: String,
    server_version: String,
    edition: String,
    oracle_edition: String,
    instance_mode: String,
    page_size: u64,
    scope_classification: String,
    community_evidence_sha256: String,
    catalog_sha256: String,
    source_total_rules: usize,
    total_rules: usize,
    unverified_rules: BTreeMap<String, Vec<String>>,
    languages: BTreeMap<String, SnapshotLanguage>,
    endpoints: BTreeMap<String, RawResponseReceipt>,
    plugins: Vec<PluginFact>,
    rule_files: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotLanguage {
    language: String,
    repository: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_capture_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    captured_at_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_edition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oracle_edition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instance_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    page_size: Option<u64>,
    source_total: u64,
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
#[serde(deny_unknown_fields)]
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

pub fn import(
    capture: &Path,
    community_resolution: &Path,
    output: &Path,
    merge: bool,
) -> Result<()> {
    let original_digest = catalog_directory_digest(output)?;
    let staging = allocate_catalog_sibling(output, "staging")?;
    let mut staging_cleanup = DirectoryCleanup::new(staging.clone());
    if original_digest.is_some() {
        copy_catalog_directory(output, &staging)?;
    }

    import_into(capture, community_resolution, &staging, merge)?;
    ensure!(
        catalog_directory_digest(output)? == original_digest,
        "catalog output changed during import"
    );
    publish_catalog_directory(output, &staging, original_digest.is_some())?;
    staging_cleanup.disarm();
    Ok(())
}

fn import_into(
    capture: &Path,
    community_resolution: &Path,
    output: &Path,
    merge: bool,
) -> Result<()> {
    let manifest_bytes = read(capture.join("manifest.json"))?;
    let manifest: RawManifest =
        serde_json::from_slice(&manifest_bytes).context("raw capture manifest is invalid")?;
    ensure!(
        manifest.schema_version == 1,
        "unsupported raw capture schema"
    );
    ensure!(manifest.page_size > 0, "raw capture page size is zero");
    ensure!(
        !manifest.captured_at_utc.is_empty()
            && !manifest.approval_id.trim().is_empty()
            && !manifest.instance.is_empty()
            && !manifest.base_origin.is_empty()
            && !manifest.server_version.is_empty()
            && !manifest.project_prefix.is_empty()
            && is_sha256(&manifest.snapshot_sha256),
        "raw capture provenance is incomplete"
    );
    ensure!(
        !manifest.languages.is_empty(),
        "raw capture has no languages"
    );
    ensure!(
        manifest.languages.keys().all(|name| {
            LANGUAGES
                .iter()
                .any(|(known_name, _, _)| known_name == &name.as_str())
        }),
        "raw capture contains an unknown language"
    );
    if !merge {
        ensure!(
            manifest.languages.len() == LANGUAGES.len(),
            "raw capture language count mismatch"
        );
    }
    verify_raw_manifest(capture, &manifest, &manifest_bytes)?;

    let (community_bytes, resolution) = validated_community_resolution(community_resolution)?;

    let (edition, mode) = imported_instance_evidence(capture, &manifest.server_version)?;
    let plugins = extract_plugins(&read_json(capture.join("plugins-installed.json"))?)?;
    let existing_snapshot = if merge {
        let snapshot_text = fs::read_to_string(output.join("snapshot.toml"))
            .context("merge import requires an existing catalog snapshot")?;
        let mut existing: Snapshot =
            toml::from_str(&snapshot_text).context("existing catalog snapshot is invalid")?;
        migrate_snapshot_provenance(&mut existing)?;
        validate_catalog_state(output, &existing).context("merge-base catalog is invalid")?;
        Some(existing)
    } else {
        None
    };
    let imported_rule_files = import_rule_catalogs(capture, output, &manifest, &resolution, merge)?;
    write_generated_file(
        &output.join("community-artifact-resolution.json"),
        &community_bytes,
        merge,
    )?;

    let imported_languages = snapshot_languages(&manifest, &edition, &mode);
    let mut snapshot = if let Some(mut existing) = existing_snapshot {
        existing.languages.extend(imported_languages);
        existing.rule_files.extend(imported_rule_files);
        existing.schema_version = 4;
        existing.community_evidence_sha256 = sha256(&community_bytes);
        existing.unverified_rules = resolution.enterprise_unverified_rules;
        existing
    } else {
        Snapshot {
            schema_version: 4,
            capture_sha256: manifest.snapshot_sha256,
            captured_at_utc: manifest.captured_at_utc,
            server_version: manifest.server_version,
            oracle_edition: resolution.target.oracle_edition,
            edition,
            instance_mode: mode,
            page_size: manifest.page_size,
            scope_classification: SCOPE_CLASSIFICATION.to_owned(),
            community_evidence_sha256: sha256(&community_bytes),
            catalog_sha256: String::new(),
            source_total_rules: 0,
            total_rules: 0,
            unverified_rules: resolution.enterprise_unverified_rules,
            languages: imported_languages,
            endpoints: manifest.endpoints,
            plugins,
            rule_files: imported_rule_files,
        }
    };
    let (catalog_sha256, total_rules, rule_files) = aggregate_catalog(output)?;
    snapshot.catalog_sha256 = catalog_sha256;
    snapshot.source_total_rules = total_rules;
    snapshot.total_rules = total_rules;
    snapshot.rule_files = rule_files;
    validate_catalog_state(output, &snapshot).context("imported catalog is invalid")?;
    let snapshot_bytes = toml::to_string_pretty(&snapshot)?.into_bytes();
    let snapshot_path = output.join("snapshot.toml");
    if merge {
        write_atomic_replace(&snapshot_path, &snapshot_bytes)
    } else {
        write_atomic_same(&snapshot_path, &snapshot_bytes)
    }
}

fn allocate_catalog_sibling(output: &Path, purpose: &str) -> Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = output
        .file_name()
        .context("catalog output path has no final component")?
        .to_string_lossy();
    for _ in 0..100 {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{name}.{purpose}-{}-{id}", std::process::id()));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).context("failed to allocate catalog staging directory");
            }
        }
    }
    bail!("failed to allocate catalog staging directory")
}

fn copy_catalog_directory(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to inspect {}", source.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "catalog output is not a regular directory"
    );
    copy_catalog_children(source, destination)?;
    fs::set_permissions(destination, metadata.permissions())?;
    Ok(())
}

fn copy_catalog_children(source: &Path, destination: &Path) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "catalog contains symbolic link {}",
            source_path.display()
        );
        if metadata.is_dir() {
            fs::create_dir(&destination_path)?;
            copy_catalog_children(&source_path, &destination_path)?;
            fs::set_permissions(&destination_path, metadata.permissions())?;
        } else {
            ensure!(
                metadata.is_file(),
                "catalog contains non-file entry {}",
                source_path.display()
            );
            fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

fn catalog_directory_digest(output: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", output.display()));
        }
        Ok(metadata) => ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "catalog output is not a regular directory"
        ),
    }
    let mut hasher = Sha256::new();
    hash_catalog_children(output, output, &mut hasher)?;
    Ok(Some(hex::encode(hasher.finalize())))
}

fn hash_catalog_children(root: &Path, directory: &Path, hasher: &mut Sha256) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(directory)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "catalog contains symbolic link {}",
            path.display()
        );
        let relative = path.strip_prefix(root)?;
        hash_record(hasher, relative.to_string_lossy().as_bytes());
        if metadata.is_dir() {
            hash_record(hasher, b"directory");
            hash_catalog_children(root, &path, hasher)?;
        } else {
            ensure!(
                metadata.is_file(),
                "catalog contains non-file entry {}",
                path.display()
            );
            hash_record(hasher, b"file");
            hash_record(hasher, &fs::read(&path)?);
        }
    }
    Ok(())
}

fn publish_catalog_directory(output: &Path, staging: &Path, replacing: bool) -> Result<()> {
    if !replacing {
        fs::rename(staging, output).context("failed to publish catalog directory")?;
        return Ok(());
    }

    let backup = allocate_catalog_sibling(output, "backup")?;
    fs::remove_dir(&backup)?;
    fs::rename(output, &backup).context("failed to reserve existing catalog for rollback")?;
    if let Err(publish_error) = fs::rename(staging, output) {
        let rollback = fs::rename(&backup, output);
        return match rollback {
            Ok(()) => {
                Err(publish_error).context("failed to publish catalog directory; rolled back")
            }
            Err(rollback_error) => bail!(
                "failed to publish catalog directory ({publish_error}); rollback also failed ({rollback_error})"
            ),
        };
    }
    // Publication is complete. Failure to delete this private rollback copy
    // must not turn a successful transaction into a reported failure.
    let _ = fs::remove_dir_all(backup);
    Ok(())
}

struct DirectoryCleanup {
    path: PathBuf,
    armed: bool,
}

impl DirectoryCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DirectoryCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn snapshot_languages(
    manifest: &RawManifest,
    edition: &str,
    mode: &str,
) -> BTreeMap<String, SnapshotLanguage> {
    manifest
        .languages
        .iter()
        .map(|(name, receipt)| {
            (
                name.clone(),
                SnapshotLanguage {
                    language: receipt.language.clone(),
                    repository: receipt.repository.clone(),
                    source_capture_sha256: Some(manifest.snapshot_sha256.clone()),
                    captured_at_utc: Some(manifest.captured_at_utc.clone()),
                    server_version: Some(manifest.server_version.clone()),
                    source_edition: Some(edition.to_owned()),
                    oracle_edition: Some("community".to_owned()),
                    instance_mode: Some(mode.to_owned()),
                    page_size: Some(manifest.page_size),
                    source_total: receipt.total,
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
        .collect()
}

fn import_rule_catalogs(
    capture: &Path,
    output: &Path,
    manifest: &RawManifest,
    resolution: &CommunityResolution,
    replace: bool,
) -> Result<BTreeMap<String, String>> {
    let rules_dir = output.join("rules");
    let mut rule_files = BTreeMap::new();
    let mut prepared = Vec::new();
    for (language_name, language_id, repository) in LANGUAGES {
        let Some(receipt) = manifest.languages.get(language_name) else {
            continue;
        };
        validate_receipt(
            capture,
            language_name,
            receipt,
            language_id,
            repository,
            manifest.page_size,
        )?;
        let mut catalog =
            extract_language(capture, language_name, receipt, &manifest.snapshot_sha256)?;
        let unverified = resolution
            .enterprise_unverified_rules
            .get(language_name)
            .with_context(|| format!("Community evidence lacks {language_name} rule scope"))?;
        ensure!(
            unverified.windows(2).all(|pair| pair[0] < pair[1]),
            "unverified rules are not strictly key-sorted"
        );
        for rule in &mut catalog.rules {
            let classification = if unverified.binary_search(&rule.external_key).is_ok() {
                ENTERPRISE_UNVERIFIED_CLASSIFICATION
            } else {
                COMMUNITY_CLASSIFICATION
            };
            classification.clone_into(&mut rule.classification);
        }
        ensure!(
            unverified.iter().all(|key| {
                key.strip_prefix(repository)
                    .and_then(|rest| rest.strip_prefix(':'))
                    .is_some_and(|marker| !marker.is_empty())
                    && catalog.rules.iter().any(|rule| &rule.external_key == key)
            }),
            "source capture lacks an Enterprise-unverified rule"
        );
        SCOPE_CLASSIFICATION.clone_into(&mut catalog.classification);
        audit_rule_facts(&catalog, language_id, repository)?;
        let bytes = serde_json::to_vec_pretty(&catalog)?;
        reject_forbidden_output(&bytes)?;
        let digest = sha256(&bytes);
        prepared.push((language_name, bytes, digest));
    }
    fs::create_dir_all(&rules_dir)?;
    for (language_name, bytes, digest) in prepared {
        let path = rules_dir.join(format!("{language_name}.json"));
        write_generated_file(&path, &bytes, replace)?;
        rule_files.insert(language_name.to_owned(), digest);
    }
    Ok(rule_files)
}

fn migrate_snapshot_provenance(snapshot: &mut Snapshot) -> Result<()> {
    ensure!(
        matches!(snapshot.schema_version, 3 | 4),
        "unsupported merge-base snapshot schema"
    );
    for language in snapshot.languages.values_mut() {
        language
            .source_capture_sha256
            .get_or_insert_with(|| snapshot.capture_sha256.clone());
        language
            .captured_at_utc
            .get_or_insert_with(|| snapshot.captured_at_utc.clone());
        language
            .server_version
            .get_or_insert_with(|| snapshot.server_version.clone());
        language
            .source_edition
            .get_or_insert_with(|| snapshot.edition.clone());
        language
            .oracle_edition
            .get_or_insert_with(|| snapshot.oracle_edition.clone());
        language
            .instance_mode
            .get_or_insert_with(|| snapshot.instance_mode.clone());
        language.page_size.get_or_insert(snapshot.page_size);
    }
    snapshot.schema_version = 4;
    Ok(())
}

fn validate_catalog_state(output: &Path, snapshot: &Snapshot) -> Result<()> {
    audit_snapshot(snapshot)?;
    let evidence_path = output.join("community-artifact-resolution.json");
    let (evidence_bytes, resolution) = validated_community_resolution(&evidence_path)?;
    ensure!(
        snapshot.community_evidence_sha256 == sha256(&evidence_bytes)
            && snapshot.unverified_rules == resolution.enterprise_unverified_rules,
        "catalog Community evidence mismatch"
    );
    let mut source_total = 0_usize;
    let mut scoped_total = 0_usize;
    let mut catalog_hasher = Sha256::new();
    for (name, language_id, repository) in LANGUAGES {
        let (source_count, scoped_count) = audit_language(
            output,
            snapshot,
            name,
            language_id,
            repository,
            true,
            &mut catalog_hasher,
        )?;
        source_total += source_count;
        scoped_total += scoped_count;
    }
    ensure!(
        source_total == snapshot.source_total_rules
            && scoped_total == snapshot.total_rules
            && hex::encode(catalog_hasher.finalize()) == snapshot.catalog_sha256,
        "catalog aggregate mismatch"
    );
    Ok(())
}

fn aggregate_catalog(output: &Path) -> Result<(String, usize, BTreeMap<String, String>)> {
    let mut hasher = Sha256::new();
    let mut total = 0_usize;
    let mut files = BTreeMap::new();
    for (name, _, _) in LANGUAGES {
        let bytes = read(output.join("rules").join(format!("{name}.json")))?;
        let catalog: RuleCatalog =
            serde_json::from_slice(&bytes).with_context(|| format!("catalog {name} is invalid"))?;
        hash_record(&mut hasher, name.as_bytes());
        hash_record(&mut hasher, &bytes);
        total += catalog.rules.len();
        files.insert(name.to_owned(), sha256(&bytes));
    }
    Ok((hex::encode(hasher.finalize()), total, files))
}

fn validated_community_resolution(path: &Path) -> Result<(Vec<u8>, CommunityResolution)> {
    let bytes = read(path)?;
    let evidence: CommunityResolution = serde_json::from_slice(&bytes)
        .context("Community artifact-resolution evidence is invalid")?;
    ensure!(
        evidence.schema_version == 3,
        "unsupported Community evidence schema"
    );
    ensure!(
        evidence.target.oracle_edition == "community"
            && !evidence.target.requires_license
            && evidence.target.includes_enterprise_rules
            && evidence.target.classification == SCOPE_CLASSIFICATION,
        "Community evidence does not describe the declared mixed rule scope"
    );
    ensure!(
        evidence.enterprise_unverified_rules.len() == LANGUAGES.len()
            && LANGUAGES
                .iter()
                .all(|(name, _, _)| evidence.enterprise_unverified_rules.contains_key(*name)),
        "Community evidence language scope mismatch"
    );
    Ok((bytes, evidence))
}

fn imported_instance_evidence(capture: &Path, server_version: &str) -> Result<(String, String)> {
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
    let mode = instance_mode(&read_json(capture.join("instance-mode.json"))?)?;
    Ok((edition, mode))
}

pub fn audit(snapshot_path: &Path, require_pages_complete: bool) -> Result<()> {
    let snapshot_text = fs::read_to_string(snapshot_path)
        .with_context(|| format!("failed to read {}", snapshot_path.display()))?;
    let snapshot: Snapshot =
        toml::from_str(&snapshot_text).context("catalog snapshot is invalid")?;
    audit_snapshot(&snapshot)?;
    let root = snapshot_path
        .parent()
        .context("snapshot path has no parent")?;
    let community_path = root.join("community-artifact-resolution.json");
    let (community_evidence, resolution) = validated_community_resolution(&community_path)?;
    ensure!(
        resolution.enterprise_unverified_rules == snapshot.unverified_rules,
        "snapshot unverified rules differ from Community evidence"
    );
    ensure!(
        snapshot.community_evidence_sha256 == sha256(&community_evidence),
        "Community scope evidence hash mismatch"
    );

    let mut source_total = 0_usize;
    let mut scoped_total = 0_usize;
    let mut catalog_hasher = Sha256::new();
    for (language_name, language_id, repository) in LANGUAGES {
        let (source_count, scoped_count) = audit_language(
            root,
            &snapshot,
            language_name,
            language_id,
            repository,
            require_pages_complete,
            &mut catalog_hasher,
        )?;
        source_total += source_count;
        scoped_total += scoped_count;
    }
    ensure!(
        source_total == snapshot.source_total_rules,
        "snapshot total rule count mismatch"
    );
    ensure!(
        scoped_total == snapshot.total_rules,
        "snapshot scoped rule count mismatch"
    );
    ensure!(
        hex::encode(catalog_hasher.finalize()) == snapshot.catalog_sha256,
        "catalog aggregate hash mismatch"
    );
    Ok(())
}

fn audit_snapshot(snapshot: &Snapshot) -> Result<()> {
    ensure!(
        snapshot.schema_version == 4,
        "unsupported catalog snapshot schema"
    );
    ensure!(
        snapshot.oracle_edition == "community",
        "snapshot oracle is not Community"
    );
    ensure!(
        snapshot.scope_classification == SCOPE_CLASSIFICATION,
        "snapshot has invalid scope classification"
    );
    ensure!(
        is_sha256(&snapshot.capture_sha256)
            && is_sha256(&snapshot.catalog_sha256)
            && !snapshot.captured_at_utc.is_empty()
            && !snapshot.server_version.is_empty()
            && !snapshot.edition.is_empty()
            && !snapshot.instance_mode.is_empty()
            && snapshot.page_size > 0,
        "snapshot capture provenance is incomplete"
    );
    ensure!(
        has_exact_language_keys(&snapshot.languages)
            && has_exact_language_keys(&snapshot.unverified_rules)
            && has_exact_language_keys(&snapshot.rule_files),
        "snapshot language scope mismatch"
    );
    ensure!(
        snapshot.endpoints.len() == REQUIRED_ENDPOINTS.len()
            && REQUIRED_ENDPOINTS
                .iter()
                .all(|endpoint| snapshot.endpoints.contains_key(*endpoint))
            && snapshot.endpoints.values().all(|receipt| {
                (200..300).contains(&receipt.status)
                    && receipt.bytes > 0
                    && is_sha256(&receipt.sha256)
            }),
        "snapshot endpoint provenance is incomplete"
    );
    ensure!(
        !snapshot.plugins.is_empty()
            && snapshot
                .plugins
                .windows(2)
                .all(|pair| pair[0].key < pair[1].key)
            && snapshot.plugins.iter().all(|plugin| !plugin.key.is_empty()),
        "snapshot plugin provenance is incomplete"
    );
    Ok(())
}

fn audit_language(
    root: &Path,
    snapshot: &Snapshot,
    language_name: &str,
    language_id: &str,
    repository: &str,
    _require_pages_complete: bool,
    catalog_hasher: &mut Sha256,
) -> Result<(usize, usize)> {
    let path = root.join("rules").join(format!("{language_name}.json"));
    let bytes = read(&path)?;
    reject_forbidden_output(&bytes)?;
    let catalog: RuleCatalog = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid catalog file {}", path.display()))?;
    ensure!(
        catalog.schema_version == 1,
        "unsupported rule catalog schema"
    );
    ensure!(catalog.language == language_id, "catalog language mismatch");
    ensure!(
        catalog.classification == SCOPE_CLASSIFICATION,
        "catalog classification mismatch"
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
    audit_language_receipt(
        snapshot,
        language_name,
        receipt,
        &catalog,
        language_id,
        repository,
    )?;
    ensure!(
        snapshot.rule_files.get(language_name) == Some(&sha256(&bytes)),
        "catalog file hash mismatch"
    );
    hash_record(catalog_hasher, language_name.as_bytes());
    hash_record(catalog_hasher, &bytes);
    Ok((catalog.rules.len(), catalog.rules.len()))
}

fn audit_language_receipt(
    snapshot: &Snapshot,
    language_name: &str,
    receipt: &SnapshotLanguage,
    catalog: &RuleCatalog,
    language_id: &str,
    repository: &str,
) -> Result<()> {
    ensure!(
        receipt.language == language_id && receipt.repository == repository,
        "language receipt identity mismatch"
    );
    ensure!(
        receipt.source_capture_sha256.as_deref() == Some(catalog.source_capture_sha256.as_str()),
        "catalog capture provenance mismatch"
    );
    ensure!(
        receipt.oracle_edition.as_deref() == Some("community")
            && receipt.page_size.is_some_and(|size| size > 0)
            && receipt
                .source_capture_sha256
                .as_deref()
                .is_some_and(is_sha256)
            && is_sha256(&receipt.query_sha256)
            && is_sha256(&receipt.pages_sha256)
            && is_sha256(&receipt.keys_sha256)
            && is_sha256(&receipt.shows_sha256)
            && receipt
                .server_version
                .as_deref()
                .is_some_and(|version| !version.is_empty())
            && receipt
                .captured_at_utc
                .as_deref()
                .is_some_and(|timestamp| !timestamp.is_empty())
            && receipt
                .source_edition
                .as_deref()
                .is_some_and(|edition| !edition.is_empty())
            && receipt
                .instance_mode
                .as_deref()
                .is_some_and(|mode| !mode.is_empty()),
        "language capture provenance is incomplete"
    );
    let unverified = snapshot
        .unverified_rules
        .get(language_name)
        .with_context(|| format!("snapshot lacks {language_name} unverified rules"))?;
    ensure!(
        unverified.windows(2).all(|pair| pair[0] < pair[1]),
        "unverified rules are not strictly key-sorted"
    );
    ensure!(
        unverified.iter().all(|key| {
            key.strip_prefix(repository)
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|marker| !marker.is_empty())
                && catalog.rules.iter().any(|rule| &rule.external_key == key)
        }),
        "invalid or missing unverified rule"
    );
    ensure!(
        catalog.rules.iter().all(|rule| {
            let expected = if unverified.binary_search(&rule.external_key).is_ok() {
                ENTERPRISE_UNVERIFIED_CLASSIFICATION
            } else {
                COMMUNITY_CLASSIFICATION
            };
            rule.classification == expected
        }),
        "rule verification classification mismatch"
    );
    ensure!(
        catalog.rules.len() as u64 == receipt.source_total
            && catalog.rules.len() as u64 == receipt.total,
        "catalog count mismatch"
    );
    audit_rule_facts(catalog, language_id, repository)?;
    let expected_pages = receipt
        .source_total
        .max(1)
        .div_ceil(receipt.page_size.context("language page size is missing")?);
    ensure!(
        counts_match(expected_pages, receipt.page_count),
        "page count mismatch"
    );
    ensure!(
        counts_match(receipt.source_total, receipt.unique_keys),
        "unique-key count mismatch"
    );
    ensure!(
        counts_match(receipt.source_total, receipt.show_count),
        "show count mismatch"
    );
    Ok(())
}

fn audit_rule_facts(catalog: &RuleCatalog, language_id: &str, repository: &str) -> Result<()> {
    ensure!(
        is_sha256(&catalog.source_capture_sha256)
            && catalog.rules.iter().all(|rule| {
                rule.language == language_id
                    && rule.repository == repository
                    && rule
                        .external_key
                        .strip_prefix(repository)
                        .and_then(|rest| rest.strip_prefix(':'))
                        .is_some_and(|marker| !marker.is_empty())
            }),
        "catalog rule identity mismatch"
    );
    ensure!(
        catalog.rules.iter().all(|rule| {
            rule.provenance_id == catalog.source_capture_sha256
                && !rule.status.is_empty()
                && !rule.scope.is_empty()
                && !rule.severity.is_empty()
                && !rule.rule_type.is_empty()
                && rule
                    .clean_code_attribute
                    .as_ref()
                    .is_none_or(|value| !value.is_empty())
                && rule
                    .clean_code_attribute_category
                    .as_ref()
                    .is_none_or(|value| !value.is_empty())
                && rule.impacts.iter().all(|impact| {
                    !impact.software_quality.is_empty() && !impact.severity.is_empty()
                })
                && rule
                    .parameters
                    .iter()
                    .all(|parameter| !parameter.key.is_empty())
                && all_unique(
                    rule.parameters
                        .iter()
                        .map(|parameter| parameter.key.as_str()),
                )
        }),
        "catalog contains incomplete rule facts"
    );
    Ok(())
}

fn all_unique<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn has_exact_language_keys<T>(map: &BTreeMap<String, T>) -> bool {
    map.len() == LANGUAGES.len() && LANGUAGES.iter().all(|(name, _, _)| map.contains_key(*name))
}

fn counts_match(total: u64, count: usize) -> bool {
    u64::try_from(count).is_ok_and(|count| count == total)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Audits implemented-rule coverage of the analyzer crates against the frozen catalogs.
///
/// A frozen rule counts as implemented when its distinguishing key marker (the part
/// after the repository prefix, such as `S103` or `BackticksUsage`) occurs in a compiled
/// string literal used by analyzer code. It counts as tested only when the complete
/// repository-qualified key occurs in a `#[cfg(test)]` string literal. Comments, doc
/// attributes, identifiers, and longer colliding rule IDs cannot satisfy either
/// requirement. The report prints one table
/// row per language followed by all gap lists. The command always exits successfully
/// once the inputs are readable; `strict` turns implementation, test, and infrastructure
/// gaps into exit code 1 unless `allow_infra` permits documented infrastructure gaps.
pub fn coverage(lang: Option<&str>, strict: bool, allow_infra: bool) -> Result<()> {
    if let Some(lang) = lang {
        ensure!(
            LANGUAGES.iter().any(|(name, _, _)| *name == lang),
            "unknown language {lang}; expected one of csharp, javascript, typescript, python, go, rust"
        );
    }
    audit(Path::new("catalog/snapshot.toml"), true)
        .context("catalog integrity audit failed before coverage")?;
    let mut rows = Vec::new();
    for (name, language_id, _) in LANGUAGES {
        if lang.is_some_and(|filter| filter != name) {
            continue;
        }
        rows.push(coverage_language(name, language_id)?);
    }
    print_coverage(&rows);
    if strict && rows.iter().any(|row| row.has_gaps(allow_infra)) {
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
    /// Implemented keys without a repository-qualified test marker.
    untested: Vec<String>,
    /// Keys requiring out-of-repository infrastructure; documented skips.
    infra: Vec<String>,
}

impl LanguageCoverage {
    fn total(&self) -> usize {
        self.implemented + self.missing.len() + self.infra.len()
    }

    /// Whether any actionable frozen rule lacks an implementation marker.
    fn has_gaps(&self, allow_infra: bool) -> bool {
        !self.missing.is_empty()
            || !self.untested.is_empty()
            || (!allow_infra && !self.infra.is_empty())
    }

    fn tested(&self) -> usize {
        self.implemented.saturating_sub(self.untested.len())
    }

    /// Coverage percentage over actionable rules; empty catalog = covered.
    fn percent(&self) -> f64 {
        let total = self.implemented + self.missing.len();
        if total == 0 {
            return 100.0;
        }
        let tested = u32::try_from(self.tested()).unwrap_or(u32::MAX);
        let total = u32::try_from(total).unwrap_or(u32::MAX);
        f64::from(tested) * 100.0 / f64::from(total)
    }
}

fn coverage_language(name: &'static str, language_id: &str) -> Result<LanguageCoverage> {
    let source_dir = coverage_source_dir(name)
        .with_context(|| format!("no analyzer crate maps language {name}"))?;
    let mut production_literals = Vec::new();
    let mut test_literals = Vec::new();
    let sources = collect_rust_sources(Path::new(source_dir))?;
    for path in &sources {
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read analyzer source {}", path.display()))?;
        let (production, tests) = partition_rust_source(path, &source)?;
        production_literals.extend(production);
        test_literals.extend(tests);
    }
    if sources.is_empty() {
        return Err(anyhow::anyhow!(
            "no Rust sources under analyzer directory {source_dir}"
        ));
    }
    let keys = coverage_keys(name, language_id)?;
    let boundaries = infra_boundaries()?;
    // Infra classification takes precedence over marker matching: a key that
    // only appears in a documented skip note must not count as implemented.
    let (infra_keys, actionable_keys): (Vec<_>, Vec<_>) = keys.iter().partition(|key| {
        boundaries
            .get(key.as_str())
            .is_some_and(|boundary| boundary.implementation_gap)
    });
    let infra = infra_keys.into_iter().cloned().collect::<Vec<_>>();
    let actionable: Vec<String> = actionable_keys.into_iter().cloned().collect();
    let missing = missing_rules(&actionable, &production_literals, false);
    let missing_set = missing.iter().map(String::as_str).collect::<HashSet<_>>();
    let implemented_keys = actionable
        .iter()
        .filter(|key| !missing_set.contains(key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let untested = missing_rules(&implemented_keys, &test_literals, true);
    let implemented = actionable.len() - missing.len();
    Ok(LanguageCoverage {
        name,
        implemented,
        missing,
        untested,
        infra,
    })
}

/// Separates compiled and test-only Rust tokens. Files reached only through a
/// `tests` or `test_support` module are classified as tests by path; inline
/// `#[cfg(test)]` items are removed from otherwise compiled files.
fn partition_rust_source(path: &Path, source: &str) -> Result<(Vec<String>, Vec<String>)> {
    let parsed = syn::parse_file(source)
        .with_context(|| format!("failed to parse analyzer source {}", path.display()))?;
    let mut collector = PartitionedStringLiteralCollector {
        in_test: is_test_source_path(path),
        ..PartitionedStringLiteralCollector::default()
    };
    for item in &parsed.items {
        collector.visit_item(item);
    }
    Ok((collector.production, collector.tests))
}

#[derive(Default)]
struct PartitionedStringLiteralCollector {
    production: Vec<String>,
    tests: Vec<String>,
    in_test: bool,
}

impl PartitionedStringLiteralCollector {
    fn values(&mut self) -> &mut Vec<String> {
        if self.in_test {
            &mut self.tests
        } else {
            &mut self.production
        }
    }
}

impl<'ast> visit::Visit<'ast> for PartitionedStringLiteralCollector {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let previous = self.in_test;
        self.in_test |= item_requires_test(item);
        visit::visit_item(self, item);
        self.in_test = previous;
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.values().push(literal.value());
    }

    fn visit_attribute(&mut self, _attribute: &'ast syn::Attribute) {
        // Doc comments become `#[doc = "..."]` after parsing. No attribute is
        // executable rule evidence, so do not traverse attribute token values.
    }

    fn visit_macro(&mut self, item_macro: &'ast syn::Macro) {
        collect_token_literals(item_macro.tokens.clone(), self.values());
    }
}

fn collect_token_literals(tokens: proc_macro2::TokenStream, values: &mut Vec<String>) {
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Group(group) => collect_token_literals(group.stream(), values),
            proc_macro2::TokenTree::Literal(literal) => {
                if let Ok(literal) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                    values.push(literal.value());
                }
            }
            proc_macro2::TokenTree::Ident(_) | proc_macro2::TokenTree::Punct(_) => {}
        }
    }
}

fn is_test_source_path(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "tests")
        || path
            .file_stem()
            .is_some_and(|stem| stem == "tests" || stem == "test_support")
}

fn item_requires_test(item: &syn::Item) -> bool {
    item_attrs(item).iter().any(attribute_requires_test)
}

fn attribute_requires_test(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("cfg")
        && attribute
            .parse_args::<syn::Meta>()
            .is_ok_and(|meta| !cfg_can_be_true_without_test(&meta))
}

fn cfg_can_be_true_without_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => !path.is_ident("test"),
        syn::Meta::NameValue(_) => true,
        syn::Meta::List(list) => {
            let Ok(nested) =
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
            else {
                return true;
            };
            if list.path.is_ident("all") {
                nested.iter().all(cfg_can_be_true_without_test)
            } else if list.path.is_ident("any") {
                nested.iter().any(cfg_can_be_true_without_test)
            } else if list.path.is_ident("not") && nested.len() == 1 {
                cfg_can_be_false_without_test(&nested[0])
            } else {
                true
            }
        }
    }
}

fn cfg_can_be_false_without_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(_) | syn::Meta::NameValue(_) => true,
        syn::Meta::List(list) => {
            let Ok(nested) =
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
            else {
                return true;
            };
            if list.path.is_ident("all") {
                nested.iter().any(cfg_can_be_false_without_test)
            } else if list.path.is_ident("any") {
                nested.iter().all(cfg_can_be_false_without_test)
            } else if list.path.is_ident("not") && nested.len() == 1 {
                cfg_can_be_true_without_test(&nested[0])
            } else {
                true
            }
        }
    }
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

/// Loads the single source of truth for implementation and oracle boundaries.
fn infra_boundaries() -> Result<BTreeMap<String, InfraBoundary>> {
    let manifest: InfraBoundaryManifest = serde_json::from_str(INFRA_BOUNDARIES_JSON)
        .context("failed to parse catalog/infra-boundaries.json")?;
    ensure!(
        manifest.schema_version == 1,
        "infra boundary schema_version must be 1"
    );
    ensure!(
        !manifest.boundaries.is_empty(),
        "infra boundary manifest must not be empty"
    );
    for (key, boundary) in &manifest.boundaries {
        ensure!(!key.is_empty(), "infra boundary key must not be empty");
        ensure!(
            !boundary.reason.trim().is_empty(),
            "infra boundary {key} reason must not be empty"
        );
    }
    Ok(manifest.boundaries)
}

/// Iteratively collects `*.rs` paths without following symbolic links.
fn collect_rust_sources(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![dir.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).with_context(|| {
            format!("failed to read analyzer directory {}", directory.display())
        })?;
        for entry in entries {
            let entry = entry
                .with_context(|| format!("failed to read entry under {}", directory.display()))?;
            let file_type = entry
                .file_type()
                .with_context(|| format!("failed to inspect {}", entry.path().display()))?;
            let path = entry.path();
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    Ok(sources)
}

/// Analyzer crate source tree scanned for rule markers, by catalog name.
///
/// `javascript` and `typescript` share the single `hoonarqube-jsts` crate.
fn coverage_source_dir(name: &str) -> Option<&'static str> {
    match name {
        "csharp" => Some("crates/hoonarqube-csharp/src"),
        "javascript" | "typescript" => Some("crates/hoonarqube-jsts/src"),
        "python" => Some("crates/hoonarqube-python/src"),
        "go" => Some("crates/hoonarqube-go/src"),
        "rust" => Some("crates/hoonarqube-rust/src"),
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
fn missing_rules(keys: &[String], literals: &[String], qualified: bool) -> Vec<String> {
    let exact = literals.iter().map(String::as_str).collect::<HashSet<_>>();
    let dynamic = literals
        .iter()
        .filter_map(|literal| dynamic_rule_marker(literal))
        .collect::<HashSet<_>>();
    keys.iter()
        .map(String::as_str)
        .filter(|key| {
            if qualified {
                !exact.contains(key)
            } else {
                let marker = rule_key_marker(key);
                !exact.contains(key) && !exact.contains(marker) && !dynamic.contains(marker)
            }
        })
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

fn dynamic_rule_marker(literal: &str) -> Option<&str> {
    let (prefix, marker) = literal.rsplit_once(':')?;
    (prefix.contains('{') && prefix.contains('}') && !marker.is_empty()).then_some(marker)
}

fn print_coverage(rows: &[LanguageCoverage]) {
    println!("language      implemented  tested  missing  untested  infra  total  coverage");
    for row in rows {
        println!(
            "{:<12} {:>11} {:>7} {:>7} {:>9} {:>5} {:>6} {:>8.1}%",
            row.name,
            row.implemented,
            row.tested(),
            row.missing.len(),
            row.untested.len(),
            row.infra.len(),
            row.total(),
            row.percent(),
        );
    }
    for row in rows {
        if row.missing.is_empty() && row.untested.is_empty() && row.infra.is_empty() {
            continue;
        }
        println!("\n{}:", row.name);
        for key in &row.missing {
            println!("  {key} (implementation missing)");
        }
        for key in &row.untested {
            println!("  {key} (test evidence missing)");
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
        classification: COMMUNITY_CLASSIFICATION.to_owned(),
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
        classification: COMMUNITY_CLASSIFICATION.to_owned(),
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
    repository: &str,
    page_size: u64,
) -> Result<()> {
    ensure!(
        receipt.language == language && receipt.repository == repository,
        "language receipt mismatch"
    );
    ensure!(
        is_sha256(&receipt.query_sha256)
            && is_sha256(&receipt.pages_sha256)
            && is_sha256(&receipt.keys_sha256)
            && is_sha256(&receipt.shows_sha256),
        "language receipt provenance is incomplete"
    );
    ensure!(
        counts_match(receipt.total, receipt.unique_keys),
        "unique key closure mismatch"
    );
    ensure!(
        counts_match(receipt.total, receipt.show_count),
        "show closure mismatch"
    );
    let expected_pages = if receipt.total == 0 {
        1
    } else {
        receipt.total.div_ceil(page_size)
    };
    ensure!(
        counts_match(expected_pages, receipt.page_count),
        "page closure mismatch"
    );

    let language_dir = capture.join("rules").join(language_name);
    let keys = validate_capture_index(&language_dir, receipt)?;

    let mut pages_hasher = Sha256::new();
    let mut page_keys = BTreeSet::new();
    for page in 1..=receipt.page_count {
        let bytes = read(language_dir.join(format!("page-{page:04}.json")))?;
        let value: Value =
            serde_json::from_slice(&bytes).context("captured rule page is invalid")?;
        validate_captured_rule_page(
            &value,
            page,
            page_size,
            receipt,
            page_keys.len(),
            &mut page_keys,
        )?;
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
    ensure!(
        page_keys.iter().eq(keys.iter()),
        "captured page keys differ from keys.json"
    );

    validate_captured_shows(&language_dir, receipt, &keys)
}

fn validate_capture_index(
    language_dir: &Path,
    receipt: &RawLanguageReceipt,
) -> Result<Vec<String>> {
    let query_bytes = read(language_dir.join("query.json"))?;
    ensure!(
        sha256(&query_bytes) == receipt.query_sha256,
        "query hash mismatch"
    );
    let query: Value = serde_json::from_slice(&query_bytes).context("query.json is invalid")?;
    let query = query.as_object().context("query.json must be an object")?;
    ensure!(
        query.len() == 4
            && query.get("include_external").and_then(Value::as_bool) == Some(false)
            && query.get("is_template").and_then(Value::as_bool) == Some(false)
            && query.get("languages").and_then(Value::as_str) == Some(receipt.language.as_str())
            && query.get("repositories").and_then(Value::as_str)
                == Some(receipt.repository.as_str()),
        "captured query does not match language receipt"
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
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("rule key is not a string")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        counts_match(receipt.total, keys.len()),
        "keys count mismatch"
    );
    ensure!(
        keys.windows(2).all(|pair| pair[0] < pair[1]),
        "keys.json is not strictly sorted"
    );
    Ok(keys)
}

fn validate_captured_shows(
    language_dir: &Path,
    receipt: &RawLanguageReceipt,
    keys: &[String],
) -> Result<()> {
    let shows_dir = language_dir.join("show");
    let mut shows_hasher = Sha256::new();
    for (ordinal, key) in keys.iter().enumerate() {
        let bytes = read(shows_dir.join(format!("{ordinal:04}.json")))?;
        let value: Value =
            serde_json::from_slice(&bytes).context("captured rule show is invalid")?;
        ensure!(
            value
                .get("rule")
                .and_then(|rule| rule.get("key"))
                .and_then(Value::as_str)
                == Some(key.as_str()),
            "captured rule show key mismatch"
        );
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

fn validate_captured_rule_page(
    value: &Value,
    page: usize,
    page_size: u64,
    receipt: &RawLanguageReceipt,
    prior_keys: usize,
    keys: &mut BTreeSet<String>,
) -> Result<()> {
    let paging = value
        .get("paging")
        .context("captured rule page lacks paging")?;
    ensure!(
        paging.get("pageIndex").and_then(Value::as_u64) == u64::try_from(page).ok(),
        "captured rule page index mismatch"
    );
    ensure!(
        paging.get("pageSize").and_then(Value::as_u64) == Some(page_size),
        "captured rule page size mismatch"
    );
    ensure!(
        paging.get("total").and_then(Value::as_u64) == Some(receipt.total),
        "captured rule page total mismatch"
    );
    let rules = value
        .get("rules")
        .and_then(Value::as_array)
        .context("captured rule page lacks rules array")?;
    let prior_keys = u64::try_from(prior_keys).context("captured key count does not fit u64")?;
    let expected = receipt
        .total
        .checked_sub(prior_keys)
        .context("captured pages exceed receipt total")?
        .min(page_size);
    ensure!(
        counts_match(expected, rules.len()),
        "captured rule page length mismatch"
    );
    for rule in rules {
        let key = rule
            .get("key")
            .and_then(Value::as_str)
            .context("captured rule page record lacks key")?;
        ensure!(
            key.strip_prefix(&receipt.repository)
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|marker| !marker.is_empty()),
            "captured rule page key has wrong repository"
        );
        ensure!(keys.insert(key.to_owned()), "duplicate captured rule key");
    }
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
    ensure!(
        manifest.endpoints.len() == REQUIRED_ENDPOINTS.len()
            && REQUIRED_ENDPOINTS
                .iter()
                .all(|endpoint| manifest.endpoints.contains_key(*endpoint)),
        "raw capture endpoint scope mismatch"
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
    ] {
        let receipt = manifest
            .endpoints
            .get(endpoint)
            .with_context(|| format!("raw capture lacks endpoint receipt {endpoint}"))?;
        ensure!(
            (200..300).contains(&receipt.status),
            "raw capture endpoint {endpoint} was not successful"
        );
        ensure!(
            receipt.bytes > 0 && is_sha256(&receipt.sha256),
            "raw capture endpoint {endpoint} provenance is incomplete"
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

fn write_generated_file(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    match fs::read(path) {
        Ok(existing) if existing == bytes => Ok(()),
        Ok(_) if replace => write_atomic_replace(path, bytes),
        Ok(_) => bail!("refusing conflicting generated file {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_atomic_same(path, bytes)
        }
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn write_atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(
        path.is_file(),
        "replace target {} is not a file",
        path.display()
    );
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
        // Identifiers and comments are not executable evidence.
        let literals = vec!["S1523".to_owned()];
        assert_eq!(
            missing_rules(&keys, &literals, false),
            vec!["javascript:S100", "javascript:S122"]
        );
    }

    #[test]
    fn missing_rules_rejects_longer_rule_id_collisions() {
        // `python:S112` must stay missing even though `python:S1128`'s
        // marker occurs: digit-suffixed ids otherwise satisfy shorter ones.
        let keys = vec!["python:S112".to_owned(), "python:S1128".to_owned()];
        let literals = vec!["python:S1128".to_owned()];
        assert_eq!(missing_rules(&keys, &literals, false), vec!["python:S112"]);
    }

    #[test]
    fn qualified_test_markers_do_not_cross_language_repositories() {
        let keys = vec!["javascript:S112".to_owned(), "typescript:S112".to_owned()];
        let literals = vec!["javascript:S112".to_owned()];
        assert_eq!(
            missing_rules(&keys, &literals, true),
            vec!["typescript:S112"]
        );
    }

    #[test]
    fn dynamic_repository_prefix_counts_as_shared_implementation() {
        let keys = vec!["javascript:S103".to_owned(), "typescript:S103".to_owned()];
        let literals = vec!["{}:S103".to_owned()];
        assert!(missing_rules(&keys, &literals, false).is_empty());
    }

    #[test]
    fn rust_partition_excludes_comments_and_cfg_test_items_from_production() {
        let source = r#"
            //! python:S100 is only documentation.
            #[doc = "python:S101 is also documentation"]
            const RULE: &str = "python:S112";
            fn dynamic_key() { let _ = format!("{}:S103", "python"); }
            #[cfg(test)]
            mod tests {
                const TESTED: &str = "python:S112";
                #[test]
                fn macro_literal() { assert_eq!("python:S103", "python:S103"); }
            }
        "#;
        let (production, tests) = partition_rust_source(Path::new("rule.rs"), source).unwrap();
        assert_eq!(production, vec!["python:S112", "{}:S103", "python"]);
        assert_eq!(tests, vec!["python:S112", "python:S103", "python:S103"]);
    }

    #[test]
    fn rust_partition_tracks_nested_and_composed_test_cfgs() {
        let source = r#"
            mod outer {
                const PROD: &str = "python:S100";
                #[cfg(all(test, unix))]
                mod unix_tests { const TEST: &str = "python:S101"; }
                #[cfg(not(not(test)))]
                const ALSO_TEST: &str = "python:S102";
                #[cfg(any(test, feature = "special"))]
                const OPTIONAL_PROD: &str = "python:S103";
            }
        "#;
        let (production, tests) = partition_rust_source(Path::new("rule.rs"), source).unwrap();
        assert!(production.contains(&"python:S100".to_owned()));
        assert!(production.contains(&"python:S103".to_owned()));
        assert!(!production.contains(&"python:S101".to_owned()));
        assert!(!production.contains(&"python:S102".to_owned()));
        assert!(tests.contains(&"python:S101".to_owned()));
        assert!(tests.contains(&"python:S102".to_owned()));
    }

    #[test]
    fn raw_receipts_reject_unknown_fields() {
        let value = serde_json::json!({
            "status": 200,
            "bytes": 1,
            "sha256": "0".repeat(64),
            "unexpected": true,
        });
        assert!(serde_json::from_value::<RawResponseReceipt>(value).is_err());
    }

    #[test]
    fn captured_pages_enforce_lengths_and_repository_identity() {
        let receipt = RawLanguageReceipt {
            language: "py".to_owned(),
            repository: "python".to_owned(),
            query_sha256: "0".repeat(64),
            total: 2,
            unique_keys: 2,
            page_count: 1,
            pages_sha256: "0".repeat(64),
            keys_sha256: "0".repeat(64),
            show_count: 2,
            shows_sha256: "0".repeat(64),
        };
        let valid = serde_json::json!({
            "paging": {"pageIndex": 1, "pageSize": 2, "total": 2},
            "rules": [{"key": "python:S100"}, {"key": "python:S101"}],
        });
        let mut keys = BTreeSet::new();
        validate_captured_rule_page(&valid, 1, 2, &receipt, 0, &mut keys).unwrap();
        assert_eq!(keys.len(), 2);

        let short = serde_json::json!({
            "paging": {"pageIndex": 1, "pageSize": 2, "total": 2},
            "rules": [{"key": "python:S100"}],
        });
        assert!(
            validate_captured_rule_page(&short, 1, 2, &receipt, 0, &mut BTreeSet::new()).is_err()
        );

        let wrong_repository = serde_json::json!({
            "paging": {"pageIndex": 1, "pageSize": 2, "total": 2},
            "rules": [{"key": "python:S100"}, {"key": "other:S101"}],
        });
        assert!(
            validate_captured_rule_page(
                &wrong_repository,
                1,
                2,
                &receipt,
                0,
                &mut BTreeSet::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn generated_merge_files_replace_only_when_authorized() {
        let directory = std::env::temp_dir().join(format!(
            "hoonarqube-xtask-generated-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("rules.json");
        write_generated_file(&path, b"first", false).unwrap();
        assert!(write_generated_file(&path, b"second", false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        write_generated_file(&path, b"second", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn catalog_directory_publication_replaces_the_complete_tree() {
        let root = std::env::temp_dir().join(format!(
            "hoonarqube-xtask-catalog-publish-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let output = root.join("catalog");
        let staging = root.join("staging");
        fs::create_dir_all(output.join("rules")).unwrap();
        fs::write(output.join("obsolete.json"), b"old").unwrap();
        fs::write(output.join("rules/python.json"), b"old-python").unwrap();
        fs::create_dir_all(staging.join("rules")).unwrap();
        fs::write(staging.join("snapshot.toml"), b"new-snapshot").unwrap();
        fs::write(staging.join("rules/python.json"), b"new-python").unwrap();

        publish_catalog_directory(&output, &staging, true).unwrap();

        assert!(!output.join("obsolete.json").exists());
        assert_eq!(
            fs::read(output.join("snapshot.toml")).unwrap(),
            b"new-snapshot"
        );
        assert_eq!(
            fs::read(output.join("rules/python.json")).unwrap(),
            b"new-python"
        );
        assert!(!staging.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_directory_publication_rolls_back_a_failed_swap() {
        let root = std::env::temp_dir().join(format!(
            "hoonarqube-xtask-catalog-rollback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let output = root.join("catalog");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("snapshot.toml"), b"original").unwrap();

        let error = publish_catalog_directory(&output, &root.join("missing"), true).unwrap_err();

        assert!(error.to_string().contains("rolled back"));
        assert_eq!(fs::read(output.join("snapshot.toml")).unwrap(), b"original");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_coverage_treats_infra_and_missing_tests_as_gaps() {
        let infra = LanguageCoverage {
            name: "python",
            implemented: 0,
            missing: Vec::new(),
            untested: Vec::new(),
            infra: vec!["python:S6786".to_owned()],
        };
        let untested = LanguageCoverage {
            name: "python",
            implemented: 1,
            missing: Vec::new(),
            untested: vec!["python:S112".to_owned()],
            infra: Vec::new(),
        };
        assert!(infra.has_gaps(false));
        assert!(!infra.has_gaps(true));
        assert!(untested.has_gaps(false));
        assert!(untested.has_gaps(true));
    }

    #[test]
    fn infrastructure_boundaries_have_exact_implementation_gap_count() {
        let boundaries = infra_boundaries().unwrap();
        assert_eq!(boundaries.len(), 52);
        assert_eq!(
            boundaries
                .values()
                .filter(|boundary| boundary.implementation_gap)
                .count(),
            17
        );
        assert!(
            boundaries
                .get("python:S6786")
                .is_some_and(|boundary| boundary.implementation_gap)
        );
    }

    #[test]
    fn every_catalog_language_maps_to_analyzer_source() {
        for (name, _, _) in LANGUAGES {
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
            untested: Vec::new(),
            infra: Vec::new(),
        };
        assert!((row.percent() - 100.0).abs() < 1e-9);
        assert!(!row.has_gaps(false));
    }
}
