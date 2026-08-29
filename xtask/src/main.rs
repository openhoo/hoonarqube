mod catalog;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use rayon::prelude::*;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::{Host, Url};

use crate::catalog::{canonical_json, hash_record, same_server_version, sha256};

const LANGUAGE_QUERIES: [LanguageQuery; 6] = [
    LanguageQuery {
        name: "csharp",
        language: "cs",
        repository: "csharpsquid",
    },
    LanguageQuery {
        name: "javascript",
        language: "js",
        repository: "javascript",
    },
    LanguageQuery {
        name: "typescript",
        language: "ts",
        repository: "typescript",
    },
    LanguageQuery {
        name: "python",
        language: "py",
        repository: "python",
    },
    LanguageQuery {
        name: "go",
        language: "go",
        repository: "go",
    },
    LanguageQuery {
        name: "rust",
        language: "rust",
        repository: "rust",
    },
];

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Hoonarqube repository tasks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Legally gated catalog acquisition. Writes raw Results Data only below .oracle/.
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
}

#[derive(Subcommand)]
enum CatalogCommand {
    /// Capture one dedicated `SonarQube` instance without modifying it.
    Capture {
        #[arg(long, default_value = ".oracle/approval.toml")]
        approval: PathBuf,
        #[arg(long, default_value = ".oracle/captures")]
        raw_dir: PathBuf,
        /// Capture only these catalog names; repeat for multiple languages.
        #[arg(long = "lang")]
        languages: Vec<String>,
        /// Capture an owned Community instance bound to loopback without external approval.
        #[arg(long)]
        local_community: bool,
    },
    /// Import factual fields from one raw Community capture.
    Import {
        #[arg(long)]
        capture: PathBuf,
        #[arg(long, default_value = "catalog/community-artifact-resolution.json")]
        community_resolution: PathBuf,
        #[arg(long, default_value = "catalog")]
        output: PathBuf,
        /// Merge a partial capture into the existing aggregate snapshot.
        #[arg(long)]
        merge: bool,
    },
    /// Verify committed catalog closure and deterministic hashes.
    Audit {
        #[arg(long, default_value = "catalog/snapshot.toml")]
        snapshot: PathBuf,
        #[arg(long)]
        require_pages_complete: bool,
    },
    /// Audit implemented-rule coverage of the analyzer crates against the frozen catalogs.
    Coverage {
        /// Restrict the audit to one catalog language (csharp, javascript, typescript, python).
        #[arg(long)]
        lang: Option<String>,
        /// Exit nonzero when any audited language has unimplemented rules.
        #[arg(long)]
        strict: bool,
        /// Permit rules explicitly classified as requiring out-of-repository infrastructure.
        #[arg(long, requires = "strict")]
        allow_infra: bool,
    },
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum InstanceClass {
    Community,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum ApprovedAction {
    CatalogCapture,
    ResultsDataHandling,
    Retention,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum PublicationControl {
    CounselReviewRequired,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    #[serde(rename = "approval_id")]
    id: String,
    dedicated_base_url: String,
    approved_actions: BTreeSet<ApprovedAction>,
    publication_control: PublicationControl,
}

#[derive(Clone, Copy)]
struct LanguageQuery {
    name: &'static str,
    language: &'static str,
    repository: &'static str,
}

#[derive(Debug, Serialize)]
struct CaptureManifest {
    schema_version: u16,
    captured_at_utc: String,
    approval_id: String,
    instance: InstanceClass,
    base_origin: String,
    server_version: String,
    page_size: u64,
    project_prefix: String,
    endpoints: BTreeMap<String, ResponseReceipt>,
    languages: BTreeMap<String, LanguageReceipt>,
    snapshot_sha256: String,
}

#[derive(Debug, Serialize)]
struct ResponseReceipt {
    status: u16,
    bytes: usize,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct LanguageReceipt {
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

struct OracleClient {
    client: Client,
    base: Url,
    token: String,
}

struct CapturedResponse {
    status: u16,
    body: Vec<u8>,
}

impl CapturedResponse {
    fn receipt(&self) -> ResponseReceipt {
        ResponseReceipt {
            status: self.status,
            bytes: self.body.len(),
            sha256: sha256(&self.body),
        }
    }

    fn require_success(&self, endpoint: &str) -> Result<()> {
        ensure!(
            (200..300).contains(&self.status),
            "SonarQube endpoint {endpoint} returned HTTP {}",
            self.status
        );
        Ok(())
    }

    fn json(&self, endpoint: &str) -> Result<Value> {
        serde_json::from_slice(&self.body)
            .with_context(|| format!("SonarQube endpoint {endpoint} did not return valid JSON"))
    }
}

impl OracleClient {
    fn new(base: Url, token: String) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let client = Client::builder()
            .default_headers(headers)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_mins(2))
            .build()
            .context("failed to build SonarQube HTTP client")?;
        Ok(Self {
            client,
            base,
            token,
        })
    }

    fn get(&self, endpoint: &str, query: &[(&str, String)]) -> Result<CapturedResponse> {
        let url = self
            .base
            .join(endpoint)
            .with_context(|| format!("invalid SonarQube endpoint path {endpoint}"))?;
        ensure!(
            same_origin(&self.base, &url),
            "refusing cross-origin request"
        );
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .query(query)
            .send()
            .with_context(|| format!("request to SonarQube endpoint {endpoint} failed"))?;
        capture_response(response, endpoint)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Catalog { command } => match command {
            CatalogCommand::Capture {
                approval,
                raw_dir,
                languages,
                local_community,
            } => capture_catalog(
                &approval,
                &raw_dir,
                InstanceClass::Community,
                &languages,
                local_community,
            ),
            CatalogCommand::Import {
                capture,
                community_resolution,
                output,
                merge,
            } => catalog::import(&capture, &community_resolution, &output, merge),
            CatalogCommand::Audit {
                snapshot,
                require_pages_complete,
            } => catalog::audit(&snapshot, require_pages_complete),
            CatalogCommand::Coverage {
                lang,
                strict,
                allow_infra,
            } => catalog::coverage(lang.as_deref(), strict, allow_infra),
        },
    }
}

fn capture_catalog(
    approval_path: &Path,
    raw_dir: &Path,
    instance: InstanceClass,
    language_names: &[String],
    local_community: bool,
) -> Result<()> {
    ensure_oracle_path(raw_dir)?;
    let environment_base =
        env::var("SONAR_HOST_URL").context("SONAR_HOST_URL is required for oracle capture")?;
    let environment_base = validate_base_url(&environment_base)?;
    let authorization_id = if local_community {
        ensure_loopback_origin(&environment_base)?;
        "local-community-loopback".to_owned()
    } else {
        ensure_oracle_path(approval_path)?;
        let approval = load_approval(approval_path)?;
        validate_approval(&approval)?;
        let configured_base = validate_base_url(&approval.dedicated_base_url)?;
        ensure!(
            same_origin(&configured_base, &environment_base),
            "SONAR_HOST_URL does not match the legally approved dedicated origin"
        );
        approval.id
    };
    let token = env::var("SONAR_TOKEN").context("SONAR_TOKEN is required for oracle capture")?;
    ensure!(!token.trim().is_empty(), "SONAR_TOKEN must not be empty");
    let queries = selected_language_queries(language_names)?;

    create_private_dir(raw_dir)?;
    let staging = raw_dir.join(format!(".capture-{}", std::process::id()));
    ensure!(!staging.exists(), "capture staging path already exists");
    create_private_dir(&staging)?;

    let result = capture_into(
        &staging,
        authorization_id,
        &environment_base,
        token,
        instance,
        &queries,
    );
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    let (manifest, manifest_bytes) = result?;
    let final_dir = raw_dir.join(format!(
        "{}-{}",
        "community",
        &manifest.snapshot_sha256[..16]
    ));
    if final_dir.exists() {
        let existing = fs::read(final_dir.join("manifest.json"))
            .context("existing capture lacks a readable manifest")?;
        ensure!(
            equivalent_manifests(&existing, &manifest_bytes)?,
            "capture identity collision"
        );
        fs::remove_dir_all(&staging).context("failed to remove duplicate staging capture")?;
    } else {
        fs::rename(&staging, &final_dir).context("failed to atomically publish raw capture")?;
    }
    println!("captured {}", final_dir.display());
    Ok(())
}

fn capture_into(
    staging: &Path,
    authorization_id: String,
    base: &Url,
    token: String,
    instance: InstanceClass,
    queries: &[LanguageQuery],
) -> Result<(CaptureManifest, Vec<u8>)> {
    let captured_at_utc = rfc3339_utc_now()?;
    let oracle = OracleClient::new(base.clone(), token)?;
    let mut endpoints = BTreeMap::new();
    let mut identity_hasher = Sha256::new();

    let server_version = oracle.get("api/server/version", &[])?;
    server_version.require_success("api/server/version")?;
    write_capture(staging, "server-version.txt", &server_version.body)?;
    record_response(
        &mut endpoints,
        &mut identity_hasher,
        "api/server/version",
        &server_version,
    );
    let server_version_text = String::from_utf8(server_version.body.clone())
        .context("api/server/version returned non-UTF-8 text")?
        .trim()
        .to_owned();
    ensure!(!server_version_text.is_empty(), "server version is empty");

    for (endpoint, file) in [
        ("api/system/status", "system-status.json"),
        ("api/plugins/installed", "plugins-installed.json"),
        ("api/webservices/list", "webservices-list.json"),
    ] {
        let response = oracle.get(endpoint, &[])?;
        response.require_success(endpoint)?;
        response.json(endpoint)?;
        write_capture(staging, file, &response.body)?;
        record_response(&mut endpoints, &mut identity_hasher, endpoint, &response);
    }

    let system_status: Value =
        serde_json::from_slice(&fs::read(staging.join("system-status.json"))?)?;
    ensure!(
        system_status
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty()),
        "api/system/status lacks instance identity"
    );
    ensure!(
        system_status.get("version").and_then(Value::as_str) == Some(server_version_text.as_str()),
        "system status belongs to a different server version"
    );

    capture_instance_evidence(
        &oracle,
        staging,
        &server_version_text,
        &mut endpoints,
        &mut identity_hasher,
    )?;

    let webservices_bytes = fs::read(staging.join("webservices-list.json"))?;
    let webservices: Value = serde_json::from_slice(&webservices_bytes)?;
    let page_size = documented_rule_page_size(&webservices)?;
    ensure!(page_size > 0, "documented rules page size must be positive");

    let mut languages = BTreeMap::new();
    for query in queries.iter().copied() {
        let receipt = capture_language(&oracle, staging, query, page_size, &mut identity_hasher)?;
        languages.insert(query.name.to_owned(), receipt);
    }

    let pre_snapshot = hex::encode(identity_hasher.finalize());
    let project_prefix = format!("hoonarqube-oracle-{}-", &pre_snapshot[..16]);
    let mut manifest = CaptureManifest {
        schema_version: 1,
        captured_at_utc,
        approval_id: authorization_id,
        instance,
        base_origin: origin_string(base),
        server_version: server_version_text,
        page_size,
        project_prefix,
        endpoints,
        languages,
        snapshot_sha256: String::new(),
    };
    manifest.snapshot_sha256 = manifest_identity(&manifest)?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    write_capture(staging, "manifest.json", &manifest_bytes)?;
    Ok((manifest, manifest_bytes))
}

fn capture_instance_evidence(
    oracle: &OracleClient,
    staging: &Path,
    server_version: &str,
    endpoints: &mut BTreeMap<String, ResponseReceipt>,
    identity_hasher: &mut Sha256,
) -> Result<()> {
    let navigation = oracle.get("api/navigation/global", &[])?;
    navigation.require_success("api/navigation/global")?;
    let navigation_json = navigation.json("api/navigation/global")?;
    let navigation_version = navigation_json
        .get("version")
        .and_then(Value::as_str)
        .context("api/navigation/global lacks version")?;
    ensure!(
        same_server_version(navigation_version, server_version),
        "edition evidence belongs to a different server build"
    );
    let edition = navigation_json
        .get("edition")
        .and_then(Value::as_str)
        .context("api/navigation/global lacks edition")?;
    ensure!(
        edition == "community",
        "catalog capture requires Community edition evidence"
    );
    write_capture(staging, "navigation-global.json", &navigation.body)?;
    record_response(
        endpoints,
        identity_hasher,
        "api/navigation/global",
        &navigation,
    );

    let instance_mode = oracle.get(
        "api/settings/values",
        &[("keys", "sonar.multi-quality-mode.enabled".to_owned())],
    )?;
    instance_mode.require_success("api/settings/values")?;
    let instance_mode_json = instance_mode.json("api/settings/values")?;
    let mode_value = instance_mode_json
        .get("settings")
        .and_then(Value::as_array)
        .and_then(|settings| {
            settings.iter().find(|setting| {
                setting.get("key").and_then(Value::as_str)
                    == Some("sonar.multi-quality-mode.enabled")
            })
        })
        .and_then(|setting| setting.get("value"))
        .and_then(Value::as_str)
        .context("api/settings/values lacks sonar.multi-quality-mode.enabled")?;
    ensure!(
        matches!(mode_value, "true" | "false"),
        "instance mode setting is not boolean"
    );
    write_capture(staging, "instance-mode.json", &instance_mode.body)?;
    record_response(
        endpoints,
        identity_hasher,
        "api/settings/values?keys=sonar.multi-quality-mode.enabled",
        &instance_mode,
    );

    Ok(())
}

fn capture_language(
    oracle: &OracleClient,
    staging: &Path,
    query: LanguageQuery,
    page_size: u64,
    identity_hasher: &mut Sha256,
) -> Result<LanguageReceipt> {
    let language_dir = staging.join("rules").join(query.name);
    create_private_dir(&language_dir)?;
    let query_value = json!({
        "include_external": false,
        "is_template": false,
        "languages": query.language,
        "repositories": query.repository,
    });
    let query_bytes = canonical_json(&query_value)?;
    let query_sha256 = sha256(&query_bytes);
    write_capture(&language_dir, "query.json", &query_bytes)?;

    let pages = capture_rule_pages(oracle, &language_dir, query, page_size, identity_hasher)?;

    let keys_value = Value::Array(pages.keys.iter().cloned().map(Value::String).collect());
    let keys_bytes = canonical_json(&keys_value)?;
    write_capture(&language_dir, "keys.json", &keys_bytes)?;
    let keys_sha256 = sha256(&keys_bytes);
    let shows_sha256 = capture_rule_shows(oracle, &language_dir, &pages.keys, identity_hasher)?;

    Ok(LanguageReceipt {
        language: query.language.to_owned(),
        repository: query.repository.to_owned(),
        query_sha256,
        total: pages.total,
        unique_keys: pages.keys.len(),
        page_count: pages.page_count,
        pages_sha256: pages.pages_sha256,
        keys_sha256,
        show_count: pages.keys.len(),
        shows_sha256,
    })
}

struct PageCapture {
    total: u64,
    keys: BTreeSet<String>,
    page_count: usize,
    pages_sha256: String,
}

fn capture_rule_pages(
    oracle: &OracleClient,
    language_dir: &Path,
    query: LanguageQuery,
    page_size: u64,
    identity_hasher: &mut Sha256,
) -> Result<PageCapture> {
    let mut page = 1_u64;
    let mut total = None;
    let mut keys = BTreeSet::new();
    let mut pages_hasher = Sha256::new();
    let mut page_count = 0_usize;
    loop {
        let params = vec![
            ("languages", query.language.to_owned()),
            ("repositories", query.repository.to_owned()),
            ("is_template", "false".to_owned()),
            ("include_external", "false".to_owned()),
            ("ps", page_size.to_string()),
            ("p", page.to_string()),
        ];
        let response = oracle.get("api/rules/search", &params)?;
        response.require_success("api/rules/search")?;
        let body = response.json("api/rules/search")?;
        let paging = body
            .get("paging")
            .context("rules search response lacks paging")?;
        let response_total = paging
            .get("total")
            .and_then(Value::as_u64)
            .context("rules search response lacks numeric paging.total")?;
        if let Some(expected) = total {
            ensure!(
                response_total == expected,
                "paging.total changed during capture"
            );
        } else {
            total = Some(response_total);
        }
        let response_page = paging
            .get("pageIndex")
            .and_then(Value::as_u64)
            .with_context(|| format!("rules search page {page} lacks numeric paging.pageIndex"))?;
        ensure!(
            response_page == page,
            "rules search returned wrong page index"
        );
        let rules = validate_search_page(&body, page_size, response_total, keys.len())?;
        for rule in rules {
            let key = rule
                .get("key")
                .and_then(Value::as_str)
                .context("rules search record lacks key")?;
            ensure!(
                key.strip_prefix(query.repository)
                    .and_then(|rest| rest.strip_prefix(':'))
                    .is_some_and(|marker| !marker.is_empty()),
                "rules search returned key outside requested repository"
            );
            ensure!(keys.insert(key.to_owned()), "duplicate rule key {key}");
        }
        let canonical = canonical_json(&body)?;
        write_capture(language_dir, &format!("page-{page:04}.json"), &canonical)?;
        hash_record(&mut pages_hasher, &canonical);
        hash_record(identity_hasher, &canonical);
        page_count += 1;

        if keys.len() as u64 >= total.unwrap_or(0) {
            break;
        }
        ensure!(
            !rules.is_empty(),
            "rules pagination ended before paging.total"
        );
        page += 1;
    }

    let total = total.unwrap_or(0);
    ensure!(
        keys.len() as u64 == total,
        "unique key count differs from paging.total"
    );
    let expected_pages = if total == 0 {
        1
    } else {
        total.div_ceil(page_size)
    };
    ensure!(
        page_count as u64 == expected_pages,
        "saved page count differs from documented pagination"
    );
    Ok(PageCapture {
        total,
        keys,
        page_count,
        pages_sha256: hex::encode(pages_hasher.finalize()),
    })
}

fn validate_search_page(
    body: &Value,
    page_size: u64,
    total: u64,
    prior_keys: usize,
) -> Result<&[Value]> {
    let paging = body
        .get("paging")
        .context("rules search response lacks paging")?;
    ensure!(
        paging.get("pageSize").and_then(Value::as_u64) == Some(page_size),
        "rules search returned wrong page size"
    );
    let rules = body
        .get("rules")
        .and_then(Value::as_array)
        .context("rules search response lacks rules array")?;
    let prior_keys = u64::try_from(prior_keys).context("captured rule count does not fit u64")?;
    let remaining = total
        .checked_sub(prior_keys)
        .context("rules search returned more records than paging.total")?;
    let expected = remaining.min(page_size);
    ensure!(
        u64::try_from(rules.len()).is_ok_and(|length| length == expected),
        "rules search page length differs from paging contract"
    );
    Ok(rules)
}

fn capture_rule_shows(
    oracle: &OracleClient,
    language_dir: &Path,
    keys: &BTreeSet<String>,
    identity_hasher: &mut Sha256,
) -> Result<String> {
    let shows_dir = language_dir.join("show");
    create_private_dir(&shows_dir)?;
    let keys: Vec<&String> = keys.iter().collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .thread_name(|index| format!("oracle-show-{index}"))
        .build()
        .context("failed to build bounded oracle capture pool")?;
    let captures: Result<Vec<Vec<u8>>> = pool.install(|| {
        keys.par_iter()
            .map(|key| {
                let response = oracle.get("api/rules/show", &[("key", (*key).clone())])?;
                response.require_success("api/rules/show")?;
                let value = response.json("api/rules/show")?;
                let returned_key = value
                    .get("rule")
                    .and_then(|rule| rule.get("key"))
                    .and_then(Value::as_str)
                    .context("rules show response lacks rule.key")?;
                ensure!(
                    returned_key == key.as_str(),
                    "rules show returned a different key"
                );
                canonical_json(&value)
            })
            .collect()
    });

    let mut shows_hasher = Sha256::new();
    for (ordinal, (key, canonical)) in keys.iter().zip(captures?).enumerate() {
        write_capture(&shows_dir, &format!("{ordinal:04}.json"), &canonical)?;
        hash_record(&mut shows_hasher, key.as_bytes());
        hash_record(&mut shows_hasher, &canonical);
        hash_record(identity_hasher, key.as_bytes());
        hash_record(identity_hasher, &canonical);
    }
    Ok(hex::encode(shows_hasher.finalize()))
}

fn capture_response(response: Response, endpoint: &str) -> Result<CapturedResponse> {
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .with_context(|| format!("failed to read SonarQube endpoint {endpoint}"))?
        .to_vec();
    Ok(CapturedResponse { status, body })
}

fn record_response(
    receipts: &mut BTreeMap<String, ResponseReceipt>,
    identity: &mut Sha256,
    endpoint: &str,
    response: &CapturedResponse,
) {
    hash_record(identity, endpoint.as_bytes());
    hash_record(identity, &response.body);
    receipts.insert(endpoint.to_owned(), response.receipt());
}

fn load_approval(path: &Path) -> Result<Approval> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("legal approval file {} is required", path.display()))?;
    toml::from_str(&content).context("legal approval file is invalid")
}

fn validate_approval(approval: &Approval) -> Result<()> {
    ensure!(
        !approval.id.trim().is_empty(),
        "approval_id must not be empty"
    );
    for required in [
        ApprovedAction::CatalogCapture,
        ApprovedAction::ResultsDataHandling,
        ApprovedAction::Retention,
    ] {
        ensure!(
            approval.approved_actions.contains(&required),
            "legal approval lacks required action {required:?}"
        );
    }
    ensure!(
        approval.publication_control == PublicationControl::CounselReviewRequired,
        "publication must remain subject to counsel review"
    );
    Ok(())
}

fn validate_base_url(input: &str) -> Result<Url> {
    let mut url = Url::parse(input).context("dedicated SonarQube base URL is invalid")?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "base URL must use HTTP or HTTPS"
    );
    ensure!(url.host_str().is_some(), "base URL must include a host");
    ensure!(
        url.username().is_empty(),
        "base URL must not contain credentials"
    );
    ensure!(
        url.password().is_none(),
        "base URL must not contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "base URL must not contain query or fragment"
    );
    ensure!(
        matches!(url.path(), "" | "/"),
        "base URL must be an origin without a path"
    );
    url.set_path("/");
    Ok(url)
}

fn ensure_loopback_origin(url: &Url) -> Result<()> {
    let is_loopback = match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    ensure!(
        is_loopback,
        "--local-community requires SONAR_HOST_URL on a loopback origin"
    );
    Ok(())
}

fn selected_language_queries(names: &[String]) -> Result<Vec<LanguageQuery>> {
    if names.is_empty() {
        return Ok(LANGUAGE_QUERIES.to_vec());
    }
    let mut selected = Vec::with_capacity(names.len());
    let mut seen = BTreeSet::new();
    for name in names {
        ensure!(seen.insert(name.as_str()), "duplicate language {name}");
        let query = LANGUAGE_QUERIES
            .iter()
            .find(|query| query.name == name)
            .with_context(|| {
                format!(
                    "unknown language {name}; expected one of {}",
                    LANGUAGE_QUERIES
                        .iter()
                        .map(|query| query.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        selected.push(*query);
    }
    selected.sort_by_key(|query| query.name);
    Ok(selected)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn origin_string(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

fn ensure_oracle_path(path: &Path) -> Result<()> {
    ensure!(
        !path
            .components()
            .any(|component| matches!(component, Component::ParentDir)),
        "oracle paths must not contain parent components"
    );
    let current_dir = env::current_dir()?.canonicalize()?;
    let oracle_root = current_dir.join(".oracle");
    let canonical_oracle_root = oracle_root.canonicalize().context(
        "legal approval directory .oracle/ is required and must not be a broken symbolic link",
    )?;
    ensure!(
        canonical_oracle_root.starts_with(&current_dir),
        ".oracle/ must resolve inside the repository"
    );
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir.join(path)
    };
    ensure!(
        absolute.starts_with(&oracle_root),
        "oracle inputs and raw Results Data must remain below .oracle/"
    );
    let existing_ancestor = absolute
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .context("oracle path has no existing ancestor")?;
    let canonical_ancestor = existing_ancestor
        .canonicalize()
        .context("failed to resolve oracle path ancestor")?;
    ensure!(
        canonical_ancestor.starts_with(&canonical_oracle_root),
        "oracle path resolves outside .oracle/"
    );
    Ok(())
}

fn documented_rule_page_size(webservices: &Value) -> Result<u64> {
    let services = webservices
        .get("webServices")
        .and_then(Value::as_array)
        .context("api/webservices/list lacks webServices")?;
    for service in services {
        if service.get("path").and_then(Value::as_str) != Some("api/rules") {
            continue;
        }
        let Some(actions) = service.get("actions").and_then(Value::as_array) else {
            continue;
        };
        for action in actions {
            if action.get("key").and_then(Value::as_str) != Some("search") {
                continue;
            }
            let Some(params) = action.get("params").and_then(Value::as_array) else {
                continue;
            };
            for parameter in params {
                if parameter.get("key").and_then(Value::as_str) == Some("ps")
                    && let Some(maximum) = parameter.get("maximumValue").and_then(Value::as_u64)
                {
                    return Ok(maximum);
                }
            }
        }
    }
    bail!("server Web API metadata does not document api/rules/search ps maximumValue")
}

fn manifest_identity(manifest: &CaptureManifest) -> Result<String> {
    let value = serde_json::to_value(manifest)?;
    let mut object = value
        .as_object()
        .cloned()
        .context("capture manifest must serialize as an object")?;
    object.remove("snapshot_sha256");
    object.remove("captured_at_utc");
    canonical_json(&Value::Object(object)).map(|bytes| sha256(&bytes))
}

fn equivalent_manifests(left: &[u8], right: &[u8]) -> Result<bool> {
    fn normalize(bytes: &[u8]) -> Result<Vec<u8>> {
        let value: Value = serde_json::from_slice(bytes).context("capture manifest is invalid")?;
        let mut object = value
            .as_object()
            .cloned()
            .context("capture manifest must be a JSON object")?;
        object.remove("captured_at_utc");
        canonical_json(&Value::Object(object))
    }

    Ok(normalize(left)? == normalize(right)?)
}

/// Formats an instant as an RFC 3339 UTC timestamp ending in `Z`.
fn format_rfc3339_utc(timestamp: OffsetDateTime) -> Result<String> {
    timestamp
        .format(&Rfc3339)
        .context("failed to format capture timestamp as RFC 3339")
}

fn rfc3339_utc_now() -> Result<String> {
    format_rfc3339_utc(OffsetDateTime::now_utc())
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    set_private_dir_permissions(path)
}

fn write_capture(directory: &Path, file: &str, bytes: &[u8]) -> Result<()> {
    create_private_dir(directory)?;
    let path = directory.join(file);
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options
        .open(&path)
        .with_context(|| format!("refusing to overwrite capture file {}", path.display()))?;
    output
        .write_all(bytes)
        .with_context(|| format!("failed to write capture file {}", path.display()))?;
    output.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to secure {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_server_documented_page_size() {
        let value = json!({
            "webServices": [{
                "path": "api/rules",
                "actions": [{
                    "key": "search",
                    "params": [{"key": "ps", "maximumValue": 500}]
                }]
            }]
        });
        assert_eq!(documented_rule_page_size(&value).unwrap(), 500);
    }

    #[test]
    fn search_pages_must_match_reported_page_size_and_remaining_total() {
        let valid = json!({
            "paging": {"pageIndex": 1, "pageSize": 2, "total": 3},
            "rules": [{"key": "python:S100"}, {"key": "python:S101"}],
        });
        assert_eq!(validate_search_page(&valid, 2, 3, 0).unwrap().len(), 2);

        let wrong_size = json!({
            "paging": {"pageIndex": 1, "pageSize": 1, "total": 3},
            "rules": [{"key": "python:S100"}, {"key": "python:S101"}],
        });
        assert!(validate_search_page(&wrong_size, 2, 3, 0).is_err());

        let truncated = json!({
            "paging": {"pageIndex": 1, "pageSize": 2, "total": 3},
            "rules": [{"key": "python:S100"}],
        });
        assert!(validate_search_page(&truncated, 2, 3, 0).is_err());

        let final_page = json!({
            "paging": {"pageIndex": 2, "pageSize": 2, "total": 3},
            "rules": [{"key": "python:S102"}],
        });
        assert_eq!(validate_search_page(&final_page, 2, 3, 2).unwrap().len(), 1);
    }

    #[test]
    fn canonical_json_sorts_nested_objects() {
        let first = json!({"z": {"b": 1, "a": 2}, "a": 0});
        let second = json!({"a": 0, "z": {"a": 2, "b": 1}});
        assert_eq!(
            canonical_json(&first).unwrap(),
            canonical_json(&second).unwrap()
        );
    }

    #[test]
    fn dedicated_origin_requires_scheme_host_and_port_match() {
        let approved = validate_base_url("https://sonar.example:9443").unwrap();
        let same = validate_base_url("https://sonar.example:9443/").unwrap();
        let other = validate_base_url("https://sonar.example").unwrap();
        assert!(same_origin(&approved, &same));
        assert!(!same_origin(&approved, &other));
    }

    #[test]
    fn local_capture_accepts_only_loopback_origins() {
        for origin in [
            "http://127.0.0.1:19002",
            "http://[::1]:19002",
            "https://localhost:9443",
        ] {
            let url = validate_base_url(origin).unwrap();
            ensure_loopback_origin(&url).unwrap();
        }
        let remote = validate_base_url("https://sonarqube.example.test").unwrap();
        assert!(ensure_loopback_origin(&remote).is_err());
    }

    #[test]
    fn language_selection_is_explicit_unique_and_canonical() {
        let names = vec!["rust".to_owned(), "go".to_owned()];
        let selected = selected_language_queries(&names).unwrap();
        assert_eq!(
            selected.iter().map(|query| query.name).collect::<Vec<_>>(),
            ["go", "rust"]
        );
        assert!(selected_language_queries(&["go".to_owned(), "go".to_owned()]).is_err());
        assert!(selected_language_queries(&["unknown".to_owned()]).is_err());
    }

    #[test]
    fn formats_rfc3339_utc_timestamp() {
        let instant = OffsetDateTime::from_unix_timestamp(1_234_567_890)
            .expect("timestamp must be representable");
        let formatted = format_rfc3339_utc(instant).unwrap();
        assert_eq!(formatted, "2009-02-13T23:31:30Z");
        assert!(!formatted.is_empty());
        assert!(formatted.ends_with('Z'));
    }

    #[test]
    fn manifest_identity_and_equivalence_ignore_capture_time() {
        let first =
            br#"{"captured_at_utc":"2026-08-22T10:00:00Z","snapshot_sha256":"same","value":1}"#;
        let second =
            br#"{"captured_at_utc":"2026-08-22T11:00:00Z","snapshot_sha256":"same","value":1}"#;
        assert!(equivalent_manifests(first, second).unwrap());
    }

    #[test]
    fn matches_equivalent_server_version_formats() {
        assert!(same_server_version(
            "2025.4.4.119049",
            "2025.4.4 (build 119049)"
        ));
        assert!(!same_server_version(
            "2025.4.4.119049",
            "2025.4.4 (build 119050)"
        ));
    }
}
