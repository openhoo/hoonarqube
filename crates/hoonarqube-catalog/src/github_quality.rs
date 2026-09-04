//! Embedded definitions for GitHub `CodeQL`'s official Code Quality queries.
//!
//! This catalog contains definitions only.  A query is not considered implemented
//! merely because it is present here; every row starts with
//! [`ImplementationStatus::Unimplemented`].  Detector coverage belongs to a
//! separate, future registry.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const CATALOG_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../catalog/github-code-quality.json"
));

/// The `CodeQL` repository revision from which the embedded definitions were
/// captured.  Source links in every row are pinned to this revision.
pub const SOURCE_REVISION: &str = "cb55cf1f281101f8e6d1522998e821d1b3547ce4";
const SOURCE_PAGE_PREFIX: &str =
    "https://github.com/github/codeql/blob/cb55cf1f281101f8e6d1522998e821d1b3547ce4/";
const HELP_URL_PREFIX: &str = "https://codeql.github.com/codeql-query-help/";
const EXPECTED_TOTAL: usize = 382;

/// SHA-256 of the exact embedded GitHub Code Quality metadata bytes.
///
/// This digest is intentionally immutable: changing a fact requires an
/// explicit catalog refresh and a corresponding update to this contract.
pub const CATALOG_SHA256: &str = "b283df0d2073c093092a5021d04316fc676e549aab0e6e9df9f63945386c10fd";

/// Canonical language families represented by GitHub Code Quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LanguageFamily {
    #[serde(rename = "C#")]
    CSharp,
    Go,
    Java,
    #[serde(rename = "JavaScript/TypeScript")]
    JavaScriptTypeScript,
    Python,
    Ruby,
}

impl LanguageFamily {
    /// Language families in the catalog's deterministic order.
    pub const ALL: [Self; 6] = [
        Self::CSharp,
        Self::Go,
        Self::Java,
        Self::JavaScriptTypeScript,
        Self::Python,
        Self::Ruby,
    ];

    /// The exact language-family label used by the source catalog.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CSharp => "C#",
            Self::Go => "Go",
            Self::Java => "Java",
            Self::JavaScriptTypeScript => "JavaScript/TypeScript",
            Self::Python => "Python",
            Self::Ruby => "Ruby",
        }
    }

    const fn query_prefix(self) -> &'static str {
        match self {
            Self::CSharp => "cs",
            Self::Go => "go",
            Self::Java => "java",
            Self::JavaScriptTypeScript => "js",
            Self::Python => "py",
            Self::Ruby => "rb",
        }
    }
}

/// GitHub's Code Quality query categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Category {
    Maintainability,
    Reliability,
}

/// GitHub's Code Quality severities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Info,
    Recommendation,
    Warning,
}

/// Implementation/evidence state for a definition row.
///
/// The catalog intentionally has no implementation claims.  This explicit
/// state prevents metadata-only presence from being mistaken for detector
/// coverage when a future registry is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImplementationStatus {
    Unimplemented,
}

/// A complete, immutable definition from GitHub Code Quality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryDefinition {
    pub id: String,
    pub language: LanguageFamily,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub help_url: String,
    pub source_page: String,
    pub implementation_status: ImplementationStatus,
}

/// Compatibility alias for callers that refer to a definition's status as
/// evidence status.
pub type EvidenceStatus = ImplementationStatus;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddedCatalog {
    source_revision: String,
    queries: Vec<QueryDefinition>,
}

fn embedded() -> &'static Result<Box<[QueryDefinition]>, String> {
    static CATALOG: LazyLock<Result<Box<[QueryDefinition]>, String>> =
        LazyLock::new(|| parse_and_verify(CATALOG_JSON));
    &CATALOG
}

fn verified_queries() -> &'static [QueryDefinition] {
    match embedded() {
        Ok(queries) => queries,
        Err(error) => panic!("invalid embedded GitHub Code Quality catalog: {error}"),
    }
}

/// Verifies the embedded catalog's complete integrity contract.
///
/// # Errors
///
/// Returns an error when the embedded catalog fails an integrity check.
pub fn verify() -> Result<(), String> {
    parse_and_verify(CATALOG_JSON).map(|_| ())
}

/// Verifies caller-provided catalog JSON using the same integrity contract as
/// the embedded catalog.  This is useful for fixture tests and for rejecting
/// malformed metadata before it can be embedded.
///
/// # Errors
///
/// Returns an error when the supplied JSON fails parsing or an integrity check.
pub fn verify_json(json: &str) -> Result<(), String> {
    parse_and_verify(json).map(|_| ())
}

/// Iterates all official GitHub Code Quality definitions in stable order.
#[must_use]
pub fn queries() -> impl ExactSizeIterator<Item = &'static QueryDefinition> {
    verified_queries().iter()
}

/// Looks up an official definition by its exact `CodeQL` query ID.
#[must_use]
pub fn query(id: &str) -> Option<&'static QueryDefinition> {
    verified_queries()
        .iter()
        .find(|definition| definition.id == id)
}

/// Iterates definitions for one language family in stable ID order.
#[must_use]
pub fn queries_for_language(
    language: LanguageFamily,
) -> impl ExactSizeIterator<Item = &'static QueryDefinition> {
    let all = verified_queries();
    let start = all
        .iter()
        .position(|definition| definition.language == language)
        .unwrap_or(all.len());
    let end = all
        .iter()
        .enumerate()
        .skip(start)
        .find(|(_, definition)| definition.language != language)
        .map_or(all.len(), |(index, _)| index);
    all[start..end].iter()
}

fn parse_and_verify(json: &str) -> Result<Box<[QueryDefinition]>, String> {
    let catalog: EmbeddedCatalog = serde_json::from_str(json)
        .map_err(|error| format!("invalid GitHub Code Quality JSON: {error}"))?;
    let actual_digest = hex::encode(Sha256::digest(json.as_bytes()));
    if actual_digest != CATALOG_SHA256 {
        return Err(format!(
            "GitHub Code Quality catalog content digest mismatch: expected {CATALOG_SHA256}, got {actual_digest}"
        ));
    }

    verify_catalog_metadata(&catalog)?;
    verify_definitions(&catalog.queries)?;
    verify_language_counts(&catalog.queries)?;
    verify_query_order(&catalog.queries)?;

    Ok(catalog.queries.into_boxed_slice())
}

fn verify_catalog_metadata(catalog: &EmbeddedCatalog) -> Result<(), String> {
    if catalog.source_revision != SOURCE_REVISION {
        return Err(format!(
            "source_revision must be {SOURCE_REVISION}, got {:?}",
            catalog.source_revision
        ));
    }
    if catalog.queries.len() != EXPECTED_TOTAL {
        return Err(format!(
            "expected {EXPECTED_TOTAL} GitHub Code Quality queries, got {}",
            catalog.queries.len()
        ));
    }
    Ok(())
}

fn verify_definitions<'a>(queries: &'a [QueryDefinition]) -> Result<(), String> {
    let mut seen_ids: BTreeSet<&'a str> = BTreeSet::new();
    for (index, definition) in queries.iter().enumerate() {
        verify_definition(index, definition, &mut seen_ids)?;
    }
    Ok(())
}

fn verify_definition<'a>(
    index: usize,
    definition: &'a QueryDefinition,
    seen_ids: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    if definition.id.is_empty() {
        return Err(format!("query {index} has an empty ID"));
    }
    if !valid_id(definition.id.as_str(), definition.language) {
        return Err(format!(
            "query {} has invalid {} ID {:?}",
            index,
            definition.language.as_str(),
            definition.id
        ));
    }
    if !seen_ids.insert(definition.id.as_str()) {
        return Err(format!("duplicate query ID {:?}", definition.id));
    }
    if definition.title.trim().is_empty() {
        return Err(format!("query {:?} has an empty title", definition.id));
    }
    if !valid_help_url(definition.help_url.as_str()) {
        return Err(format!("query {:?} has an invalid help URL", definition.id));
    }
    if !valid_source_page(definition.source_page.as_str()) {
        return Err(format!(
            "query {:?} has an invalid source page",
            definition.id
        ));
    }
    if definition.implementation_status != ImplementationStatus::Unimplemented {
        return Err(format!(
            "query {:?} has an implementation claim in a definition catalog",
            definition.id
        ));
    }
    Ok(())
}

fn verify_language_counts(queries: &[QueryDefinition]) -> Result<(), String> {
    let mut counts = [0usize; 6];
    for definition in queries {
        counts[language_index(definition.language)] += 1;
    }
    let expected = [69, 22, 89, 98, 101, 3];
    if counts != expected {
        return Err(format!(
            "language counts must be C#/Go/Java/JS-TS/Python/Ruby = {expected:?}, got {counts:?}"
        ));
    }
    Ok(())
}

fn verify_query_order(queries: &[QueryDefinition]) -> Result<(), String> {
    if !queries.windows(2).all(|pair| {
        let left = (&pair[0].language, &pair[0].id);
        let right = (&pair[1].language, &pair[1].id);
        left < right
    }) {
        return Err("queries are not sorted by language family and ID".to_owned());
    }
    Ok(())
}

fn valid_id(id: &str, language: LanguageFamily) -> bool {
    let Some((prefix, remainder)) = id.split_once('/') else {
        return false;
    };
    !remainder.is_empty()
        && prefix == language.query_prefix()
        && id.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '/' | '-')
        })
}

fn valid_help_url(url: &str) -> bool {
    url.starts_with(HELP_URL_PREFIX) && url.ends_with('/') && !url.chars().any(char::is_whitespace)
}

fn valid_source_page(url: &str) -> bool {
    url.starts_with(SOURCE_PAGE_PREFIX)
        && url.strip_suffix(".ql").is_some()
        && !url.chars().any(char::is_whitespace)
}

const fn language_index(language: LanguageFamily) -> usize {
    match language {
        LanguageFamily::CSharp => 0,
        LanguageFamily::Go => 1,
        LanguageFamily::Java => 2,
        LanguageFamily::JavaScriptTypeScript => 3,
        LanguageFamily::Python => 4,
        LanguageFamily::Ruby => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_has_exact_counts() {
        verify().expect("the embedded catalog must satisfy its integrity contract");
        assert_eq!(queries().len(), EXPECTED_TOTAL);
        let counts: Vec<_> = LanguageFamily::ALL
            .into_iter()
            .map(|language| queries_for_language(language).len())
            .collect();
        assert_eq!(counts, [69, 22, 89, 98, 101, 3]);
    }

    #[test]
    fn all_ids_are_unique_and_lookup_is_exact() {
        let definitions: Vec<_> = queries().collect();
        let ids: BTreeSet<_> = definitions
            .iter()
            .map(|definition| &definition.id)
            .collect();
        assert_eq!(ids.len(), EXPECTED_TOTAL);
        for definition in definitions {
            assert_eq!(query(&definition.id), Some(definition));
        }
        assert!(query("cs/does-not-exist").is_none());
    }

    #[test]
    fn malformed_metadata_is_rejected() {
        let mut value: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).expect("fixture JSON must parse");

        value["queries"][0]["severity"] = serde_json::Value::String("Critical".to_owned());
        assert!(verify_json(&serde_json::to_string(&value).unwrap()).is_err());

        let mut value: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).expect("fixture JSON must parse");
        value["queries"][0]["source_page"] =
            serde_json::Value::String("https://github.com/github/codeql/blob/main/a.ql".to_owned());
        assert!(verify_json(&serde_json::to_string(&value).unwrap()).is_err());

        let mut value: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).expect("fixture JSON must parse");
        value["queries"][1]["id"] = value["queries"][0]["id"].clone();
        assert!(verify_json(&serde_json::to_string(&value).unwrap()).is_err());

        // A semantically valid fact mutation must still fail the immutable
        // content contract; schema checks alone are not sufficient.
        let mut value: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).expect("fixture JSON must parse");
        value["queries"][0]["title"] = serde_json::Value::String("Drifted title".to_owned());
        let error = verify_json(&serde_json::to_string(&value).unwrap()).unwrap_err();
        assert!(error.contains("content digest mismatch"));
    }
    #[test]
    fn language_family_views_reconstruct_global_catalog_order() {
        let mut partitioned = Vec::new();
        for family in LanguageFamily::ALL {
            let definitions: Vec<_> = queries_for_language(family).collect();
            assert!(
                definitions
                    .iter()
                    .all(|definition| definition.language == family)
            );
            partitioned.extend(
                definitions
                    .into_iter()
                    .map(|definition| definition.id.as_str()),
            );
        }

        let global: Vec<_> = queries().map(|definition| definition.id.as_str()).collect();
        assert_eq!(partitioned, global);
        assert_eq!(
            queries_for_language(LanguageFamily::JavaScriptTypeScript).len(),
            98
        );
    }

    #[test]
    fn malformed_json_is_reported_before_content_integrity() {
        let error = verify_json("{").expect_err("malformed JSON must be rejected");
        assert!(error.starts_with("invalid GitHub Code Quality JSON:"));
    }

    #[test]
    fn duplicate_and_cross_family_ids_are_rejected_by_definition_validation() {
        let mut catalog: EmbeddedCatalog =
            serde_json::from_str(CATALOG_JSON).expect("fixture JSON must parse");
        catalog.queries[1].id = catalog.queries[0].id.clone();
        let error = verify_definitions(&catalog.queries).expect_err("duplicate IDs must fail");
        assert!(error.contains("duplicate query ID"));

        let mut catalog: EmbeddedCatalog =
            serde_json::from_str(CATALOG_JSON).expect("fixture JSON must parse");
        catalog.queries[0].id = "go/not-a-csharp-query".to_owned();
        let error = verify_definitions(&catalog.queries).expect_err("cross-family IDs must fail");
        assert_eq!(error, "query 0 has invalid C# ID \"go/not-a-csharp-query\"");
    }
}
