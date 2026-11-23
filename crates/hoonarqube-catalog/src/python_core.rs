//! Frozen Python activation facts from Community 26.11's Sonar way core.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::Catalog;

/// The pinned profile name accepted by the scanner.
pub const PROFILE_NAME: &str = "community-26.11-python-core";
const SNAPSHOT: &str = include_str!("../../../catalog/reference/python-core-community-26.11.json");

/// Activation facts; catalog presence does not establish an executable detector.
#[derive(Deserialize)]
pub struct PythonCoreSelection {
    schema_version: u32,
    pub version: String,
    pub active_keys: Vec<String>,
    parameters: BTreeMap<String, BTreeMap<String, String>>,
}

/// Effective parameters supported by the native S905 detector.
pub struct S905Parameters<'a> {
    pub report_on_strings: bool,
    pub ignored_operators: &'a str,
}

impl PythonCoreSelection {
    /// Reads the immutable release-scoped activation snapshot.
    ///
    /// # Panics
    /// Panics if the embedded data violates its version or ordering contract.
    pub fn embedded() -> &'static Self {
        static SELECTION: OnceLock<PythonCoreSelection> = OnceLock::new();
        SELECTION.get_or_init(|| {
            let selection: Self =
                serde_json::from_str(SNAPSHOT).expect("valid Python Core snapshot");
            assert_eq!(selection.schema_version, 1);
            assert_eq!(selection.active_keys.len(), 232);
            assert!(
                selection
                    .active_keys
                    .iter()
                    .all(|key| key.starts_with("python:"))
            );
            assert!(
                selection
                    .active_keys
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            );
            assert!(selection.parameters.iter().all(|(key, params)| {
                !params.is_empty() && selection.active_keys.binary_search(key).is_ok()
            }));
            selection
        })
    }

    /// Includes known activated keys with no unmapped profile parameters.
    #[must_use]
    pub fn selects(&self, key: &str, catalog: &Catalog) -> bool {
        self.active_keys
            .binary_search_by(|value| value.as_str().cmp(key))
            .is_ok()
            && !self.has_unmapped_parameters(key)
            && catalog.rule(key).is_some()
    }

    /// Reads the entire S905 parameter set. Unrecognized sets remain excluded.
    #[must_use]
    pub fn s905_parameters(&self) -> Option<S905Parameters<'_>> {
        let params = self.parameters.get("python:S905")?;
        if params.len() != 2 {
            return None;
        }
        Some(S905Parameters {
            report_on_strings: params.get("reportOnStrings")?.parse().ok()?,
            ignored_operators: params.get("ignoredOperators")?,
        })
    }

    fn has_unmapped_parameters(&self, key: &str) -> bool {
        self.parameters.contains_key(key)
            && (key != "python:S905" || self.s905_parameters().is_none())
    }

    /// Lists activated keys excluded because their parameters aren't mapped.
    pub fn unmapped_parameter_keys(&self) -> impl Iterator<Item = &String> {
        self.parameters
            .keys()
            .filter(|key| self.has_unmapped_parameters(key))
    }

    /// Digest of the activation snapshot, including its effective parameters.
    #[must_use]
    pub fn digest() -> &'static str {
        static DIGEST: OnceLock<String> = OnceLock::new();
        DIGEST.get_or_init(|| format!("{:x}", Sha256::digest(SNAPSHOT)))
    }
}
