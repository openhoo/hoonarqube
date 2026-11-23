//! Frozen JavaScript activation facts from Community 26.11's Sonar way core.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::Catalog;

/// The pinned JavaScript profile name accepted by the scanner.
pub const PROFILE_NAME: &str = "community-26.11-javascript-core";
const SNAPSHOT: &str =
    include_str!("../../../catalog/reference/javascript-core-community-26.11.json");

/// Activation facts; catalog presence does not establish an executable detector.
#[derive(Deserialize)]
pub struct JavaScriptCoreSelection {
    schema_version: u32,
    pub version: String,
    pub active_keys: Vec<String>,
    pub parameters: BTreeMap<String, BTreeMap<String, String>>,
}

impl JavaScriptCoreSelection {
    /// Reads the immutable release-scoped activation snapshot.
    ///
    /// # Panics
    /// Panics if the embedded data violates its version or ordering contract.
    pub fn embedded() -> &'static Self {
        static SELECTION: OnceLock<JavaScriptCoreSelection> = OnceLock::new();
        SELECTION.get_or_init(|| {
            let selection: Self =
                serde_json::from_str(SNAPSHOT).expect("valid JavaScript Core snapshot");
            assert_eq!(selection.schema_version, 1);
            assert_eq!(selection.active_keys.len(), 200);
            assert!(
                selection
                    .active_keys
                    .iter()
                    .all(|key| key.starts_with("javascript:"))
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
            && !self.parameters.contains_key(key)
            && catalog.rule(key).is_some()
    }

    /// Digest of the activation snapshot, including its effective parameters.
    #[must_use]
    pub fn digest() -> &'static str {
        static DIGEST: OnceLock<String> = OnceLock::new();
        DIGEST.get_or_init(|| format!("{:x}", Sha256::digest(SNAPSHOT)))
    }
}
