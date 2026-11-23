//! Frozen activation facts for the JavaScript and TypeScript Community profiles.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::Catalog;

pub const JAVASCRIPT_PROFILE: &str = "community-26.11-javascript-core";
pub const TYPESCRIPT_PROFILE: &str = "community-26.11-typescript-core";

/// Each language has its own assigned profile, active keys, and effective parameters.
#[derive(Clone, Copy)]
pub enum ScriptCore {
    JavaScript,
    TypeScript,
}

impl ScriptCore {
    #[must_use]
    pub const fn profile_name(self) -> &'static str {
        match self {
            Self::JavaScript => JAVASCRIPT_PROFILE,
            Self::TypeScript => TYPESCRIPT_PROFILE,
        }
    }

    #[must_use]
    pub const fn language(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
        }
    }

    /// The active keys and effective parameters for this Community release.
    ///
    /// # Panics
    /// Panics if the embedded data violates the snapshot contract.
    #[must_use]
    pub fn selection(self) -> &'static Selection {
        static JS: OnceLock<Selection> = OnceLock::new();
        static TS: OnceLock<Selection> = OnceLock::new();
        let (cell, snapshot, count) = match self {
            Self::JavaScript => (
                &JS,
                include_str!("../../../catalog/reference/javascript-core-community-26.11.json"),
                200,
            ),
            Self::TypeScript => (
                &TS,
                include_str!("../../../catalog/reference/typescript-core-community-26.11.json"),
                199,
            ),
        };
        cell.get_or_init(|| {
            let mut selection: Selection =
                serde_json::from_str(snapshot).expect("valid script Core snapshot");
            assert_eq!(selection.schema_version, 1);
            assert_eq!(selection.version, "26.11.0.134175");
            assert_eq!(selection.active_keys.len(), count);
            assert!(selection.active_keys.iter().all(|key| {
                key.split_once(':')
                    .is_some_and(|(lang, _)| lang == self.language())
            }));
            assert!(
                selection
                    .active_keys
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            );
            assert!(
                selection
                    .parameters
                    .iter()
                    .all(|(key, params)| !params.is_empty()
                        && selection.active_keys.binary_search(key).is_ok())
            );
            selection.digest = format!("{:x}", Sha256::digest(snapshot));
            selection
        })
    }
}

/// Catalog presence and activation do not establish detector support.
#[derive(Deserialize)]
pub struct Selection {
    schema_version: u32,
    pub version: String,
    pub active_keys: Vec<String>,
    pub parameters: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(skip)]
    pub digest: String,
}

impl Selection {
    /// Includes known activated keys with no unmapped profile parameters.
    #[must_use]
    pub fn selects(&self, key: &str, catalog: &Catalog) -> bool {
        self.active_keys
            .binary_search_by(|value| value.as_str().cmp(key))
            .is_ok()
            && !self.parameters.contains_key(key)
            && catalog.rule(key).is_some()
    }
}
