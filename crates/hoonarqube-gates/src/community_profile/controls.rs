//! Verified positive and clean native fixtures for strict Community rule coverage.
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

const CONTROLS: &str =
    include_str!("../../../../catalog/reference/community-26.9-detector-controls.tsv");

/// SHA-256 of the positive/negative detector-control manifest sealed into this build.
/// A submitting scanner must declare exactly this digest for a strict gate.
#[must_use]
pub fn community_detector_controls_sha256() -> &'static str {
    static DIGEST: OnceLock<String> = OnceLock::new();
    DIGEST.get_or_init(|| format!("{:x}", Sha256::digest(CONTROLS.as_bytes())))
}

type Keys = BTreeSet<(&'static str, &'static str)>;

pub(super) fn keys() -> Result<&'static Keys, String> {
    static KEYS: OnceLock<Result<Keys, String>> = OnceLock::new();
    KEYS.get_or_init(load).as_ref().map_err(Clone::clone)
}

fn load() -> Result<Keys, String> {
    let mut keys = BTreeSet::new();
    for line in CONTROLS.lines() {
        let columns: Vec<_> = line.split('\t').collect();
        let [language, key, bad, bad_sha, good, good_sha] = columns.as_slice() else {
            return Err("malformed Community detector controls".into());
        };
        if bad == good
            || bad_sha == good_sha
            || ![bad_sha, good_sha]
                .iter()
                .all(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            || !keys.insert((*language, *key))
        {
            return Err("invalid or duplicate Community detector controls".into());
        }
    }
    Ok(keys)
}
