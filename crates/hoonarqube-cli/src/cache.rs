//! Best-effort per-file cache for the project analysis path.
//!
//! Cache entries are deliberately private to one executable/options/path/content
//! combination.  A cache is an optimization only: every malformed, stale,
//! unreadable, or otherwise untrusted entry is treated as a miss and analysis
//! proceeds normally.  The cache never stores failed project outcomes.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hoonarqube_core::project::ProjectFile;
use hoonarqube_core::source_facts::{NormalizedToken, SourceFacts};
use hoonarqube_core::{AnalyzerOptions, Language, language_for_path};
use hoonarqube_ir::{FileMetrics, FileReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CACHE_VERSION: u32 = 1;
const CACHE_NAMESPACE: &str = ".hoonarqube-cache-v1";
const CACHE_EXTENSION: &str = "hqc";
const CACHE_MAGIC: &[u8; 8] = b"HQCACHE1";
const CHECKSUM_BYTES: usize = 32;
const FRAME_PREFIX_BYTES: usize = 8 + 4 + 4 + 8 + CHECKSUM_BYTES;
const MAX_CACHE_ENTRY_BYTES: usize = 64 * 1024 * 1024;
const MAX_CACHE_HEADER_BYTES: usize = 64 * 1024;
const MAX_CACHE_TOKENS: usize = 2 * 1024 * 1024;
const MAX_CACHE_SYMBOLS: usize = 2 * 1024 * 1024;
const TEMP_ATTEMPTS: usize = 16;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Immutable cache context shared by all project workers.
#[derive(Debug)]
pub(crate) struct Cache {
    owned_root: PathBuf,
    cwd_key: String,
    executable_fingerprint: String,
    options_fingerprint: String,
}

/// A successful cached analysis, ready to become a current `ProjectFile`.
pub(crate) struct CacheEntry {
    pub(crate) report: FileReport,
    pub(crate) facts: SourceFacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CacheKey {
    executable: String,
    options: String,
    cwd: String,
    path: String,
    content: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CacheHeader {
    key: CacheKey,
}

#[derive(Debug, Deserialize, Serialize)]
struct CachePayload {
    report: FileReport,
    facts: CachedFacts,
}

#[derive(Debug, Deserialize, Serialize)]
struct CachedFacts {
    metrics: FileMetrics,
    tokens: Vec<CachedToken>,
    symbols: Vec<String>,
    error: Option<String>,
    language: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CachedToken {
    symbol: u32,
    start_line: u32,
    end_line: u32,
    start_byte: u32,
    end_byte: u32,
}

#[derive(Serialize)]
struct CachePayloadRef<'a> {
    report: &'a FileReport,
    facts: CachedFactsRef<'a>,
}

#[derive(Serialize)]
struct CachedFactsRef<'a> {
    metrics: &'a FileMetrics,
    tokens: CachedTokens<'a>,
    symbols: &'a [String],
    error: Option<&'a str>,
    language: &'static str,
}

struct CachedTokens<'a>(&'a [NormalizedToken]);

impl Serialize for CachedTokens<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(CachedToken::from))
    }
}

impl Cache {
    /// Builds a cache context without touching the cache directory.
    ///
    /// An empty `--cache-dir`, missing current directory, or unreadable
    /// executable disables caching rather than changing analysis semantics.
    pub(crate) fn new(cache_dir: Option<&Path>, options: &AnalyzerOptions) -> Option<Self> {
        let cache_dir = cache_dir.filter(|path| !path.as_os_str().is_empty())?;
        let cwd = std::env::current_dir().ok()?;
        let executable_path = std::env::current_exe().ok()?;
        let executable_fingerprint =
            digest_file(&executable_path).map(|digest| digest_hex(&digest))?;
        let owned_root = cwd.join(cache_dir).join(CACHE_NAMESPACE);
        let cwd_key = path_key(&cwd);
        let options_fingerprint =
            digest_hex(&digest(format!("cache-options-v1:{options:?}").as_bytes()));
        Some(Self {
            owned_root,
            cwd_key,
            executable_fingerprint,
            options_fingerprint,
        })
    }

    /// Computes the source digest once per input and uses it for lookup/write.
    pub(crate) fn source_digest(bytes: &[u8]) -> [u8; 32] {
        digest(bytes)
    }

    /// Loads one entry. Every failure is a cache miss and has no user-visible
    /// warning; project completeness is determined only by the fresh analysis.
    pub(crate) fn load(
        &self,
        path: &Path,
        source_len: usize,
        content_digest: [u8; 32],
    ) -> Option<CacheEntry> {
        let key = self.key(path, content_digest);
        let entry_path = self.entry_path(&key);
        let metadata = fs::symlink_metadata(&entry_path).ok()?;
        if !metadata.file_type().is_file() {
            return None;
        }
        let file_len = usize::try_from(metadata.len()).ok()?;
        if !(FRAME_PREFIX_BYTES..=MAX_CACHE_ENTRY_BYTES).contains(&file_len) {
            return None;
        }
        let file = OpenOptions::new().read(true).open(&entry_path).ok()?;
        let mut bytes = Vec::with_capacity(file_len);
        file.take(u64::try_from(MAX_CACHE_ENTRY_BYTES).ok()?.saturating_add(1))
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() != file_len || bytes.len() > MAX_CACHE_ENTRY_BYTES {
            return None;
        }
        let (version, header_len, payload_len, expected_checksum) = parse_frame(&bytes)?;
        if version != CACHE_VERSION
            || header_len > MAX_CACHE_HEADER_BYTES
            || payload_len > MAX_CACHE_ENTRY_BYTES
        {
            return None;
        }
        let total = FRAME_PREFIX_BYTES
            .checked_add(header_len)?
            .checked_add(payload_len)?;
        if total != bytes.len() {
            return None;
        }
        let header_start = FRAME_PREFIX_BYTES;
        let payload_start = header_start.checked_add(header_len)?;
        let header =
            serde_json::from_slice::<CacheHeader>(&bytes[header_start..payload_start]).ok()?;
        if header.key != key {
            return None;
        }
        let payload_bytes = &bytes[payload_start..];
        if digest(payload_bytes) != expected_checksum {
            return None;
        }
        let payload = serde_json::from_slice::<CachePayload>(payload_bytes).ok()?;
        Self::decode_payload(path, source_len, payload)
    }

    /// Stores only a complete successful result. Directory creation and all
    /// writes are best-effort; a cache failure must never fail a report.
    pub(crate) fn store(&self, path: &Path, content_digest: [u8; 32], project_file: &ProjectFile) {
        if project_file.error.is_some() {
            return;
        }
        let (Some(report), Some(facts)) = (&project_file.report, &project_file.facts) else {
            return;
        };
        if facts.error.is_some() || report.metrics != facts.metrics {
            return;
        }
        let payload = CachePayloadRef {
            report,
            facts: CachedFactsRef {
                metrics: &facts.metrics,
                tokens: CachedTokens(&facts.tokens),
                symbols: &facts.symbols,
                error: facts.error.as_deref(),
                language: language_name(facts.language),
            },
        };
        let Ok(header_bytes) = serde_json::to_vec(&CacheHeader {
            key: self.key(path, content_digest),
        }) else {
            return;
        };
        let Some(frame) = make_frame(&header_bytes, &payload) else {
            return;
        };
        let key = self.key(path, content_digest);
        let entry_path = self.entry_path(&key);
        let Some(parent) = entry_path.parent() else {
            return;
        };
        if fs::create_dir_all(parent).is_err() {
            return;
        }
        let Some((temp_path, mut file)) = unique_temp_path(parent, &entry_path) else {
            return;
        };
        let write_result = (|| {
            file.write_all(&frame)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp_path, &entry_path)
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(temp_path);
        }
    }

    fn key(&self, path: &Path, content_digest: [u8; 32]) -> CacheKey {
        CacheKey {
            executable: self.executable_fingerprint.clone(),
            options: self.options_fingerprint.clone(),
            cwd: self.cwd_key.clone(),
            path: path_key(path),
            content: digest_hex(&content_digest),
        }
    }

    fn entry_path(&self, key: &CacheKey) -> PathBuf {
        let mut name = digest_hex(&key_digest(key));
        name.push('.');
        name.push_str(CACHE_EXTENSION);
        self.owned_root.join(name)
    }

    fn decode_payload(path: &Path, source_len: usize, payload: CachePayload) -> Option<CacheEntry> {
        let expected_language = language_for_path(path)?;
        let facts = SourceFacts::try_from(payload.facts).ok()?;
        if facts.error.is_some()
            || facts.language != expected_language
            || payload.report.metrics != facts.metrics
            || payload.report.language != language_name(expected_language)
            || !valid_facts(&facts, source_len)
        {
            return None;
        }
        let mut report = payload.report;
        // The current input owns the current metadata even when the payload
        // came from an earlier process invocation.
        report.path = path.to_path_buf();
        Some(CacheEntry { report, facts })
    }
}

impl From<&NormalizedToken> for CachedToken {
    fn from(token: &NormalizedToken) -> Self {
        Self {
            symbol: token.symbol,
            start_line: token.start_line,
            end_line: token.end_line,
            start_byte: token.start_byte,
            end_byte: token.end_byte,
        }
    }
}

impl TryFrom<CachedFacts> for SourceFacts {
    type Error = ();

    fn try_from(facts: CachedFacts) -> Result<Self, Self::Error> {
        let language = parse_language(&facts.language).ok_or(())?;
        if facts.tokens.len() > MAX_CACHE_TOKENS || facts.symbols.len() > MAX_CACHE_SYMBOLS {
            return Err(());
        }
        let tokens = facts
            .tokens
            .into_iter()
            .map(|token| NormalizedToken {
                symbol: token.symbol,
                start_line: token.start_line,
                end_line: token.end_line,
                start_byte: token.start_byte,
                end_byte: token.end_byte,
            })
            .collect();
        Ok(SourceFacts {
            metrics: facts.metrics,
            tokens,
            symbols: facts.symbols,
            error: facts.error,
            language,
        })
    }
}

fn valid_facts(facts: &SourceFacts, source_len: usize) -> bool {
    if facts.metrics.code_lines > facts.metrics.lines
        || facts.metrics.comment_lines > facts.metrics.lines
        || facts.tokens.len() > MAX_CACHE_TOKENS
        || facts.symbols.len() > MAX_CACHE_SYMBOLS
    {
        return false;
    }
    facts.tokens.iter().all(|token| {
        let symbol = usize::try_from(token.symbol).ok();
        let start_byte = usize::try_from(token.start_byte).ok();
        let end_byte = usize::try_from(token.end_byte).ok();
        symbol.is_some_and(|index| index < facts.symbols.len())
            && token.start_line != 0
            && token.end_line >= token.start_line
            && token.end_line <= facts.metrics.lines
            && start_byte <= end_byte
            && end_byte.is_some_and(|end| end <= source_len)
    })
}

fn parse_language(value: &str) -> Option<Language> {
    Some(match value {
        "python" => Language::Python,
        "javascript" => Language::JavaScript,
        "typescript" => Language::TypeScript,
        "csharpsquid" => Language::CSharp,
        "go" => Language::Go,
        "java" => Language::Java,
        "rust" => Language::Rust,
        "ruby" => Language::Ruby,
        _ => return None,
    })
}

fn language_name(language: Language) -> &'static str {
    match language {
        Language::Python => "python",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::CSharp => "csharpsquid",
        Language::Go => "go",
        Language::Java => "java",
        Language::Rust => "rust",
        Language::Ruby => "ruby",
    }
}

fn parse_frame(bytes: &[u8]) -> Option<(u32, usize, usize, [u8; 32])> {
    if bytes.len() < FRAME_PREFIX_BYTES || &bytes[..CACHE_MAGIC.len()] != CACHE_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let header_len = usize::try_from(u32::from_le_bytes(bytes[12..16].try_into().ok()?)).ok()?;
    let payload_len = usize::try_from(u64::from_le_bytes(bytes[16..24].try_into().ok()?)).ok()?;
    let checksum = bytes[24..56].try_into().ok()?;
    Some((version, header_len, payload_len, checksum))
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl std::io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("cache entry exceeds byte limit"));
        }
        let needed = self.bytes.len() + bytes.len();
        if needed > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(needed)
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(std::io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn make_frame(header: &[u8], payload: &impl Serialize) -> Option<Vec<u8>> {
    if header.len() > MAX_CACHE_HEADER_BYTES {
        return None;
    }
    let header_len = u32::try_from(header.len()).ok()?;
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        limit: MAX_CACHE_ENTRY_BYTES,
    };
    writer.write_all(CACHE_MAGIC).ok()?;
    writer.write_all(&CACHE_VERSION.to_le_bytes()).ok()?;
    writer.write_all(&header_len.to_le_bytes()).ok()?;
    writer.write_all(&[0; 8 + CHECKSUM_BYTES]).ok()?;
    writer.write_all(header).ok()?;
    let payload_start = writer.bytes.len();
    serde_json::to_writer(&mut writer, payload).ok()?;
    let payload_len = u64::try_from(writer.bytes.len() - payload_start).ok()?;
    let checksum = digest(&writer.bytes[payload_start..]);
    writer.bytes[16..24].copy_from_slice(&payload_len.to_le_bytes());
    writer.bytes[24..56].copy_from_slice(&checksum);
    Some(writer.bytes)
}

fn unique_temp_path(parent: &Path, entry: &Path) -> Option<(PathBuf, std::fs::File)> {
    let file_name = entry.file_name()?.to_string_lossy();
    for _ in 0..TEMP_ATTEMPTS {
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));
        if let Ok(file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            return Some((candidate, file));
        }
    }
    None
}

fn key_digest(key: &CacheKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in [
        &key.executable,
        &key.options,
        &key.cwd,
        &key.path,
        &key.content,
    ] {
        let length = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(length.to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().into()
}
fn digest_file(path: &Path) -> Option<[u8; 32]> {
    let mut file = OpenOptions::new().read(true).open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Some(hasher.finalize().into())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn path_key(path: &Path) -> String {
    digest_hex(path.as_os_str().as_encoded_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hoonarqube_core::project::analyze_project_file;
    use hoonarqube_ir::FileClassification;

    #[test]
    fn oversized_serialization_stops_at_the_cache_budget() {
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            limit: 32,
        };
        let error = serde_json::to_writer(&mut writer, &["large-payload"; 100][..])
            .expect_err("oversized entry must stop serialization");
        assert!(error.is_io());
        assert!(writer.bytes.len() <= 32);
        assert!(writer.bytes.capacity() <= 32);
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "hoonarqube-cache-test-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cached_results_invalidate_on_content_path_options_and_binary_changes() {
        let fixture = Fixture::new();
        let options = AnalyzerOptions::default();
        let mut cache = Cache::new(Some(&fixture.0), &options).expect("cache context");
        let path = Path::new("sample.py");
        let source = "def greet(name):\n    return name\n";
        let digest = Cache::source_digest(source.as_bytes());
        let analyzed =
            analyze_project_file(path, source, &options, FileClassification::Source, false);
        cache.store(path, digest, &analyzed);
        let cached = cache.load(path, source.len(), digest).expect("cache hit");
        assert_eq!(
            serde_json::to_value(cached.report).unwrap(),
            serde_json::to_value(analyzed.report.as_ref().unwrap()).unwrap()
        );
        assert_eq!(&cached.facts, analyzed.facts.as_ref().unwrap());
        assert!(
            cache
                .load(path, source.len(), Cache::source_digest(b"changed"))
                .is_none()
        );
        assert!(
            cache
                .load(Path::new("renamed.py"), source.len(), digest)
                .is_none()
        );
        cache.options_fingerprint.push('x');
        assert!(cache.load(path, source.len(), digest).is_none());
        cache.options_fingerprint.pop();
        cache.executable_fingerprint.push('x');
        assert!(cache.load(path, source.len(), digest).is_none());
    }

    #[test]
    fn corrupt_entries_and_failed_analysis_are_never_reused() {
        let fixture = Fixture::new();
        let options = AnalyzerOptions::default();
        let cache = Cache::new(Some(&fixture.0), &options).expect("cache context");
        let path = Path::new("sample.py");
        let source = "answer = 42\n";
        let digest = Cache::source_digest(source.as_bytes());
        let mut analyzed =
            analyze_project_file(path, source, &options, FileClassification::Source, false);
        cache.store(path, digest, &analyzed);
        let entry = cache.entry_path(&cache.key(path, digest));
        let mut bytes = fs::read(&entry).expect("stored entry");
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&entry, bytes).unwrap();
        assert!(cache.load(path, source.len(), digest).is_none());
        cache.store(path, digest, &analyzed);
        assert!(cache.load(path, source.len(), digest).is_some());
        fs::write(&entry, b"truncated").unwrap();
        assert!(cache.load(path, source.len(), digest).is_none());
        fs::remove_file(&entry).unwrap();
        analyzed.facts.as_mut().unwrap().error = Some("incomplete facts".into());
        cache.store(path, digest, &analyzed);
        assert!(!entry.exists());
        analyzed.facts.as_mut().unwrap().error = None;
        analyzed.error = Some("analyzer failed".into());
        cache.store(path, digest, &analyzed);
        assert!(!entry.exists());
    }
}
