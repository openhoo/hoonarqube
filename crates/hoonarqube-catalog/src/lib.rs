//! Compile-time frozen `SonarQube` rule catalog with evidence-first integrity verification.
//!
//! The crate embeds `catalog/snapshot.toml` plus the six per-language rule files at
//! compile time. [`embedded`] replays the exact audit semantics of
//! `xtask catalog audit` once per process; every accessor afterwards relies on the
//! established invariants (verified hashes, verified counts, strictly key-sorted rules).
//!
//! Because the embedded bytes are frozen at compile time, a verification failure can
//! only mean corrupted build artifacts. [`embedded`] therefore panics with a
//! precise message instead of ever exposing unverified catalog data.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
pub mod github_quality;

/// Analyzer profile controlling whether Hoonarqube-native rules run in
/// addition to the frozen Sonar-parity catalog, or whether the analyzer
/// emits GitHub Code Quality findings instead.
///
/// Profiles are cumulative: `extended` includes `recommended`, while
/// `strict` includes every native rule. `sonar-parity` is the compatibility
/// profile and never enables native rules. `github-code-quality` is an
/// isolated output profile and does not enable native rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleProfile {
    #[default]
    SonarParity,
    Recommended,
    Extended,
    Strict,
    GithubCodeQuality,
}

impl RuleProfile {
    /// Whether this selected profile includes a rule introduced at
    /// `minimum_profile`.
    #[must_use]
    pub const fn includes(self, minimum_profile: Self) -> bool {
        match self {
            Self::SonarParity | Self::GithubCodeQuality => false,
            Self::Recommended => matches!(minimum_profile, Self::Recommended),
            Self::Extended => matches!(minimum_profile, Self::Recommended | Self::Extended),
            Self::Strict => !matches!(minimum_profile, Self::SonarParity | Self::GithubCodeQuality),
        }
    }
}

impl std::str::FromStr for RuleProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sonar-parity" => Ok(Self::SonarParity),
            "recommended" => Ok(Self::Recommended),
            "extended" => Ok(Self::Extended),
            "strict" => Ok(Self::Strict),
            "github-code-quality" => Ok(Self::GithubCodeQuality),
            _ => Err(format!(
                "unknown profile {value:?}; expected sonar-parity, recommended, extended, strict, or github-code-quality"
            )),
        }
    }
}

impl std::fmt::Display for RuleProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::SonarParity => "sonar-parity",
            Self::Recommended => "recommended",
            Self::Extended => "extended",
            Self::Strict => "strict",
            Self::GithubCodeQuality => "github-code-quality",
        })
    }
}

/// Expected precision of an independently implemented native rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativePrecision {
    High,
    Medium,
}

/// Analysis capability used by a native rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeImplementation {
    Syntax,
    ControlFlow,
    SemanticAdapter,
}

/// One software-quality impact declared by a native rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NativeImpact {
    pub software_quality: &'static str,
    pub severity: &'static str,
}

/// Metadata for one Hoonarqube-native rule.
///
/// This catalog is intentionally separate from [`RuleRecord`]: native rules
/// must never be mistaken for facts captured from a `SonarQube` server. Rule
/// behavior is independently implemented from public documentation; no
/// third-party rule source is embedded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NativeRuleRecord {
    pub external_key: &'static str,
    pub language: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: &'static str,
    pub rule_type: &'static str,
    pub clean_code_attribute: &'static str,
    pub impacts: &'static [NativeImpact],
    pub minimum_profile: RuleProfile,
    pub precision: NativePrecision,
    pub implementation: NativeImplementation,
    pub origin_tool: &'static str,
    pub origin_rule_id: &'static str,
    pub origin_url: &'static str,
    pub origin_license: &'static str,
    pub derivation: &'static str,
}

const SECURITY_HIGH: &[NativeImpact] = &[NativeImpact {
    software_quality: "SECURITY",
    severity: "HIGH",
}];
const RELIABILITY_HIGH: &[NativeImpact] = &[NativeImpact {
    software_quality: "RELIABILITY",
    severity: "HIGH",
}];
const RELIABILITY_MEDIUM: &[NativeImpact] = &[NativeImpact {
    software_quality: "RELIABILITY",
    severity: "MEDIUM",
}];
const MAINTAINABILITY_MEDIUM: &[NativeImpact] = &[NativeImpact {
    software_quality: "MAINTAINABILITY",
    severity: "MEDIUM",
}];

const GOSEC_URL: &str = "https://github.com/securego/gosec/blob/master/RULES.md";
const STATICCHECK_URL: &str = "https://staticcheck.dev/docs/checks/";
const CODEQL_PY_FILE_URL: &str =
    "https://codeql.github.com/codeql-query-help/python/py-file-not-closed/";
const CODEQL_PY_ASSERT_URL: &str =
    "https://codeql.github.com/codeql-query-help/python/py-side-effect-in-assert/";
const CODEQL_JS_LOOP_URL: &str = "https://codeql.github.com/codeql-query-help/javascript/js-loop-iteration-skipped-due-to-shifting/";
const CODEQL_JS_STREAM_URL: &str =
    "https://codeql.github.com/codeql-query-help/javascript/js-unhandled-error-in-stream-pipeline/";
const DOTNET_CA2022_URL: &str =
    "https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca2022";
const DOTNET_CA2024_URL: &str =
    "https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca2024";
const DOTNET_CA2026_URL: &str =
    "https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca2026";
const ESLINT_ASYNC_EXECUTOR_URL: &str =
    "https://eslint.org/docs/latest/rules/no-async-promise-executor";
const ESLINT_EXECUTOR_RETURN_URL: &str =
    "https://eslint.org/docs/latest/rules/no-promise-executor-return";
const RUFF_REQUEST_TIMEOUT_URL: &str = "https://docs.astral.sh/ruff/rules/request-without-timeout/";
const CLIPPY_LOCK_URL: &str =
    "https://rust-lang.github.io/rust-clippy/master/index.html#await_holding_lock";
const CLIPPY_REFCELL_URL: &str =
    "https://rust-lang.github.io/rust-clippy/master/index.html#await_holding_refcell_ref";
const CLIPPY_PERMISSIONS_URL: &str =
    "https://rust-lang.github.io/rust-clippy/master/index.html#permissions_set_readonly_false";
const CLIPPY_OPEN_OPTIONS_URL: &str =
    "https://rust-lang.github.io/rust-clippy/master/index.html#suspicious_open_options";
const INDEPENDENT_DERIVATION: &str =
    "Independent implementation from published rule behavior; no third-party source embedded.";

macro_rules! native_rule {
    ($key:literal, $language:literal, $name:literal, $description:literal,
     $severity:literal, $rule_type:literal, $attribute:literal, $impacts:ident,
     $profile:ident, $precision:ident, $implementation:ident,
     $tool:literal, $origin:literal, $url:expr, $license:literal) => {
        NativeRuleRecord {
            external_key: $key,
            language: $language,
            name: $name,
            description: $description,
            severity: $severity,
            rule_type: $rule_type,
            clean_code_attribute: $attribute,
            impacts: $impacts,
            minimum_profile: RuleProfile::$profile,
            precision: NativePrecision::$precision,
            implementation: NativeImplementation::$implementation,
            origin_tool: $tool,
            origin_rule_id: $origin,
            origin_url: $url,
            origin_license: $license,
            derivation: INDEPENDENT_DERIVATION,
        }
    };
}

/// Independently implemented native rules, sorted by `external_key`.
const NATIVE_RULES: &[NativeRuleRecord] = &[
    native_rule!(
        "hoonarqube-csharp:CA2022",
        "cs",
        "Avoid inexact Stream.Read calls",
        "Stream.Read and ReadAsync can return fewer bytes than requested, so callers must inspect the returned count.",
        "MAJOR",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        ".NET analyzers",
        "CA2022",
        DOTNET_CA2022_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-csharp:CA2024",
        "cs",
        "Do not use StreamReader.EndOfStream in async methods",
        "Synchronous end-of-stream checks can block an asynchronous method.",
        "MAJOR",
        "BUG",
        "EFFICIENT",
        RELIABILITY_MEDIUM,
        Recommended,
        High,
        Syntax,
        ".NET analyzers",
        "CA2024",
        DOTNET_CA2024_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-csharp:CA2026",
        "cs",
        "Prefer JsonElement.Parse",
        "Parsing a temporary JsonDocument only to retain RootElement keeps disposable backing data alive unnecessarily.",
        "MAJOR",
        "BUG",
        "EFFICIENT",
        RELIABILITY_MEDIUM,
        Extended,
        High,
        SemanticAdapter,
        ".NET analyzers",
        "CA2026",
        DOTNET_CA2026_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:G110",
        "go",
        "Limit decompression output",
        "Copying decompressed data without an explicit limit can exhaust disk or memory.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "gosec",
        "G110",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G112",
        "go",
        "Configure an HTTP ReadHeaderTimeout",
        "HTTP servers should bound the time spent reading request headers.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        Syntax,
        "gosec",
        "G112",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G114",
        "go",
        "Avoid unconfigured net/http serving helpers",
        "Package-level HTTP serving helpers omit server timeout configuration.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        Syntax,
        "gosec",
        "G114",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G116",
        "go",
        "Remove bidirectional Unicode controls",
        "Bidirectional control characters can make reviewed source differ from compiled source.",
        "BLOCKER",
        "VULNERABILITY",
        "IDENTIFIABLE",
        SECURITY_HIGH,
        Recommended,
        High,
        Syntax,
        "gosec",
        "G116",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G117",
        "go",
        "Do not serialize exported secret fields",
        "Exported secret-bearing fields should not be exposed through serialization tags.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        Syntax,
        "gosec",
        "G117",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G124",
        "go",
        "Harden HTTP cookie attributes",
        "HTTP cookies should enable Secure and HttpOnly and use SameSite Lax or Strict.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "gosec",
        "G124",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G301",
        "go",
        "Restrict directory permissions",
        "Created directories should not grant permissions broader than 0750.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        Syntax,
        "gosec",
        "G301",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G302",
        "go",
        "Restrict chmod permissions",
        "Files changed with chmod should not grant permissions broader than 0600.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        Syntax,
        "gosec",
        "G302",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G303",
        "go",
        "Avoid predictable temporary paths",
        "Writing directly to a shared temporary directory allows predictable-name attacks.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "gosec",
        "G303",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G305",
        "go",
        "Validate archive entry paths",
        "Joining zip or tar entry names directly to an extraction root can escape the target directory.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "gosec",
        "G305",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G306",
        "go",
        "Restrict written-file permissions",
        "Files written in one operation should not grant permissions broader than 0600.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        Syntax,
        "gosec",
        "G306",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G307",
        "go",
        "Avoid os.Create under strict file-permission policy",
        "os.Create uses mode 0666 before the process umask; strict policy requires an explicit 0600 mode.",
        "MAJOR",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Strict,
        High,
        SemanticAdapter,
        "gosec",
        "G307",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G401",
        "go",
        "Do not use MD5 or SHA-1",
        "MD5 and SHA-1 are unsuitable for security-sensitive hashing.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "gosec",
        "G401",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G402",
        "go",
        "Verify TLS certificates",
        "TLS clients must not disable certificate verification.",
        "BLOCKER",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        Syntax,
        "gosec",
        "G402",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G403",
        "go",
        "Use sufficiently large cryptographic keys",
        "RSA keys shorter than 2048 bits are not sufficiently strong.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        Syntax,
        "gosec",
        "G403",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G405",
        "go",
        "Do not use DES or RC4",
        "DES and RC4 are obsolete encryption algorithms.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "gosec",
        "G405",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:G406",
        "go",
        "Do not use MD4 or RIPEMD-160",
        "MD4 and RIPEMD-160 are deprecated cryptographic hashes.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "gosec",
        "G406",
        GOSEC_URL,
        "Apache-2.0"
    ),
    native_rule!(
        "hoonarqube-go:SA1004",
        "go",
        "Use an explicit time unit for short sleeps",
        "Small untyped integer durations passed to time.Sleep are usually mistaken for a larger time unit.",
        "MAJOR",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Extended,
        High,
        SemanticAdapter,
        "Staticcheck",
        "SA1004",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA1012",
        "go",
        "Do not pass nil contexts",
        "A context.Context argument must not be nil; use context.TODO or context.Background when no parent exists.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "Staticcheck",
        "SA1012",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA2000",
        "go",
        "Call WaitGroup.Add before starting a goroutine",
        "Calling Add inside the goroutine races with Wait.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        Syntax,
        "Staticcheck",
        "SA2000",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA2001",
        "go",
        "Remove empty critical sections",
        "Locking and immediately unlocking performs no protected work.",
        "MAJOR",
        "BUG",
        "LOGICAL",
        RELIABILITY_MEDIUM,
        Extended,
        Medium,
        ControlFlow,
        "Staticcheck",
        "SA2001",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA2003",
        "go",
        "Do not defer Lock after locking",
        "A deferred Lock usually means Unlock was intended and can deadlock.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        Medium,
        ControlFlow,
        "Staticcheck",
        "SA2003",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA4006",
        "go",
        "Use assigned values before overwriting them",
        "A value overwritten before any read is dead and often represents a forgotten error check.",
        "MAJOR",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Extended,
        Medium,
        ControlFlow,
        "Staticcheck",
        "SA4006",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA4008",
        "go",
        "Update the variable used by the loop condition",
        "A loop condition variable that never changes can make the loop infinite or ineffective.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "Staticcheck",
        "SA4008",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA4010",
        "go",
        "Use append results",
        "Discarding append's returned slice leaves the intended update unused.",
        "MAJOR",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        Medium,
        Syntax,
        "Staticcheck",
        "SA4010",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA5000",
        "go",
        "Initialize maps before assignment",
        "Assigning an entry through a nil map panics.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "Staticcheck",
        "SA5000",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA5001",
        "go",
        "Check errors before deferring Close",
        "Deferring Close before checking a resource-opening error can dereference a nil resource.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "Staticcheck",
        "SA5001",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA5003",
        "go",
        "Do not defer inside endless loops",
        "Deferred calls in a loop that never returns cannot run and accumulate resources.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "Staticcheck",
        "SA5003",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-go:SA6000",
        "go",
        "Compile regular expressions outside loops",
        "Compiling a constant regular expression on every iteration wastes work.",
        "MINOR",
        "CODE_SMELL",
        "EFFICIENT",
        MAINTAINABILITY_MEDIUM,
        Extended,
        High,
        ControlFlow,
        "Staticcheck",
        "SA6000",
        STATICCHECK_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-javascript:loop-iteration-skipped-due-to-shifting",
        "js",
        "Do not splice at an incrementing loop index",
        "Removing the current indexed element with splice while incrementing can skip the following element.",
        "MAJOR",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "CodeQL",
        "js/loop-iteration-skipped-due-to-shifting",
        CODEQL_JS_LOOP_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-javascript:no-async-promise-executor",
        "js",
        "Do not use async Promise executors",
        "Exceptions thrown by an async Promise executor do not reject the Promise being constructed.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "ESLint",
        "no-async-promise-executor",
        ESLINT_ASYNC_EXECUTOR_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-javascript:no-promise-executor-return",
        "js",
        "Do not return values from Promise executors",
        "A Promise constructor ignores the executor's return value, so valued returns are misleading.",
        "MAJOR",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Extended,
        High,
        ControlFlow,
        "ESLint",
        "no-promise-executor-return",
        ESLINT_EXECUTOR_RETURN_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-javascript:unhandled-error-in-stream-pipeline",
        "js",
        "Handle errors on piped streams",
        "A source stream passed through pipe needs its own error handler; stream.pipeline handles the chain automatically.",
        "CRITICAL",
        "BUG",
        "COMPLETE",
        RELIABILITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "CodeQL",
        "js/unhandled-error-in-stream-pipeline",
        CODEQL_JS_STREAM_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-python:file-not-closed",
        "py",
        "Close opened files",
        "A locally opened file with no observed close or ownership transfer can leak resources.",
        "CRITICAL",
        "BUG",
        "COMPLETE",
        RELIABILITY_HIGH,
        Extended,
        High,
        ControlFlow,
        "CodeQL",
        "py/file-not-closed",
        CODEQL_PY_FILE_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-python:request-without-timeout",
        "py",
        "Set timeouts on HTTP client calls",
        "Requests has no default timeout, and an explicit None disables HTTPX's default timeout.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "Ruff",
        "S113",
        RUFF_REQUEST_TIMEOUT_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-python:side-effect-in-assert",
        "py",
        "Do not rely on assertion side effects",
        "Assertions can be disabled, so their conditions must not perform required side effects.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        Syntax,
        "CodeQL",
        "py/side-effect-in-assert",
        CODEQL_PY_ASSERT_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-rust:await-holding-lock",
        "rust",
        "Do not await while holding a lock guard",
        "Holding a lock guard across an await point can deadlock and blocks other tasks.",
        "CRITICAL",
        "BUG",
        "EFFICIENT",
        RELIABILITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "Clippy",
        "await_holding_lock",
        CLIPPY_LOCK_URL,
        "Apache-2.0 OR MIT"
    ),
    native_rule!(
        "hoonarqube-rust:await-holding-refcell-ref",
        "rust",
        "Do not await while holding a RefCell borrow",
        "Holding a RefCell borrow across an await point can panic on later mutable borrowing.",
        "CRITICAL",
        "BUG",
        "EFFICIENT",
        RELIABILITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "Clippy",
        "await_holding_refcell_ref",
        CLIPPY_REFCELL_URL,
        "Apache-2.0 OR MIT"
    ),
    native_rule!(
        "hoonarqube-rust:permissions-set-readonly-false",
        "rust",
        "Do not clear readonly with set_readonly(false)",
        "On Unix, clearing readonly this way can make a file world-writable.",
        "CRITICAL",
        "VULNERABILITY",
        "COMPLETE",
        SECURITY_HIGH,
        Extended,
        Medium,
        SemanticAdapter,
        "Clippy",
        "permissions_set_readonly_false",
        CLIPPY_PERMISSIONS_URL,
        "Apache-2.0 OR MIT"
    ),
    native_rule!(
        "hoonarqube-rust:suspicious-open-options",
        "rust",
        "Declare truncation behavior for created files",
        "OpenOptions with create(true) should explicitly select truncation, appending, or exclusive creation semantics.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "Clippy",
        "suspicious_open_options",
        CLIPPY_OPEN_OPTIONS_URL,
        "Apache-2.0 OR MIT"
    ),
    native_rule!(
        "hoonarqube-typescript:loop-iteration-skipped-due-to-shifting",
        "ts",
        "Do not splice at an incrementing loop index",
        "Removing the current indexed element with splice while incrementing can skip the following element.",
        "MAJOR",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        ControlFlow,
        "CodeQL",
        "js/loop-iteration-skipped-due-to-shifting",
        CODEQL_JS_LOOP_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-typescript:no-async-promise-executor",
        "ts",
        "Do not use async Promise executors",
        "Exceptions thrown by an async Promise executor do not reject the Promise being constructed.",
        "CRITICAL",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "ESLint",
        "no-async-promise-executor",
        ESLINT_ASYNC_EXECUTOR_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-typescript:no-promise-executor-return",
        "ts",
        "Do not return values from Promise executors",
        "A Promise constructor ignores the executor's return value, so valued returns are misleading.",
        "MAJOR",
        "BUG",
        "LOGICAL",
        RELIABILITY_HIGH,
        Extended,
        High,
        ControlFlow,
        "ESLint",
        "no-promise-executor-return",
        ESLINT_EXECUTOR_RETURN_URL,
        "MIT"
    ),
    native_rule!(
        "hoonarqube-typescript:unhandled-error-in-stream-pipeline",
        "ts",
        "Handle errors on piped streams",
        "A source stream passed through pipe needs its own error handler; stream.pipeline handles the chain automatically.",
        "CRITICAL",
        "BUG",
        "COMPLETE",
        RELIABILITY_HIGH,
        Recommended,
        High,
        SemanticAdapter,
        "CodeQL",
        "js/unhandled-error-in-stream-pipeline",
        CODEQL_JS_STREAM_URL,
        "MIT"
    ),
];

/// Iterates the Hoonarqube-native catalog in stable key order.
#[must_use]
pub fn native_rules() -> impl ExactSizeIterator<Item = &'static NativeRuleRecord> {
    NATIVE_RULES.iter()
}

/// Looks up one independently implemented native rule by external key.
#[must_use]
pub fn native_rule(external_key: &str) -> Option<&'static NativeRuleRecord> {
    NATIVE_RULES
        .binary_search_by_key(&external_key, |rule| rule.external_key)
        .ok()
        .map(|index| &NATIVE_RULES[index])
}

/// Embedded languages in canonical audit order: `(catalog name, language id, repository)`.
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
const GO_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../catalog/rules/go.json"
));
const RUST_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../catalog/rules/rust.json"
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
    pub source_capture_sha256: String,
    pub captured_at_utc: String,
    pub server_version: String,
    pub source_edition: String,
    pub oracle_edition: String,
    pub instance_mode: String,
    pub page_size: u64,
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

#[derive(Debug, Deserialize)]
struct CommunityResolution {
    schema_version: u16,
    target: CommunityTarget,
    enterprise_unverified_rules: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CommunityTarget {
    oracle_edition: String,
    requires_license: bool,
    includes_enterprise_rules: bool,
    classification: String,
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
            [
                CSHARP_JSON,
                JAVASCRIPT_JSON,
                TYPESCRIPT_JSON,
                PYTHON_JSON,
                GO_JSON,
                RUST_JSON,
            ],
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
    /// Embedded catalog name (`csharp`, `javascript`, `typescript`, `python`, `go`, or `rust`).
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// `SonarQube` language id (`cs`, `js`, `ts`, `py`, `go`, or `rust`).
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
fn verify(snapshot_text: &str, rule_texts: [&str; 6]) -> Result<Catalog, String> {
    let snapshot: Snapshot = toml::from_str(snapshot_text)
        .map_err(|error| format!("catalog snapshot is invalid: {error}"))?;
    verify_snapshot(&snapshot)?;
    verify_community_evidence(&snapshot)?;

    let mut source_total = 0_usize;
    let mut scoped_total = 0_usize;
    let mut catalog_hasher = Sha256::new();
    let mut languages = Vec::with_capacity(LANGUAGES.len());
    for ((language_name, language_id, repository), rule_text) in
        LANGUAGES.iter().copied().zip(rule_texts)
    {
        let language = verify_language(
            &snapshot,
            language_name,
            language_id,
            repository,
            rule_text,
            &mut catalog_hasher,
        )?;
        source_total += language.len();
        scoped_total += language.len();
        languages.push(language);
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

fn verify_snapshot(snapshot: &Snapshot) -> Result<(), String> {
    if snapshot.schema_version != 4 {
        return Err("unsupported catalog snapshot schema".to_owned());
    }
    if snapshot.scope_classification != SCOPE_CLASSIFICATION {
        return Err("snapshot has invalid scope classification".to_owned());
    }
    if snapshot.oracle_edition != "community" {
        return Err("snapshot oracle is not Community".to_owned());
    }
    if !is_sha256(&snapshot.capture_sha256)
        || !is_sha256(&snapshot.catalog_sha256)
        || snapshot.captured_at_utc.is_empty()
        || snapshot.server_version.is_empty()
        || snapshot.edition.is_empty()
        || snapshot.instance_mode.is_empty()
        || snapshot.page_size == 0
    {
        return Err("snapshot capture provenance is incomplete".to_owned());
    }
    if !has_exact_language_keys(&snapshot.languages)
        || !has_exact_language_keys(&snapshot.unverified_rules)
        || !has_exact_language_keys(&snapshot.rule_files)
    {
        return Err("snapshot language scope mismatch".to_owned());
    }
    if snapshot.endpoints.len() != REQUIRED_ENDPOINTS.len()
        || REQUIRED_ENDPOINTS
            .iter()
            .any(|endpoint| !snapshot.endpoints.contains_key(*endpoint))
        || snapshot.endpoints.values().any(|receipt| {
            !(200..300).contains(&receipt.status)
                || receipt.bytes == 0
                || !is_sha256(&receipt.sha256)
        })
    {
        return Err("snapshot endpoint provenance is incomplete".to_owned());
    }
    if snapshot.plugins.is_empty()
        || !snapshot
            .plugins
            .windows(2)
            .all(|pair| pair[0].key < pair[1].key)
        || snapshot.plugins.iter().any(|plugin| plugin.key.is_empty())
    {
        return Err("snapshot plugin provenance is incomplete".to_owned());
    }
    Ok(())
}

fn verify_community_evidence(snapshot: &Snapshot) -> Result<(), String> {
    if snapshot.community_evidence_sha256 != sha256(COMMUNITY_EVIDENCE_JSON.as_bytes()) {
        return Err("Community scope evidence hash mismatch".to_owned());
    }
    let evidence: CommunityResolution = serde_json::from_str(COMMUNITY_EVIDENCE_JSON)
        .map_err(|error| format!("Community artifact-resolution evidence is invalid: {error}"))?;
    if evidence.schema_version != 3 {
        return Err("unsupported Community evidence schema".to_owned());
    }
    if evidence.target.oracle_edition != "community"
        || evidence.target.requires_license
        || !evidence.target.includes_enterprise_rules
        || evidence.target.classification != SCOPE_CLASSIFICATION
    {
        return Err(
            "Community evidence does not describe the declared mixed rule scope".to_owned(),
        );
    }
    if !has_exact_language_keys(&evidence.enterprise_unverified_rules) {
        return Err("Community evidence language scope mismatch".to_owned());
    }
    if evidence.enterprise_unverified_rules != snapshot.unverified_rules {
        return Err("snapshot unverified rules differ from Community evidence".to_owned());
    }
    Ok(())
}

fn verify_language(
    snapshot: &Snapshot,
    language_name: &'static str,
    language_id: &'static str,
    repository: &'static str,
    rule_text: &str,
    catalog_hasher: &mut Sha256,
) -> Result<LanguageCatalog, String> {
    let catalog: RuleCatalog = serde_json::from_str(rule_text)
        .map_err(|error| format!("invalid catalog file {language_name}.json: {error}"))?;
    if catalog.schema_version != 1 {
        return Err("unsupported rule catalog schema".to_owned());
    }
    if catalog.language != language_id {
        return Err("catalog language mismatch".to_owned());
    }
    if catalog.classification != SCOPE_CLASSIFICATION {
        return Err("catalog classification mismatch".to_owned());
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
    verify_language_receipt(receipt, &catalog, language_id, repository)?;
    let unverified = snapshot
        .unverified_rules
        .get(language_name)
        .ok_or_else(|| format!("snapshot lacks {language_name} unverified rules"))?;
    if !unverified.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err("unverified rules are not strictly key-sorted".to_owned());
    }
    if unverified.iter().any(|key| {
        key.strip_prefix(repository)
            .and_then(|rest| rest.strip_prefix(':'))
            .is_none_or(str::is_empty)
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
    verify_rule_facts(&catalog, language_id, repository)?;
    if !counts_match(receipt.source_total, catalog.rules.len())
        || !counts_match(receipt.total, catalog.rules.len())
    {
        return Err("catalog count mismatch".to_owned());
    }
    if snapshot.rule_files.get(language_name) != Some(&sha256(rule_text.as_bytes())) {
        return Err("catalog file hash mismatch".to_owned());
    }
    hash_record(catalog_hasher, language_name.as_bytes());
    hash_record(catalog_hasher, rule_text.as_bytes());
    Ok(LanguageCatalog {
        name: language_name,
        language_id,
        catalog,
    })
}

fn verify_language_receipt(
    receipt: &SnapshotLanguage,
    catalog: &RuleCatalog,
    language_id: &str,
    repository: &str,
) -> Result<(), String> {
    if receipt.language != language_id || receipt.repository != repository {
        return Err("language receipt identity mismatch".to_owned());
    }
    if catalog.source_capture_sha256 != receipt.source_capture_sha256 {
        return Err("catalog capture provenance mismatch".to_owned());
    }
    if receipt.oracle_edition != "community"
        || receipt.page_size == 0
        || !is_sha256(&receipt.source_capture_sha256)
        || !is_sha256(&receipt.query_sha256)
        || !is_sha256(&receipt.pages_sha256)
        || !is_sha256(&receipt.keys_sha256)
        || !is_sha256(&receipt.shows_sha256)
        || receipt.server_version.is_empty()
        || receipt.captured_at_utc.is_empty()
        || receipt.source_edition.is_empty()
        || receipt.instance_mode.is_empty()
    {
        return Err("language capture provenance is incomplete".to_owned());
    }
    let expected_pages = receipt.source_total.max(1).div_ceil(receipt.page_size);
    if !counts_match(receipt.source_total, receipt.unique_keys)
        || !counts_match(receipt.source_total, receipt.show_count)
        || !counts_match(expected_pages, receipt.page_count)
    {
        return Err("language capture closure mismatch".to_owned());
    }
    Ok(())
}

fn verify_rule_facts(
    catalog: &RuleCatalog,
    language_id: &str,
    repository: &str,
) -> Result<(), String> {
    if !is_sha256(&catalog.source_capture_sha256)
        || catalog.rules.iter().any(|rule| {
            rule.language != language_id
                || rule.repository != repository
                || rule
                    .external_key
                    .strip_prefix(repository)
                    .and_then(|rest| rest.strip_prefix(':'))
                    .is_none_or(str::is_empty)
        })
    {
        return Err("catalog rule identity mismatch".to_owned());
    }
    if catalog.rules.iter().any(|rule| {
        rule.provenance_id != catalog.source_capture_sha256
            || rule.status.is_empty()
            || rule.scope.is_empty()
            || rule.severity.is_empty()
            || rule.rule_type.is_empty()
            || rule
                .clean_code_attribute
                .as_ref()
                .is_some_and(String::is_empty)
            || rule
                .clean_code_attribute_category
                .as_ref()
                .is_some_and(String::is_empty)
            || rule
                .impacts
                .iter()
                .any(|impact| impact.software_quality.is_empty() || impact.severity.is_empty())
            || rule
                .parameters
                .iter()
                .any(|parameter| parameter.key.is_empty())
            || !all_unique(
                rule.parameters
                    .iter()
                    .map(|parameter| parameter.key.as_str()),
            )
    }) {
        return Err("catalog contains incomplete rule facts".to_owned());
    }
    Ok(())
}

fn all_unique<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn has_exact_language_keys<T>(map: &BTreeMap<String, T>) -> bool {
    map.len() == LANGUAGES.len() && LANGUAGES.iter().all(|(name, _, _)| map.contains_key(*name))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        CSHARP_JSON, GO_JSON, JAVASCRIPT_JSON, LANGUAGES, PYTHON_JSON, RUST_JSON, SNAPSHOT_TOML,
        TYPESCRIPT_JSON, verify,
    };

    const PRISTINE: [&str; 6] = [
        CSHARP_JSON,
        JAVASCRIPT_JSON,
        TYPESCRIPT_JSON,
        PYTHON_JSON,
        GO_JSON,
        RUST_JSON,
    ];

    #[test]
    fn embedded_catalog_passes_full_verification() {
        let catalog = super::embedded();
        let snapshot = catalog.snapshot();
        assert_eq!(snapshot.schema_version, 4);
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
        assert_eq!(catalog.snapshot().source_total_rules, 1741);
        assert_eq!(catalog.snapshot().total_rules, 1741);
    }

    #[test]
    fn embedded_rule_counts_match_snapshot_evidence() {
        let catalog = super::embedded();
        assert_eq!(catalog.snapshot().source_total_rules, 1741);
        assert_eq!(catalog.snapshot().total_rules, 1741);
        let expected = [
            ("csharp", 467),
            ("javascript", 406),
            ("typescript", 412),
            ("python", 335),
            ("go", 36),
            ("rust", 85),
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
        assert_eq!(seen.len(), 1741);
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

    #[test]
    fn native_catalog_is_separate_sorted_and_complete() {
        let rules: Vec<_> = super::native_rules().collect();
        assert_eq!(rules.len(), 47);
        assert!(
            rules
                .windows(2)
                .all(|pair| pair[0].external_key < pair[1].external_key)
        );
        for rule in rules {
            assert!(rule.external_key.starts_with("hoonarqube-"));
            assert!(!rule.name.is_empty());
            assert!(!rule.description.is_empty());
            assert!(!rule.origin_tool.is_empty());
            assert!(!rule.origin_rule_id.is_empty());
            assert!(rule.origin_url.starts_with("https://"));
            assert!(!rule.origin_license.is_empty());
            assert!(!rule.impacts.is_empty());
            assert!(
                [
                    "CLEAR",
                    "COMPLETE",
                    "CONVENTIONAL",
                    "DISTINCT",
                    "EFFICIENT",
                    "FOCUSED",
                    "FORMATTED",
                    "IDENTIFIABLE",
                    "LAWFUL",
                    "LOGICAL",
                    "MODULAR",
                    "TESTED",
                    "TRUSTWORTHY",
                ]
                .contains(&rule.clean_code_attribute),
                "invalid Sonar clean-code attribute: {}",
                rule.clean_code_attribute,
            );
            assert!(
                ["BUG", "VULNERABILITY", "CODE_SMELL", "SECURITY_HOTSPOT"]
                    .contains(&rule.rule_type),
                "invalid Sonar rule type: {}",
                rule.rule_type,
            );
            assert!(
                ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"].contains(&rule.severity),
                "invalid Sonar severity: {}",
                rule.severity,
            );
            for impact in rule.impacts {
                assert!(
                    ["SECURITY", "RELIABILITY", "MAINTAINABILITY"]
                        .contains(&impact.software_quality),
                    "invalid Sonar software quality: {}",
                    impact.software_quality,
                );
                assert!(
                    ["BLOCKER", "HIGH", "MEDIUM", "LOW", "INFO"].contains(&impact.severity),
                    "invalid Sonar impact severity: {}",
                    impact.severity,
                );
            }
            assert!(super::embedded().rule(rule.external_key).is_none());
            assert_eq!(super::native_rule(rule.external_key), Some(rule));
        }
        assert!(super::native_rule("hoonarqube-go:missing").is_none());
    }

    #[test]
    fn native_profiles_are_cumulative_and_parity_isolated() {
        use super::RuleProfile::{Extended, Recommended, SonarParity, Strict};

        assert!(!SonarParity.includes(Recommended));
        assert!(Recommended.includes(Recommended));
        assert!(!Recommended.includes(Extended));
        assert!(Extended.includes(Recommended));
        assert!(Extended.includes(Extended));
        assert!(Strict.includes(Recommended));
        assert!(Strict.includes(Extended));
        let enabled = |profile: super::RuleProfile| {
            super::native_rules()
                .filter(|rule| profile.includes(rule.minimum_profile))
                .count()
        };
        assert_eq!(enabled(SonarParity), 0);
        assert_eq!(enabled(Recommended), 37);
        assert_eq!(enabled(Extended), 46);
        assert_eq!(enabled(Strict), 47);
    }

    #[test]
    fn github_profile_is_explicit_and_native_isolation_is_preserved() {
        use super::RuleProfile::GithubCodeQuality;

        assert_eq!(
            "github-code-quality".parse::<super::RuleProfile>(),
            Ok(GithubCodeQuality)
        );
        assert_eq!(GithubCodeQuality.to_string(), "github-code-quality");
        assert!(!GithubCodeQuality.includes(super::RuleProfile::Recommended));
        assert_eq!(
            super::native_rules()
                .filter(|rule| GithubCodeQuality.includes(rule.minimum_profile))
                .count(),
            0
        );
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

    #[test]
    fn unsupported_per_language_schema_fails_verification() {
        let tampered = PYTHON_JSON.replacen("\"schema_version\": 1", "\"schema_version\": 2", 1);
        let mut rule_texts = PRISTINE;
        rule_texts[3] = &tampered;
        let error = verify(SNAPSHOT_TOML, rule_texts).expect_err("unknown schema must fail");
        assert_eq!(error, "unsupported rule catalog schema");
    }

    #[test]
    fn mismatched_rule_repository_fails_verification() {
        let tampered = PYTHON_JSON.replacen(
            "\"repository\": \"python\"",
            "\"repository\": \"not-python\"",
            1,
        );
        let mut rule_texts = PRISTINE;
        rule_texts[3] = &tampered;
        let error = verify(SNAPSHOT_TOML, rule_texts).expect_err("wrong repository must fail");
        assert_eq!(error, "catalog rule identity mismatch");
    }

    #[test]
    fn incomplete_page_closure_fails_verification() {
        let tampered = SNAPSHOT_TOML.replacen("unique_keys = 335", "unique_keys = 334", 1);
        assert_ne!(tampered, SNAPSHOT_TOML);
        let error = verify(&tampered, PRISTINE).expect_err("incomplete key closure must fail");
        assert_eq!(error, "language capture closure mismatch");
    }

    #[test]
    fn snapshot_unverified_scope_must_match_community_evidence() {
        let tampered = SNAPSHOT_TOML.replacen("    \"csharpsquid:S2053\",\n", "", 1);
        assert_ne!(tampered, SNAPSHOT_TOML);
        let error = verify(&tampered, PRISTINE).expect_err("changed scope must fail");
        assert_eq!(
            error,
            "snapshot unverified rules differ from Community evidence"
        );
    }
}
