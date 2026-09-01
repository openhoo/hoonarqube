//! Language-registry facade: the single source of truth mapping a source
//! file to its analyzer by extension.
//!
//! Consumers (the CLI) dispatch through [`language_for_path`] and
//! [`analyze`] instead of duplicating extension tables per crate;
//! hoonarqube-bench drives the per-language analyzer crates directly to
//! isolate per-analyzer throughput.

use std::path::Path;

use hoonarqube_csharp::CsLanguage;
use hoonarqube_jsts::JstsLanguage;

pub use hoonarqube_catalog::RuleProfile;

/// Languages the registry can analyze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    CSharp,
    Go,
    Rust,
}

/// Extension table; matched case-insensitively so `.PY`/`.CS` style inputs
/// resolve like their lowercase forms.
const EXTENSIONS: &[(&str, Language)] = &[
    ("py", Language::Python),
    ("js", Language::JavaScript),
    ("jsx", Language::JavaScript),
    ("mjs", Language::JavaScript),
    ("cjs", Language::JavaScript),
    ("ts", Language::TypeScript),
    ("tsx", Language::TypeScript),
    ("mts", Language::TypeScript),
    ("cts", Language::TypeScript),
    ("cs", Language::CSharp),
    ("go", Language::Go),
    ("rs", Language::Rust),
];

/// Maps a bare file extension to its language; matched case-insensitively
/// so `PY` resolves like `py`. `None` when no analyzer claims the extension.
///
/// Single source of truth for the workspace: analyzer-crate tests resolve
/// their extensions through this function instead of private tables.
#[must_use]
pub fn language_for_extension(ext: &str) -> Option<Language> {
    let (_, language) = EXTENSIONS
        .iter()
        .find(|(candidate, _)| ext.eq_ignore_ascii_case(candidate))?;
    Some(*language)
}

/// Maps a file path to its language by extension; `None` when no analyzer
/// claims the extension.
#[must_use]
pub fn language_for_path(path: &Path) -> Option<Language> {
    let ext = path.extension()?.to_str()?;
    language_for_extension(ext)
}

/// C# analyzer knobs, re-exported for consumers constructing [`AnalyzerOptions`] field-by-field.
pub use hoonarqube_csharp::AnalyzerOptions as CSharpAnalyzerOptions;
/// Go analyzer knobs, re-exported for consumers constructing [`AnalyzerOptions`] field-by-field.
pub use hoonarqube_go::AnalyzerOptions as GoAnalyzerOptions;
/// JavaScript/TypeScript analyzer knobs, re-exported for consumers constructing [`AnalyzerOptions`] field-by-field.
pub use hoonarqube_jsts::AnalyzerOptions as JstsAnalyzerOptions;
/// Python analyzer knobs, re-exported for consumers constructing [`AnalyzerOptions`] field-by-field.
pub use hoonarqube_python::AnalyzerOptions as PythonAnalyzerOptions;
/// Rust analyzer knobs, re-exported for consumers constructing [`AnalyzerOptions`] field-by-field.
pub use hoonarqube_rust::AnalyzerOptions as RustAnalyzerOptions;

/// Per-language analyzer knobs; [`Default`] matches each analyzer crate's
/// default configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    /// Native-rule profile. `sonar-parity` preserves the historical frozen
    /// Sonar behavior and is the library default.
    pub profile: RuleProfile,
    pub python: hoonarqube_python::AnalyzerOptions,
    pub jsts: hoonarqube_jsts::AnalyzerOptions,
    pub csharp: hoonarqube_csharp::AnalyzerOptions,
    pub go: hoonarqube_go::AnalyzerOptions,
    pub rust: hoonarqube_rust::AnalyzerOptions,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            profile: RuleProfile::SonarParity,
            python: hoonarqube_python::AnalyzerOptions::default(),
            jsts: hoonarqube_jsts::AnalyzerOptions::default(),
            csharp: hoonarqube_csharp::AnalyzerOptions::default(),
            go: hoonarqube_go::AnalyzerOptions::default(),
            rust: hoonarqube_rust::AnalyzerOptions::default(),
        }
    }
}

/// Analyzes one source file with the analyzer registered for its extension.
///
/// Returns `None` when no analyzer claims the file's extension (see
/// [`language_for_path`]); otherwise every analyzer returns a complete
/// [`hoonarqube_ir::FileReport`] whose `language` field carries the catalog
/// repository prefix.
#[must_use]
pub fn analyze(
    path: &Path,
    source: &str,
    options: &AnalyzerOptions,
) -> Option<hoonarqube_ir::FileReport> {
    let language = language_for_path(path)?;
    let path = path.to_path_buf();
    let mut report = match language {
        Language::Python => hoonarqube_python::analyze(path, source, &options.python),
        Language::JavaScript => {
            hoonarqube_jsts::analyze(path, source, JstsLanguage::JavaScript, &options.jsts)
        }
        Language::TypeScript => {
            hoonarqube_jsts::analyze(path, source, JstsLanguage::TypeScript, &options.jsts)
        }
        Language::CSharp => {
            hoonarqube_csharp::analyze(path, source, CsLanguage::CSharp, &options.csharp)
        }
        Language::Go => hoonarqube_go::analyze(path, source, &options.go),
        Language::Rust => hoonarqube_rust::analyze(path, source, &options.rust),
    };
    if options.profile != RuleProfile::SonarParity {
        let mut native = match language {
            Language::Python => hoonarqube_python::analyze_native(source),
            Language::JavaScript => {
                hoonarqube_jsts::analyze_native(source, JstsLanguage::JavaScript)
            }
            Language::TypeScript => {
                hoonarqube_jsts::analyze_native(source, JstsLanguage::TypeScript)
            }
            Language::CSharp => hoonarqube_csharp::analyze_native(source),
            Language::Go => hoonarqube_go::analyze_native(source),
            Language::Rust => hoonarqube_rust::analyze_native(source),
        };
        debug_assert!(
            native
                .iter()
                .all(|issue| { hoonarqube_catalog::native_rule(&issue.rule_key).is_some() })
        );
        native.retain(|issue| {
            hoonarqube_catalog::native_rule(&issue.rule_key)
                .is_some_and(|rule| options.profile.includes(rule.minimum_profile))
        });
        report.issues.extend(native);
        hoonarqube_ir::sort_issues(&mut report.issues);
        report.issues.dedup();
    }
    Some(report)
}

#[cfg(test)]
mod tests {
    use super::{AnalyzerOptions, EXTENSIONS, Language, RuleProfile, analyze, language_for_path};
    use std::collections::HashSet;
    use std::path::Path;

    #[test]
    fn every_supported_extension_maps_to_its_language() {
        let cases = [
            ("py", Language::Python),
            ("js", Language::JavaScript),
            ("jsx", Language::JavaScript),
            ("mjs", Language::JavaScript),
            ("cjs", Language::JavaScript),
            ("ts", Language::TypeScript),
            ("tsx", Language::TypeScript),
            ("mts", Language::TypeScript),
            ("cts", Language::TypeScript),
            ("cs", Language::CSharp),
            ("go", Language::Go),
            ("rs", Language::Rust),
        ];
        for (ext, expected) in cases {
            let file = format!("src/module.{ext}");
            let path = Path::new(&file);
            assert_eq!(language_for_path(path), Some(expected), "extension {ext}");
        }
    }

    #[test]
    fn extension_registry_has_unique_canonical_keys_and_claims_every_language() {
        let mut extensions = HashSet::new();
        let mut languages = HashSet::new();
        for (extension, language) in EXTENSIONS {
            assert!(!extension.is_empty());
            assert!(extension.bytes().all(|byte| byte.is_ascii_lowercase()));
            assert!(
                extensions.insert(*extension),
                "duplicate extension {extension}"
            );
            languages.insert(*language);
        }
        assert_eq!(languages.len(), 6, "every language needs an extension");
    }

    #[test]
    fn extensions_match_case_insensitively() {
        assert_eq!(
            language_for_path(Path::new("SCRIPT.PY")),
            Some(Language::Python)
        );
        assert_eq!(
            language_for_path(Path::new("Widget.CS")),
            Some(Language::CSharp)
        );
    }

    #[test]
    fn unclaimed_paths_yield_none() {
        assert_eq!(language_for_path(Path::new("notes.txt")), None);
        assert_eq!(language_for_path(Path::new("Makefile")), None);
        assert_eq!(
            analyze(Path::new("notes.txt"), "x", &AnalyzerOptions::default()),
            None
        );
    }

    #[test]
    fn python_analyzer_runs_through_the_registry() {
        let report = analyze(
            Path::new("app.py"),
            "x = 1  # NOSONAR\n",
            &AnalyzerOptions::default(),
        )
        .unwrap();
        assert_eq!(report.language, "python");
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn javascript_analyzer_runs_through_the_registry() {
        let report = analyze(
            Path::new("a.js"),
            "eval('x');\n",
            &AnalyzerOptions::default(),
        )
        .unwrap();
        assert_eq!(report.language, "javascript");
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn typescript_analyzer_runs_through_the_registry() {
        let report = analyze(
            Path::new("a.ts"),
            "eval('x');\n",
            &AnalyzerOptions::default(),
        )
        .unwrap();
        assert_eq!(report.language, "typescript");
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn csharp_analyzer_runs_through_the_registry() {
        let report = analyze(
            Path::new("A.cs"),
            "\tint x;\nclass A\n{\n}\n",
            &AnalyzerOptions::default(),
        )
        .unwrap();
        assert_eq!(report.language, "csharpsquid");
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn go_analyzer_runs_through_the_registry() {
        let report = analyze(
            Path::new("main.go"),
            "package p\nfunc bad_name() {}\n",
            &AnalyzerOptions::default(),
        )
        .unwrap();
        assert_eq!(report.language, "go");
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn rust_analyzer_runs_through_the_registry() {
        let report = analyze(
            Path::new("main.rs"),
            "fn main() { println!(\"hello\"); }\n",
            &AnalyzerOptions::default(),
        )
        .unwrap();
        assert_eq!(report.language, "rust");
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn default_options_match_per_crate_defaults() {
        let options = AnalyzerOptions::default();
        assert_eq!(options.profile, RuleProfile::SonarParity);
        assert_eq!(
            options.python,
            hoonarqube_python::AnalyzerOptions::default()
        );
        assert_eq!(options.jsts, hoonarqube_jsts::AnalyzerOptions::default());
        assert_eq!(
            options.csharp,
            hoonarqube_csharp::AnalyzerOptions::default()
        );
        assert_eq!(options.go, hoonarqube_go::AnalyzerOptions::default());
        assert_eq!(options.rust, hoonarqube_rust::AnalyzerOptions::default());
    }

    #[test]
    fn profile_filter_keeps_sonar_parity_and_enables_cumulative_native_rules() {
        let source = concat!(
            "package p\n",
            "import (\"os\"; \"sync\")\n",
            "func f() { var wg sync.WaitGroup; go func() { wg.Add(1) }(); mu.Lock(); mu.Unlock(); os.Create(\"x\") }\n",
        );
        let parity = analyze(Path::new("main.go"), source, &AnalyzerOptions::default()).unwrap();
        assert!(
            parity
                .issues
                .iter()
                .all(|issue| !issue.rule_key.starts_with("hoonarqube-"))
        );

        let recommended = analyze(
            Path::new("main.go"),
            source,
            &AnalyzerOptions {
                profile: RuleProfile::Recommended,
                ..AnalyzerOptions::default()
            },
        )
        .unwrap();
        assert!(
            recommended
                .issues
                .iter()
                .any(|issue| issue.rule_key == "hoonarqube-go:SA2000")
        );
        assert!(
            recommended
                .issues
                .iter()
                .all(|issue| issue.rule_key != "hoonarqube-go:SA2001")
        );

        let extended = analyze(
            Path::new("main.go"),
            source,
            &AnalyzerOptions {
                profile: RuleProfile::Extended,
                ..AnalyzerOptions::default()
            },
        )
        .unwrap();
        assert!(
            extended
                .issues
                .iter()
                .any(|issue| issue.rule_key == "hoonarqube-go:SA2001")
        );
        assert!(
            extended
                .issues
                .iter()
                .all(|issue| issue.rule_key != "hoonarqube-go:G307")
        );

        let strict = analyze(
            Path::new("main.go"),
            source,
            &AnalyzerOptions {
                profile: RuleProfile::Strict,
                ..AnalyzerOptions::default()
            },
        )
        .unwrap();
        assert!(
            strict
                .issues
                .iter()
                .any(|issue| issue.rule_key == "hoonarqube-go:G307")
        );
    }
}
