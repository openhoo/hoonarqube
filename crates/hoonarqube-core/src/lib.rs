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
    Java,
    Rust,
    Ruby,
}

/// Deterministic GitHub Code Quality registry grouped by catalog family.
///
/// JavaScript and TypeScript intentionally share one family and one analyzer
/// registry. Rust is absent because it has no GitHub Code Quality IDs.
pub const GITHUB_QUALITY_RULES_BY_FAMILY: &[(
    hoonarqube_catalog::github_quality::LanguageFamily,
    &[&str],
)] = &[
    (
        hoonarqube_catalog::github_quality::LanguageFamily::CSharp,
        hoonarqube_csharp::GITHUB_QUALITY_RULE_IDS,
    ),
    (
        hoonarqube_catalog::github_quality::LanguageFamily::Go,
        hoonarqube_go::GITHUB_QUALITY_RULE_IDS,
    ),
    (
        hoonarqube_catalog::github_quality::LanguageFamily::Java,
        hoonarqube_java::GITHUB_QUALITY_RULE_IDS,
    ),
    (
        hoonarqube_catalog::github_quality::LanguageFamily::JavaScriptTypeScript,
        hoonarqube_jsts::GITHUB_QUALITY_RULE_IDS,
    ),
    (
        hoonarqube_catalog::github_quality::LanguageFamily::Python,
        hoonarqube_python::GITHUB_QUALITY_RULE_IDS,
    ),
    (
        hoonarqube_catalog::github_quality::LanguageFamily::Ruby,
        hoonarqube_ruby::GITHUB_QUALITY_RULE_IDS,
    ),
];

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
    ("java", Language::Java),
    ("rs", Language::Rust),
    ("rb", Language::Ruby),
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
/// Java analyzer knobs, re-exported for consumers constructing [`AnalyzerOptions`] field-by-field.
pub use hoonarqube_java::AnalyzerOptions as JavaAnalyzerOptions;
/// JavaScript/TypeScript analyzer knobs, re-exported for consumers constructing [`AnalyzerOptions`] field-by-field.
pub use hoonarqube_jsts::AnalyzerOptions as JstsAnalyzerOptions;
/// Python analyzer knobs, re-exported for consumers constructing [`AnalyzerOptions`] field-by-field.
pub use hoonarqube_python::AnalyzerOptions as PythonAnalyzerOptions;
/// Ruby analyzer knobs, re-exported for consumers constructing [`AnalyzerOptions`] field-by-field.
pub use hoonarqube_ruby::AnalyzerOptions as RubyAnalyzerOptions;
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
    pub java: hoonarqube_java::AnalyzerOptions,
    pub rust: hoonarqube_rust::AnalyzerOptions,
    pub ruby: hoonarqube_ruby::AnalyzerOptions,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            profile: RuleProfile::SonarParity,
            python: hoonarqube_python::AnalyzerOptions::default(),
            jsts: hoonarqube_jsts::AnalyzerOptions::default(),
            csharp: hoonarqube_csharp::AnalyzerOptions::default(),
            go: hoonarqube_go::AnalyzerOptions::default(),
            java: hoonarqube_java::AnalyzerOptions::default(),
            rust: hoonarqube_rust::AnalyzerOptions::default(),
            ruby: hoonarqube_ruby::AnalyzerOptions::default(),
        }
    }
}

/// Analyzes one source file with the analyzer registered for its extension.
///
/// Returns `None` when no analyzer claims the file's extension (see
/// [`language_for_path`]); otherwise every analyzer returns a complete
/// [`hoonarqube_ir::FileReport`] whose `language` field carries the catalog
/// repository prefix.
///
/// # Panics
///
/// Panics if a GitHub Code Quality analyzer violates its internal registry
/// contract by emitting an unknown or wrong-language query ID.
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
        Language::Java => hoonarqube_java::analyze(path, source, &options.java),
        Language::Rust => hoonarqube_rust::analyze(path, source, &options.rust),
        Language::Ruby => hoonarqube_ruby::analyze(path, source, &options.ruby),
    };
    if options.profile == RuleProfile::GithubCodeQuality {
        let family = github_family(language);
        let github = match language {
            Language::Python => hoonarqube_python::analyze_github_quality(source),
            Language::JavaScript => {
                hoonarqube_jsts::analyze_github_quality(source, JstsLanguage::JavaScript)
            }
            Language::TypeScript => {
                hoonarqube_jsts::analyze_github_quality(source, JstsLanguage::TypeScript)
            }
            Language::CSharp => hoonarqube_csharp::analyze_github_quality(source),
            Language::Go => hoonarqube_go::analyze_github_quality(source),
            Language::Java => hoonarqube_java::analyze_github_quality(source),
            Language::Rust => Vec::new(),
            Language::Ruby => hoonarqube_ruby::analyze_github_quality(source),
        };
        // Never hide registry drift in release builds. An invalid or
        // wrong-family ID is a production integrity failure, not a finding
        // to silently discard.
        assert!(
            github.iter().all(|issue| {
                hoonarqube_catalog::github_quality::query(&issue.rule_key)
                    .is_some_and(|query| family == Some(query.language))
            }),
            "GitHub Code Quality analyzer emitted an unknown or wrong-family rule ID"
        );
        report.issues = github;

        hoonarqube_ir::sort_issues(&mut report.issues);
        report.issues.dedup();
    } else if options.profile != RuleProfile::SonarParity {
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
            Language::Java | Language::Ruby => Vec::new(),
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

fn github_family(language: Language) -> Option<hoonarqube_catalog::github_quality::LanguageFamily> {
    use hoonarqube_catalog::github_quality::LanguageFamily;

    match language {
        Language::CSharp => Some(LanguageFamily::CSharp),
        Language::Go => Some(LanguageFamily::Go),
        Language::Java => Some(LanguageFamily::Java),
        Language::JavaScript | Language::TypeScript => Some(LanguageFamily::JavaScriptTypeScript),
        Language::Python => Some(LanguageFamily::Python),
        Language::Ruby => Some(LanguageFamily::Ruby),
        Language::Rust => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AnalyzerOptions, EXTENSIONS, GITHUB_QUALITY_RULES_BY_FAMILY, Language, RuleProfile,
        analyze, language_for_path,
    };
    use std::collections::{BTreeSet, HashSet};
    use std::path::Path;

    #[test]
    fn github_quality_registry_is_sorted_unique_and_family_complete() {
        let mut all_ids = BTreeSet::new();
        for (family, ids) in GITHUB_QUALITY_RULES_BY_FAMILY {
            assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
            for id in *ids {
                assert!(all_ids.insert(*id), "duplicate GitHub rule ID {id}");
                let definition = hoonarqube_catalog::github_quality::query(id)
                    .unwrap_or_else(|| panic!("unknown GitHub rule ID {id}"));
                assert_eq!(definition.language, *family);
            }
        }
        assert_eq!(all_ids.len(), 54);
        assert_eq!(
            GITHUB_QUALITY_RULES_BY_FAMILY
                .iter()
                .map(|(_, ids)| ids.len())
                .collect::<Vec<_>>(),
            vec![13, 5, 15, 13, 5, 3]
        );
    }
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
            ("java", Language::Java),
            ("rb", Language::Ruby),
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
        assert_eq!(languages.len(), 8, "every language needs an extension");
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
        assert_eq!(
            language_for_path(Path::new("Main.JAVA")),
            Some(Language::Java)
        );
        assert_eq!(
            language_for_path(Path::new("model.RB")),
            Some(Language::Ruby)
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
    fn java_analyzer_runs_through_the_registry() {
        let report = analyze(
            Path::new("Main.java"),
            "class Main {}\n",
            &AnalyzerOptions::default(),
        )
        .unwrap();
        assert_eq!(report.language, "java");
    }

    #[test]
    fn ruby_analyzer_runs_through_the_registry() {
        let report = analyze(
            Path::new("main.rb"),
            "value = 1\n",
            &AnalyzerOptions::default(),
        )
        .unwrap();
        assert_eq!(report.language, "ruby");
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
        assert_eq!(options.java, hoonarqube_java::AnalyzerOptions::default());
        assert_eq!(options.rust, hoonarqube_rust::AnalyzerOptions::default());
        assert_eq!(options.ruby, hoonarqube_ruby::AnalyzerOptions::default());
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

    #[test]
    fn github_profile_isolated_and_covers_every_catalog_family() {
        let options = AnalyzerOptions {
            profile: RuleProfile::GithubCodeQuality,
            ..AnalyzerOptions::default()
        };
        let cases = [
            (
                "sample.cs",
                "using System; class C { void M() { GC.Collect(); } }",
                "cs/",
            ),
            (
                "sample.go",
                "package p\nfunc f(x int) { if x == 1 {} else if (x == 1) {} }\n",
                "go/",
            ),
            (
                "sample.java",
                "class Main { void f() { new String(\"x\"); } }\n",
                "java/",
            ),
            ("sample.js", "/*@cc_on @*/\n", "js/"),
            ("sample.ts", "const n: number = 1; n = 2;\n", "js/"),
            ("sample.py", "global value\n", "py/"),
            ("sample.rb", "def f\n  value.length\nend\n", "rb/"),
        ];
        for (path, source, prefix) in cases {
            let report = analyze(Path::new(path), source, &options).unwrap();
            assert!(
                !report.issues.is_empty(),
                "{path} should produce a GitHub Code Quality finding"
            );
            assert!(report.issues.iter().all(|issue| {
                issue.rule_key.starts_with(prefix)
                    && hoonarqube_catalog::github_quality::query(&issue.rule_key).is_some()
            }));
            let mut unique = report.issues.clone();
            unique.dedup();
            assert_eq!(unique.len(), report.issues.len());
        }
        let rust = analyze(Path::new("sample.rs"), "fn main() {}\n", &options).unwrap();
        assert!(rust.issues.is_empty());
    }
}
