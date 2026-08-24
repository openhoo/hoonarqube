//! Language-registry facade: the single source of truth mapping a source
//! file to its analyzer by extension.
//!
//! Consumers (CLI, bench) dispatch through [`language_for_path`] and
//! [`analyze`] instead of duplicating extension tables per crate.

use std::path::Path;

use hoonarqube_csharp::CsLanguage;
use hoonarqube_jsts::JstsLanguage;

/// Languages the registry can analyze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    CSharp,
}

impl Language {
    /// Catalog repository prefix used in issue `rule_key`s (e.g.
    /// `python:S1481`, `csharpsquid:S103`).
    #[must_use]
    pub fn repository_prefix(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::CSharp => "csharpsquid",
        }
    }
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
];

/// Maps a file path to its language by extension; `None` when no analyzer
/// claims the extension.
#[must_use]
pub fn language_for_path(path: &Path) -> Option<Language> {
    let ext = path.extension()?.to_str()?;
    let (_, language) = EXTENSIONS
        .iter()
        .find(|(candidate, _)| ext.eq_ignore_ascii_case(candidate))?;
    Some(*language)
}

/// Per-language analyzer knobs; [`Default`] matches each analyzer crate's
/// default configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalyzerOptions {
    pub python: hoonarqube_python::AnalyzerOptions,
    pub jsts: hoonarqube_jsts::AnalyzerOptions,
    pub csharp: hoonarqube_csharp::AnalyzerOptions,
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
    let report = match language_for_path(path)? {
        Language::Python => hoonarqube_python::analyze(path.to_path_buf(), source, &options.python),
        Language::JavaScript => hoonarqube_jsts::analyze(
            path.to_path_buf(),
            source,
            JstsLanguage::JavaScript,
            &options.jsts,
        ),
        Language::TypeScript => hoonarqube_jsts::analyze(
            path.to_path_buf(),
            source,
            JstsLanguage::TypeScript,
            &options.jsts,
        ),
        Language::CSharp => hoonarqube_csharp::analyze(
            path.to_path_buf(),
            source,
            CsLanguage::CSharp,
            &options.csharp,
        ),
    };
    Some(report)
}

#[cfg(test)]
mod tests {
    use super::{AnalyzerOptions, Language, analyze, language_for_path};
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
        ];
        for (ext, expected) in cases {
            let file = format!("src/module.{ext}");
            let path = Path::new(&file);
            assert_eq!(language_for_path(path), Some(expected), "extension {ext}");
        }
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
    fn repository_prefixes_match_the_frozen_catalog() {
        assert_eq!(Language::Python.repository_prefix(), "python");
        assert_eq!(Language::JavaScript.repository_prefix(), "javascript");
        assert_eq!(Language::TypeScript.repository_prefix(), "typescript");
        assert_eq!(Language::CSharp.repository_prefix(), "csharpsquid");
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
            "print('hi')\n",
            &AnalyzerOptions::default(),
        )
        .unwrap();
        assert_eq!(report.language, Language::Python.repository_prefix());
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
        assert_eq!(report.language, Language::JavaScript.repository_prefix());
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
        assert_eq!(report.language, Language::TypeScript.repository_prefix());
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
        assert_eq!(report.language, Language::CSharp.repository_prefix());
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn default_options_match_per_crate_defaults() {
        let options = AnalyzerOptions::default();
        assert_eq!(
            options.python,
            hoonarqube_python::AnalyzerOptions::default()
        );
        assert_eq!(options.jsts, hoonarqube_jsts::AnalyzerOptions::default());
        assert_eq!(
            options.csharp,
            hoonarqube_csharp::AnalyzerOptions::default()
        );
    }
}
