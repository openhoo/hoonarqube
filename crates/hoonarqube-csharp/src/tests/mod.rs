pub(crate) use std::path::PathBuf;

pub(crate) use crate::{AnalyzerOptions, CsLanguage, analyze, retain_test_scope_issues};
pub(crate) use hoonarqube_core::{Language, language_for_extension};

pub(crate) fn with_key<'a>(
    report: &'a hoonarqube_ir::FileReport,
    key: &str,
) -> Vec<&'a hoonarqube_ir::Issue> {
    report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == key)
        .collect()
}

pub(crate) fn analyze_options(
    source: &str,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    analyze(PathBuf::from("t.cs"), source, CsLanguage::CSharp, options)
}

pub(crate) fn analyze_default(source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from("t.cs"),
        source,
        CsLanguage::CSharp,
        &AnalyzerOptions::default(),
    )
}

/// Like [`analyze_default`], but inside the conventional `tests/` directory
/// scope (csharpsquid TEST-scope rules apply, MAIN-scope rules are dropped).
pub(crate) fn analyze_test_default(source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from("tests/t.cs"),
        source,
        CsLanguage::CSharp,
        &AnalyzerOptions::default(),
    )
}

mod suite_10_realworld_s341_350;
mod suite_1_s2386;
mod suite_2_s4260;
mod suite_3_s3329;
mod suite_4_s3464;
mod suite_5_s3776;
mod suite_6_s4019_cross_file;
mod suite_7_local_shadows_partials;
mod suite_8_parser_recovery;
mod suite_9_realworld_s329_333;
