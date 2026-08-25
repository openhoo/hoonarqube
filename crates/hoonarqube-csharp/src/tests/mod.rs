pub(crate) use std::path::PathBuf;

pub(crate) use crate::{AnalyzerOptions, CsLanguage, analyze};
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

mod suite_1_s2386;
mod suite_2_s4260;
mod suite_3_s3329;
mod suite_4_s3464;
