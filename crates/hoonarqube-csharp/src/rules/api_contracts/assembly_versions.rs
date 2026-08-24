use crate::CsLanguage;
use crate::rules::type_members::{assembly_attribute_names, file_level_issue};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3904 — assemblies should state their version.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let names = assembly_attribute_names(root, source);
    if names.is_empty()
        || names
            .iter()
            .any(|name| name.to_ascii_lowercase().contains("version"))
    {
        return Vec::new();
    }
    vec![file_level_issue(
        language,
        "S3904",
        "Add assembly version information ([assembly: AssemblyVersion(\"1.0.0.0\")]).",
    )]
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3904_version_match_is_case_insensitive() {
        let report = analyze_default("[assembly: assemblyversion(\"2.0.0.0\")]\nclass A { }\n");
        assert!(with_key(&report, "csharpsquid:S3904").is_empty());
    }

    #[test]
    fn s3904_reports_once_for_several_non_version_attributes() {
        let report = analyze_default(
            "[assembly: System.CLSCompliant(false)]\n[assembly: AssemblyCompany(\"Acme\")]\nclass A { }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3904").len(), 1);
    }
}
