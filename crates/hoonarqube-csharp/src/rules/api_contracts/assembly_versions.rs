use crate::CsLanguage;
use crate::rules::type_members::{assembly_attribute_names, file_level_issue};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3904 — assemblies should state their version.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let names = assembly_attribute_names(root, source);
    if names.is_empty() || names.iter().any(|name| is_assembly_version(name)) {
        return Vec::new();
    }
    vec![file_level_issue(
        language,
        "S3904",
        "Add assembly version information ([assembly: AssemblyVersion(\"1.0.0.0\")]).",
    )]
}

/// Exact CLR assembly-version attribute, accepting its optional conventional
/// `Attribute` suffix. Similar custom names must not suppress the finding.
fn is_assembly_version(name: &str) -> bool {
    name.strip_suffix("Attribute").unwrap_or(name) == "AssemblyVersion"
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3904_accepts_explicit_attribute_suffix() {
        let report = analyze_default(
            "[assembly: System.Reflection.AssemblyVersionAttribute(\"2.0.0.0\")]\nclass A { }\n",
        );
        assert!(with_key(&report, "csharpsquid:S3904").is_empty());
    }

    #[test]
    fn s3904_reports_once_for_several_non_version_attributes() {
        let report = analyze_default(
            "[assembly: System.CLSCompliant(false)]\n[assembly: AssemblyCompany(\"Acme\")]\nclass A { }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3904").len(), 1);
    }

    #[test]
    fn s3904_similarly_named_custom_attributes_do_not_count() {
        let report = analyze_default(
            "[assembly: VersionControl(\"git\")]\n[assembly: ProductVersion(\"2\")]\nclass A { }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3904").len(), 1);
    }
}
