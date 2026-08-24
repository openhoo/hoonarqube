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
