//! Directory inputs without a native analyzer. Native dispatch and scope filters
//! run first. A Community source makes coverage incomplete; an inventory-only
//! file preserves the historical informational row without changing the gate.
use std::path::Path;

pub(super) enum UnsupportedInput {
    CommunitySource,
    InventoryOnly,
}

// Only mappings with indexed public bytes in the current scope reference.
// Extensions listed by an installed plugin without an indexed file are omitted.
const SOURCE_EXTENSIONS: &[(&str, &str)] = &[
    ("as", "flex"),
    ("css", "css"),
    ("ipynb", "ipynb"),
    ("kt", "kotlin"),
    ("kts", "kotlin"),
    ("less", "css"),
    ("php", "php"),
    ("sass", "css"),
    ("scss", "css"),
    ("tf", "terraform"),
    ("vb", "vbnet"),
    ("xml", "xml"),
];

fn source_language(path: &Path) -> Option<&'static str> {
    if path.file_name().is_some_and(|name| name == "Dockerfile") {
        return Some("docker");
    }
    let extension = path.extension()?;
    SOURCE_EXTENSIONS
        .iter()
        .find(|(suffix, _)| extension.eq_ignore_ascii_case(suffix))
        .map(|(_, language)| *language)
}

pub(super) fn classify(path: &Path) -> Option<UnsupportedInput> {
    if source_language(path).is_some() {
        return Some(UnsupportedInput::CommunitySource);
    }
    let extension = path.extension();
    let inventory_suffixes = [
        "cshtml",
        "vbhtml",
        "aspx",
        "ascx",
        "rhtml",
        "erb",
        "cmp",
        "twig",
        "dockerfile",
    ];
    if extension.is_some_and(|ext| {
        inventory_suffixes
            .iter()
            .any(|s| ext.eq_ignore_ascii_case(s))
    }) || path
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("dockerfile"))
    {
        return Some(UnsupportedInput::InventoryOnly);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_source_mapping_has_an_indexed_public_file() {
        let capture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tools/oracle/fixtures/linguist-community-scope-2611.json"
        ))
        .unwrap();
        let indexed = capture["cases"]["mixed"]["indexed"].as_object().unwrap();
        let mut observed = BTreeSet::new();
        for file in capture["files"].as_object().unwrap().keys() {
            let path = Path::new(file);
            if hoonarqube_core::language_for_path(path).is_some() {
                continue;
            }
            assert_eq!(
                source_language(path),
                indexed.get(file).and_then(|v| v.as_str()),
                "{file}"
            );
            if let (Some(language), Some(ext)) = (source_language(path), path.extension()) {
                observed.insert((ext.to_str().unwrap(), language));
            }
        }
        assert_eq!(observed, SOURCE_EXTENSIONS.iter().copied().collect());
    }
}
