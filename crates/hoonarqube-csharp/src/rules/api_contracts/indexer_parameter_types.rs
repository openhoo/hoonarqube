use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3876 — indexers on other types read as opaque lookups.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["indexer_declaration"])
        .into_iter()
        .filter(|indexer| !is_error_tainted(*indexer))
        .filter_map(|indexer| {
            let list = indexer.child_by_field_name("parameters")?;
            parameters_from_list(list)
                .into_iter()
                .filter_map(|parameter| parameter.child_by_field_name("type"))
                .find(|type_node| {
                    !INDEXER_PARAMETER_TYPES.contains(&simple_name(node_text(*type_node, source)))
                })
        })
        .map(|type_node| {
            issue(
                language,
                "S3876",
                "Use string, integral, index or range type here, or refactor this indexer into a method.",
                range_of(type_node, source),
            )
        })
        .collect()
}

/// Types acceptable for indexer parameters.
const INDEXER_PARAMETER_TYPES: [&str; 12] = [
    "string", "String", "int", "uint", "long", "ulong", "short", "ushort", "byte", "sbyte", "char",
    "nint",
];

/// Parameters behind either bracketed or parenthesized lists.
fn parameters_from_list(list: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(list, &["parameter"])
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3876_integer_aliases_and_string_class_are_accepted() {
        let report = analyze_default(
            "class Grid\n{\n    public int this[long offset] => 0;\n    public int this[String key] => 1;\n    public int this[char digit] => 2;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3876").is_empty());
    }

    #[test]
    fn s3876_reports_once_per_indexer_despite_several_bad_parameters() {
        let report = analyze_default(
            "class Grid\n{\n    public int this[double ratio, System.DateTime when] => 0;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3876").len(), 1);
    }
}
