use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of, simple_name,
};
use crate::rules::expressions::first_named_child;
use crate::rules::modifiers::{has_any_accessibility, has_modifier};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3887 — `readonly` does not make mutable arrays and
/// collections immutable, so exposing such fields is misleading.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let modifiers = modifiers_of(field, source);
        if !has_modifier(&modifiers, "readonly")
            || !has_any_accessibility(&modifiers)
            || has_modifier(&modifiers, "private")
        {
            continue;
        }
        let Some(type_node) = collect_kinds(field, &["variable_declaration"])
            .first()
            .and_then(|declaration| first_named_child(*declaration))
        else {
            continue;
        };
        let mutable_collection = type_node.kind() == "array_type"
            || MUTABLE_COLLECTION_TYPES.contains(&simple_name(node_text(type_node, source)));
        if mutable_collection {
            let field_name = collect_kinds(field, &["variable_declarator"])
                .first()
                .and_then(|declarator| declarator.child_by_field_name("name"))
                .map_or("field", |name| node_text(name, source));
            issues.push(issue(
                language,
                "S3887",
                format!(
                    "Use an immutable collection or reduce the accessibility of the non-private readonly field '{field_name}'."
                ),
                range_of(type_node, source),
            ));
        }
    }
    issues
}

const MUTABLE_COLLECTION_TYPES: [&str; 14] = [
    "ICollection",
    "IList",
    "IDictionary",
    "List",
    "Dictionary",
    "HashSet",
    "SortedSet",
    "SortedList",
    "SortedDictionary",
    "Queue",
    "Stack",
    "LinkedList",
    "Collection",
    "ObservableCollection",
];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3887_flags_exposed_readonly_arrays_and_mutable_collections() {
        let report = analyze_default(
            "class A\n{\n    public readonly string[] labels;\n    protected readonly List<int> values = new();\n    internal readonly Dictionary<string, int> lookup = new();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3887");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 4);
        assert_eq!(flagged[2].range.start.line, 5);
    }

    #[test]
    fn s3887_spares_private_mutable_fields_and_readonly_values() {
        let report = analyze_default(
            "class A\n{\n    private readonly string[] labels = [];\n    public string[] mutable = [];\n    public readonly int limit = 10;\n    public readonly string name = \"gate\";\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3887").is_empty());
    }
}
