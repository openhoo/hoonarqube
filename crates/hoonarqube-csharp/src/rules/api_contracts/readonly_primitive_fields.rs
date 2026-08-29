use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of, simple_name,
};
use crate::rules::expressions::first_named_child;
use crate::rules::modifiers::{has_any_accessibility, has_modifier};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3887 — `readonly` does not make mutable arrays and
/// collections immutable, so exposing such fields is misleading.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let declared_types = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let modifiers = modifiers_of(field, source);
        if !has_modifier(&modifiers, "readonly")
            || !has_any_accessibility(&modifiers)
            || is_private_only(&modifiers)
        {
            continue;
        }
        let Some(type_node) = collect_kinds(field, &["variable_declaration"])
            .first()
            .and_then(|declaration| first_named_child(*declaration))
        else {
            continue;
        };
        let mutable_collection = is_mutable_collection(type_node, source, &declared_types);
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

fn is_private_only(modifiers: &[&str]) -> bool {
    has_modifier(modifiers, "private") && !has_modifier(modifiers, "protected")
}

fn is_mutable_collection(type_node: Node<'_>, source: &str, declared_types: &[Node<'_>]) -> bool {
    if type_node.kind() == "array_type" {
        return true;
    }
    let type_text = node_text(type_node, source)
        .trim()
        .trim_start_matches("global::");
    let base = type_text
        .split('<')
        .next()
        .unwrap_or(type_text)
        .trim_end_matches('?');
    let simple = simple_name(base);
    if !MUTABLE_COLLECTION_TYPES.contains(&simple) {
        return false;
    }
    let Some((namespace, _)) = base.rsplit_once('.') else {
        return !is_shadowed_type(type_node, source, simple, declared_types);
    };
    MUTABLE_COLLECTION_NAMESPACES.contains(&namespace)
}

fn is_shadowed_type(
    use_site: Node<'_>,
    source: &str,
    wanted: &str,
    declarations: &[Node<'_>],
) -> bool {
    let use_scope = containing_scope(use_site, source);
    declarations.iter().any(|declaration| {
        declaration
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == wanted)
            && use_scope.starts_with(&containing_scope(*declaration, source))
    })
}

fn containing_scope<'a>(mut node: Node<'_>, source: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut scope = Vec::new();
    while let Some(parent) = node.parent() {
        if (TYPE_DECLARATION_KINDS.contains(&parent.kind())
            || parent.kind() == "namespace_declaration")
            && let Some(name) = parent.child_by_field_name("name")
        {
            scope.push((parent.kind(), node_text(name, source)));
        }
        node = parent;
    }
    scope.reverse();
    scope
}

const MUTABLE_COLLECTION_TYPES: [&str; 20] = [
    "ICollection",
    "IList",
    "IDictionary",
    "ISet",
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
    "BlockingCollection",
    "ConcurrentBag",
    "ConcurrentDictionary",
    "ConcurrentQueue",
    "ConcurrentStack",
];

const MUTABLE_COLLECTION_NAMESPACES: [&str; 3] = [
    "System.Collections",
    "System.Collections.Generic",
    "System.Collections.Concurrent",
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

    #[test]
    fn s3887_handles_combined_accessibility_and_collection_identity() {
        let report = analyze_default(
            "namespace Custom { class List<T> { } }\nclass List<T> { }\nclass A\n{\n    private protected readonly int[] inherited = [];\n    public readonly System.Collections.Generic.List<int> system = new();\n    public readonly Custom.List<int> qualifiedCustom = new();\n    public readonly List<int> shadowed = new();\n    public readonly System.Collections.Concurrent.ConcurrentQueue<int> queue = new();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3887");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
        assert_eq!(flagged[2].range.start.line, 9);
    }
}
