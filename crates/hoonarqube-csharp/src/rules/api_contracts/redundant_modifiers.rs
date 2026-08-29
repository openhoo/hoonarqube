use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::{accessibility_rank, has_modifier};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::{accessors_of, name_anchor};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2333 — single-part `partial` types and accessors repeating
/// their property's visibility carry dead modifiers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = redundant_partial_issues(root, source, language);
    issues.extend(redundant_sealed_issues(root, source, language));
    issues.extend(redundant_unsafe_issues(root, source, language));
    issues.extend(redundant_accessor_issues(root, source, language));
    issues
}

fn redundant_partial_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    use std::collections::BTreeMap;
    let declarations = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    let file_namespace = collect_kinds(root, &["file_scoped_namespace_declaration"])
        .first()
        .and_then(|namespace| namespace.child_by_field_name("name"));
    let mut name_counts = BTreeMap::new();
    for type_node in &declarations {
        let key = partial_identity(*type_node, file_namespace, source);
        *name_counts.entry(key).or_insert(0) += 1;
    }
    let mut issues = Vec::new();
    for type_node in &declarations {
        if is_error_tainted(*type_node)
            || !has_modifier(&modifiers_of(*type_node, source), "partial")
        {
            continue;
        }
        let key = partial_identity(*type_node, file_namespace, source);
        if name_counts.get(&key).copied().unwrap_or(0) == 1 {
            issues.push(issue(
                language,
                "S2333",
                "'partial' is gratuitous in this context.",
                modifier_range(*type_node, source, "partial")
                    .unwrap_or_else(|| range_of(name_anchor(*type_node), source)),
            ));
        }
    }
    issues
}

fn partial_identity<'a>(
    type_node: Node<'_>,
    file_namespace: Option<Node<'_>>,
    source: &'a str,
) -> Vec<(&'static str, &'a str, usize)> {
    let mut identity = file_namespace
        .map(|name| {
            vec![(
                "file_scoped_namespace_declaration",
                node_text(name, source),
                0,
            )]
        })
        .unwrap_or_default();
    let mut ancestors: Vec<Node<'_>> = std::iter::successors(type_node.parent(), Node::parent)
        .filter(|ancestor| {
            ancestor.kind() == "namespace_declaration"
                || TYPE_DECLARATION_KINDS.contains(&ancestor.kind())
        })
        .collect();
    ancestors.reverse();
    for ancestor in ancestors {
        identity.push(type_identity_segment(ancestor, source));
    }
    identity.push(type_identity_segment(type_node, source));
    identity
}

fn type_identity_segment<'a>(node: Node<'_>, source: &'a str) -> (&'static str, &'a str, usize) {
    let name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
        .unwrap_or_default();
    let arity = direct_child(node, "type_parameter_list").map_or(0, |parameters| {
        let mut cursor = parameters.walk();
        parameters
            .children(&mut cursor)
            .filter(|parameter| parameter.kind() == "type_parameter")
            .count()
    });
    (node.kind(), name, arity)
}

fn redundant_sealed_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in collect_kinds(
        root,
        &[
            "method_declaration",
            "property_declaration",
            "indexer_declaration",
            "event_declaration",
            "event_field_declaration",
        ],
    ) {
        if !has_modifier(&modifiers_of(member, source), "sealed") {
            continue;
        }
        let owner = std::iter::successors(member.parent(), Node::parent)
            .find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()));
        if owner.is_some_and(|owner| has_modifier(&modifiers_of(owner, source), "sealed"))
            && let Some(range) = modifier_range(member, source, "sealed")
        {
            issues.push(issue(
                language,
                "S2333",
                "'sealed' is redundant in a sealed type.",
                range,
            ));
        }
    }
    issues
}

fn redundant_unsafe_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(
        root,
        &[
            "method_declaration",
            "constructor_declaration",
            "operator_declaration",
            "conversion_operator_declaration",
        ],
    ) {
        if has_modifier(&modifiers_of(declaration, source), "unsafe")
            && (has_unsafe_context(declaration, source)
                || !contains_unsafe_construct(declaration, source))
            && let Some(range) = modifier_range(declaration, source, "unsafe")
        {
            issues.push(issue(
                language,
                "S2333",
                "'unsafe' is redundant in this context.",
                range,
            ));
        }
    }
    for unsafe_block in collect_kinds(root, &["unsafe_statement"]) {
        if (has_unsafe_context(unsafe_block, source)
            || !contains_unsafe_construct(unsafe_block, source))
            && let Some(range) = direct_keyword_range(unsafe_block, source, "unsafe")
        {
            issues.push(issue(
                language,
                "S2333",
                "'unsafe' is redundant in this context.",
                range,
            ));
        }
    }
    issues
}

fn has_unsafe_context(node: Node<'_>, source: &str) -> bool {
    std::iter::successors(node.parent(), Node::parent).any(|ancestor| {
        ancestor.kind() == "unsafe_statement"
            || has_modifier(&modifiers_of(ancestor, source), "unsafe")
    })
}

fn redundant_accessor_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        let property_rank = accessibility_rank(&modifiers_of(property, source));
        if property_rank == 0 {
            continue;
        }
        let accessors = accessors_of(property);
        let uniformly_redundant = accessors
            .iter()
            .all(|accessor| accessibility_rank(&modifiers_of(*accessor, source)) == property_rank);
        if !uniformly_redundant {
            continue;
        }
        for accessor in accessors {
            if accessibility_rank(&modifiers_of(accessor, source)) == property_rank {
                issues.push(issue(
                    language,
                    "S2333",
                    "Remove this redundant accessibility modifier.",
                    range_of(accessor, source),
                ));
            }
        }
    }
    issues
}

fn modifier_range(
    declaration: Node<'_>,
    source: &str,
    wanted: &str,
) -> Option<hoonarqube_ir::Range> {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "modifier" && node_text(*child, source) == wanted)
        .map(|node| range_of(node, source))
}

fn direct_child<'t>(node: Node<'t>, wanted: &str) -> Option<Node<'t>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| child.kind() == wanted)
}

fn direct_keyword_range(
    node: Node<'_>,
    source: &str,
    wanted: &str,
) -> Option<hoonarqube_ir::Range> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| !child.is_named() && node_text(*child, source) == wanted)
        .map(|keyword| range_of(keyword, source))
}

fn contains_unsafe_construct(root: Node<'_>, source: &str) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node != root
            && (node.kind() == "unsafe_statement"
                || has_modifier(&modifiers_of(node, source), "unsafe"))
        {
            continue;
        }
        if matches!(
            node.kind(),
            "pointer_type"
                | "function_pointer_type"
                | "pointer_indirection_expression"
                | "address_of_expression"
                | "fixed_statement"
        ) || node.kind() == "sizeof_expression" && sizeof_requires_unsafe(node, source)
        {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    false
}

fn sizeof_requires_unsafe(expression: Node<'_>, source: &str) -> bool {
    expression
        .child_by_field_name("type")
        .is_some_and(|type_node| !SAFE_SIZEOF_TYPES.contains(&node_text(type_node, source)))
}

const SAFE_SIZEOF_TYPES: [&str; 15] = [
    "bool", "byte", "char", "decimal", "double", "float", "int", "long", "sbyte", "short", "uint",
    "ulong", "ushort", "nint", "nuint",
];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2333_matches_accessor_visibility_against_property_rank() {
        let report = analyze_default(
            "class A\n{\n    public int Both { public get; public set; }\n    public int Mixed { public get; private set; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2333");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 3);
    }

    #[test]
    fn s2333_counts_partials_per_type_kind() {
        let report = analyze_default(
            "partial class Duo { }\npartial struct Duo { }\npartial struct Duo { }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2333");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s2333_keeps_partial_counts_inside_their_real_scope_and_arity() {
        let report = analyze_default(
            "namespace A { partial class Same { } }\nnamespace B { partial class Same { } }\npartial class Box<T> { }\npartial class Box<T> { }\npartial class Box<T, U> { }\nclass Left { partial class Nested { } }\nclass Right { partial class Nested { } }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2333");
        assert_eq!(flagged.len(), 5);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 2);
        assert_eq!(flagged[2].range.start.line, 5);
        assert_eq!(flagged[3].range.start.line, 6);
        assert_eq!(flagged[4].range.start.line, 7);
    }

    #[test]
    fn s2333_flags_sealed_members_and_redundant_unsafe_contexts() {
        let source = "sealed class Closed\n{\n    public sealed override string ToString() => \"x\";\n}\nunsafe class Native\n{\n    unsafe void Nested(int* value) { }\n}\nclass A\n{\n    unsafe void SafeOnly() { int size = sizeof(int); Span<int> x = stackalloc int[4]; }\n    unsafe void Pointer(int* value) { }\n    void Block() { unsafe { int x = 0; } }\n}\n";
        let tree = crate::parse(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let report = analyze_default(source);
        let flagged = with_key(&report, "csharpsquid:S2333");
        assert_eq!(flagged.len(), 4);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 7);
        assert_eq!(flagged[2].range.start.line, 11);
        assert_eq!(flagged[3].range.start.line, 13);
    }
}
