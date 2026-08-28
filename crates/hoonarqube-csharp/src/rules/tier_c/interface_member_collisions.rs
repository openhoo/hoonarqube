use super::support::local_type_declarations;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3444 — interfaces inheriting the same member from multiple
/// base interfaces must resolve the ambiguity themselves.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let interfaces: std::collections::HashMap<&str, Node<'_>> = local_type_declarations(root)
        .into_iter()
        .filter(|declaration| declaration.kind() == "interface_declaration")
        .filter_map(|declaration| {
            declaration
                .child_by_field_name("name")
                .map(|name| (node_text(name, source), declaration))
        })
        .collect();
    let mut issues = Vec::new();
    for declaration in collect_kinds(root, &["interface_declaration"])
        .into_iter()
        .filter(|declaration| !is_error_tainted(*declaration))
    {
        let bases = base_simple_names(declaration, source);
        if bases.len() < 2 {
            continue;
        }
        let own = direct_member_signatures(declaration, source);
        let mut inherited_counts = std::collections::HashMap::<String, usize>::new();
        for base in bases.into_iter().filter_map(|name| interfaces.get(name)) {
            for signature in direct_member_signatures(*base, source) {
                *inherited_counts.entry(signature).or_default() += 1;
            }
        }
        let mut collisions: Vec<String> = inherited_counts
            .into_iter()
            .filter_map(|(signature, count)| {
                (count > 1 && !own.contains(&signature)).then_some(signature)
            })
            .collect();
        collisions.sort();
        let Some(collision) = collisions.into_iter().next() else {
            continue;
        };
        let Some(name) = declaration.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S3444",
            format!("Rename or add member '{collision}' to this interface to resolve ambiguities."),
            range_of(name, source),
        ));
    }
    issues
}

fn direct_member_signatures(
    type_node: Node<'_>,
    source: &str,
) -> std::collections::HashSet<String> {
    let mut signatures = std::collections::HashSet::new();
    for property in member_declarations_of_kind(type_node, "property_declaration") {
        let Some(name) = property.child_by_field_name("name") else {
            continue;
        };
        for accessor in collect_kinds(property, &["accessor_declaration"]) {
            let keyword = node_text(accessor, source)
                .split(|character: char| character.is_whitespace() || character == ';')
                .next()
                .unwrap_or("");
            if matches!(keyword, "get" | "set" | "init") {
                signatures.insert(format!("{}.{keyword}", node_text(name, source)));
            }
        }
    }
    for method in member_declarations_of_kind(type_node, "method_declaration") {
        if let Some(name) = method.child_by_field_name("name") {
            signatures.insert(format!("{}()", node_text(name, source)));
        }
    }
    signatures
}
