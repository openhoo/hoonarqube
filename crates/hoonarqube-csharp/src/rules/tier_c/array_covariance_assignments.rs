use super::support::local_inheritance_graph;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2330 — array covariance assignments between file-local
/// element-type hierarchies (`Animal[] a = new Dog[2];`). Subset:
/// declarations only; assignments to previously declared arrays stay out.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let graph = local_inheritance_graph(root, source);
    collect_kinds(root, &["variable_declaration"])
        .into_iter()
        .filter(|declaration| !is_error_tainted(*declaration))
        .filter_map(move |declaration| {
            let type_node = declaration.child_by_field_name("type")?;
            if type_node.kind() != "array_type" {
                return None;
            }
            let element = simple_name(node_text(type_node, source).split('[').next()?);
            for declarator in collect_kinds(declaration, &["variable_declarator"]) {
                let Some(value) = collect_kinds(declarator, &["array_creation_expression"])
                    .into_iter()
                    .next()
                else {
                    continue;
                };
                let created = simple_name(creation_type_text(value, source).split('[').next()?);
                let covariant = created != element
                    && graph_reaches(&graph, created, element);
                if covariant {
                    return declarator.child_by_field_name("name");
                }
            }
            None
        })
        .map(|name| {
            issue(
                language,
                "S2330",
                "Avoid array covariance here; use an explicitly typed array or a common generic collection.",
                range_of(name),
            )
        })
        .collect()
}

/// Whether `descendant` reaches `ancestor` through the file-local base graph.
fn graph_reaches(
    graph: &std::collections::HashMap<&str, Vec<&str>>,
    descendant: &str,
    ancestor: &str,
) -> bool {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut queue: Vec<&str> = graph.get(descendant).cloned().unwrap_or_default();
    while let Some(current) = queue.pop() {
        if current == ancestor {
            return true;
        }
        if seen.insert(current)
            && let Some(successors) = graph.get(current)
        {
            queue.extend(successors.iter().copied());
        }
    }
    false
}
