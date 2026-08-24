use super::support::local_type_declarations;
use crate::CsLanguage;
use crate::cst::{base_simple_names, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3464 — inheritance cycles over the file-local base graph.
/// Subset: cycles fully expressible in this file; cross-file participation
/// stays uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn cycle_reaches<'a>(
        graph: &std::collections::HashMap<&'a str, Vec<&'a str>>,
        start: &str,
        target: &str,
    ) -> bool {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut queue: Vec<&str> = graph.get(start).cloned().unwrap_or_default();
        while let Some(current) = queue.pop() {
            if current == target {
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
    let mut graph: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    let mut anchors: std::collections::HashMap<&str, Node<'_>> = std::collections::HashMap::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(name_node) = declaration.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(name_node, source);
        anchors.insert(name, name_node);
        graph
            .entry(name)
            .or_default()
            .extend(base_simple_names(declaration, source));
    }
    let mut issues = Vec::new();
    for (name, successors) in &graph {
        if successors
            .iter()
            .any(|successor| cycle_reaches(&graph, successor, name))
            && let Some(anchor) = anchors.get(*name)
        {
            issues.push(issue(
                language,
                "S3464",
                "Remove this inheritance cycle; a type cannot derive from itself.",
                range_of(*anchor),
            ));
        }
    }
    issues
}
