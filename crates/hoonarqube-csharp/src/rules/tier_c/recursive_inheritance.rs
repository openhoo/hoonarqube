use super::support::{graph_reaches, local_inheritance_graph, local_type_declarations};
use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3464 — inheritance cycles over the file-local base graph.
/// Subset: cycles fully expressible in this file; cross-file participation
/// stays uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let graph = local_inheritance_graph(root, source);
    let mut anchors: std::collections::HashMap<&str, Node<'_>> = std::collections::HashMap::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(name_node) = declaration.child_by_field_name("name") else {
            continue;
        };
        anchors.insert(node_text(name_node, source), name_node);
    }
    let mut issues = Vec::new();
    for (name, successors) in &graph {
        if successors
            .iter()
            .any(|successor| graph_reaches(&graph, successor, |current| current == *name))
            && let Some(anchor) = anchors.get(*name)
        {
            issues.push(issue(
                language,
                "S3464",
                "Remove this inheritance cycle; a type cannot derive from itself.",
                range_of(*anchor, source),
            ));
        }
    }
    for declaration in local_type_declarations(root) {
        let Some(name_node) = declaration.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(name_node, source);
        let recursive_generic = collect_base_texts(declaration, source)
            .iter()
            .any(|base| generic_name_count(base, name) >= 2);
        if recursive_generic
            && !issues
                .iter()
                .any(|item| item.range == range_of(name_node, source))
        {
            issues.push(issue(
                language,
                "S3464",
                "Refactor this class so that the generic inheritance chain is not recursive.",
                range_of(name_node, source),
            ));
        }
    }
    issues
}

fn collect_base_texts<'a>(declaration: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut texts = Vec::new();
    let mut cursor = declaration.walk();
    for list in declaration
        .children(&mut cursor)
        .filter(|child| child.kind() == "base_list")
    {
        let mut list_cursor = list.walk();
        texts.extend(
            list.children(&mut list_cursor)
                .filter(Node::is_named)
                .map(|base| node_text(base, source)),
        );
    }
    texts
}

fn generic_name_count(text: &str, name: &str) -> usize {
    text.match_indices(name)
        .filter(|(index, _)| {
            let before = text[..*index].chars().next_back();
            let after = text[index + name.len()..].chars().next();
            before.is_none_or(|value| !value.is_ascii_alphanumeric() && value != '_')
                && after.is_some_and(|value| value == '<')
        })
        .count()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    /// S3464 findings arrive in hash-map order; compare sorted line numbers.
    fn cycle_lines(source: &str) -> Vec<u32> {
        let report = analyze_default(source);
        let mut lines: Vec<_> = with_key(&report, "csharpsquid:S3464")
            .into_iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        lines
    }

    #[test]
    fn s3464_minimal_single_type_has_no_cycle() {
        assert!(cycle_lines("class Solo\n{\n}\n").is_empty());
    }

    #[test]
    fn s3464_flags_both_members_of_a_two_type_cycle() {
        assert_eq!(
            cycle_lines("class A : B\n{\n}\nclass B : A\n{\n}\n"),
            vec![1, 4]
        );
    }

    #[test]
    fn s3464_flags_self_looping_declaration() {
        let report = analyze_default("class Loop : Loop\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3464");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s3464_diamond_shaped_dag_is_not_a_cycle() {
        assert!(cycle_lines(
            "class Top\n{\n}\nclass Left : Top\n{\n}\nclass Right : Top\n{\n}\nclass Bottom : Left, Right\n{\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn s3464_external_base_breaks_the_local_cycle() {
        assert!(cycle_lines("class A : External\n{\n}\nclass B : A\n{\n}\n").is_empty());
    }

    #[test]
    fn s3464_feeder_into_cycle_stays_unflagged_while_cycle_members_flag() {
        assert_eq!(
            cycle_lines(
                "class Feeder : Cycler\n{\n}\nclass Cycler : Eater\n{\n}\nclass Eater : Cycler\n{\n}\n"
            ),
            vec![4, 7]
        );
    }

    #[test]
    fn s3464_interface_cycles_participate() {
        assert_eq!(
            cycle_lines("interface IA : IB\n{\n}\ninterface IB : IA\n{\n}\n"),
            vec![1, 4]
        );
    }
}
