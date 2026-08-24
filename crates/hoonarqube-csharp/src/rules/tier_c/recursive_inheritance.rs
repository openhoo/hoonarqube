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
