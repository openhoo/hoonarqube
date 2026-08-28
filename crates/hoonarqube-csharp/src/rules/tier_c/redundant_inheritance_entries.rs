use super::support::{graph_reaches, local_inheritance_graph, local_type_declarations};
use crate::CsLanguage;
use crate::cst::{
    base_simple_names, is_error_tainted, issue, node_text, range_from_byte_offsets, range_of,
};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1939 — inheritance lists repeating an entry or repeating the
/// declared type's own name.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let graph = local_inheritance_graph(root, source);
    let mut issues = Vec::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let bases = base_nodes(declaration);
        let issue_count = issues.len();
        for (index, candidate) in bases.iter().enumerate() {
            let candidate_name = crate::cst::simple_name(node_text(*candidate, source));
            if let Some(implementer) = bases.iter().enumerate().find_map(|(other_index, other)| {
                let other_name = crate::cst::simple_name(node_text(*other, source));
                (other_index != index
                    && graph_reaches(&graph, other_name, |current| current == candidate_name))
                .then_some(other_name)
            }) {
                issues.push(issue(
                    language,
                    "S1939",
                    format!(
                        "'{implementer}' implements '{candidate_name}' so '{candidate_name}' can be removed from the inheritance list."
                    ),
                    base_entry_range(*candidate, source),
                ));
            }
        }
        if issues.len() == issue_count {
            let base_names = base_simple_names(declaration, source);
            let duplicated = (0..base_names.len())
                .any(|index| base_names[index + 1..].contains(&base_names[index]));
            let self_named = declaration
                .child_by_field_name("name")
                .is_some_and(|name| base_names.contains(&node_text(name, source)));
            if duplicated || self_named {
                issues.push(issue(
                    language,
                    "S1939",
                    "Remove the redundant entry from this inheritance list.",
                    range_of(name_anchor(declaration), source),
                ));
            }
        }
    }
    issues
}

fn base_entry_range(base: Node<'_>, source: &str) -> hoonarqube_ir::Range {
    let end = if source.as_bytes().get(base.end_byte()) == Some(&b',') {
        base.end_byte() + 1
    } else {
        base.end_byte()
    };
    range_from_byte_offsets(base.start_byte(), end, source)
}

fn base_nodes(type_node: Node<'_>) -> Vec<Node<'_>> {
    let mut nodes = Vec::new();
    let mut cursor = type_node.walk();
    for list in type_node
        .children(&mut cursor)
        .filter(|child| child.kind() == "base_list")
    {
        let mut list_cursor = list.walk();
        nodes.extend(list.children(&mut list_cursor).filter(Node::is_named));
    }
    nodes
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1939_minimal_types_without_base_lists_stay_silent() {
        let report = analyze_default("class Bare\n{\n}\nstruct Solid\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1939").is_empty());
    }

    #[test]
    fn s1939_flags_repeated_simple_name_entry() {
        let report = analyze_default(
            "interface IA\n{\n}\ninterface IB\n{\n}\nclass Dup : IA, IB, IA\n{\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s1939_flags_self_named_record() {
        let report = analyze_default("record Echo : Echo\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s1939_triple_repetition_reports_once() {
        let report = analyze_default("class Trip : IA, IA, IA\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s1939_distinct_and_qualified_bases_stay_clean() {
        let report = analyze_default(
            "class Ok : Exception, IDisposable\n{\n}\nclass Also : System.Exception\n{\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1939").is_empty());
    }

    #[test]
    fn s1939_reports_each_duplicating_type_at_its_own_line() {
        let report = analyze_default("class One : IA, IA\n{\n}\nclass Two : IB, IB\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 4);
    }

    #[test]
    fn s1939_flags_repeated_entry_on_struct() {
        let report = analyze_default("struct Pair : IPair, IPair\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }
}
