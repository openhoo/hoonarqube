use super::support::{graph_reaches, local_type_declarations};
use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, node_text, range_from_byte_offsets, range_of};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use std::collections::HashMap;
use tree_sitter::Node;

/// csharpsquid:S1939 — inheritance lists repeating an entry or repeating the
/// declared type's own name. Comparisons pair the simple name with generic
/// arity, because same-spelling references of different arity denote distinct
/// types (`Identity` vs `Identity<TFirst, …, TSeventh>`).
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let graph = arity_inheritance_graph(root, source);
    let mut issues = Vec::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let bases = base_nodes(declaration);
        let issue_count = issues.len();
        for (index, candidate) in bases.iter().enumerate() {
            let (candidate_name, candidate_arity) =
                crate::cst::type_reference_key(node_text(*candidate, source));
            let candidate_key = arity_key(candidate_name, candidate_arity);
            if let Some(implementer) = bases.iter().enumerate().find_map(|(other_index, other)| {
                let (other_name, other_arity) =
                    crate::cst::type_reference_key(node_text(*other, source));
                (other_index != index
                    && graph_reaches(&graph, &arity_key(other_name, other_arity), |current| {
                        current == &candidate_key
                    }))
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
            let base_keys: Vec<(&str, usize)> = bases
                .iter()
                .map(|base| crate::cst::type_reference_key(node_text(*base, source)))
                .collect();
            let duplicated = (0..base_keys.len())
                .any(|index| base_keys[index + 1..].contains(&base_keys[index]));
            let self_named = declaration.child_by_field_name("name").is_some_and(|name| {
                let declared_name = node_text(name, source);
                base_keys.contains(&(
                    crate::cst::simple_name(declared_name),
                    declared_type_parameter_count(declaration),
                ))
            });
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

/// File-local inheritance edges keyed by full type identity
/// (`simple_name<arity>`), so same-spelling declarations of different arity
/// never share graph nodes.
fn arity_inheritance_graph(root: Node<'_>, source: &str) -> HashMap<String, Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(name) = declaration.child_by_field_name("name") else {
            continue;
        };
        let key = arity_key(
            crate::cst::simple_name(node_text(name, source)),
            declared_type_parameter_count(declaration),
        );
        let bases = base_nodes(declaration)
            .iter()
            .map(|base| {
                let (base_name, base_arity) =
                    crate::cst::type_reference_key(node_text(*base, source));
                arity_key(base_name, base_arity)
            })
            .collect::<Vec<_>>();
        graph.entry(key).or_default().extend(bases);
    }
    graph
}

fn arity_key(name: &str, arity: usize) -> String {
    format!("{name}<{arity}>")
}

fn declared_type_parameter_count(declaration: Node<'_>) -> usize {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "type_parameter_list")
        .map_or(0, |parameters| {
            let mut parameter_cursor = parameters.walk();
            parameters
                .children(&mut parameter_cursor)
                .filter(|parameter| parameter.kind() == "type_parameter")
                .count()
        })
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
    #[test]
    fn s1939_generic_arity_distinguishes_self_named_base() {
        let report = analyze_default(
            "class Identity<TFirst, TSecond, TThird, TFourth, TFifth, TSixth, TSeventh> : Identity\n{\n}\n",
        );
        assert!(
            with_key(&report, "csharpsquid:S1939").is_empty(),
            "the arity-7 declaration and the arity-0 base are distinct types"
        );
    }

    #[test]
    fn s1939_generic_arity_distinguishes_arity_widened_base() {
        let report = analyze_default("class Table<T> : Table<T, int>\n{\n}\n");
        assert!(
            with_key(&report, "csharpsquid:S1939").is_empty(),
            "Table<T> and Table<T, int> differ in generic arity"
        );
    }

    #[test]
    fn s1939_distinct_arity_interfaces_are_not_duplicates() {
        let report = analyze_default(
            "interface Foo\n{\n}\ninterface Foo<T>\n{\n}\nclass Uses : Foo, Foo<int>\n{\n}\n",
        );
        assert!(
            with_key(&report, "csharpsquid:S1939").is_empty(),
            "same-spelling bases of different arity are distinct types"
        );
    }

    #[test]
    fn s1939_flags_same_arity_generic_duplicate() {
        let report =
            analyze_default("interface IPair<T>\n{\n}\nclass Pair<T> : IPair<T>, IPair<T>\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s1939_flags_generic_transitive_redundancy() {
        let report = analyze_default(
            "class Entity\n{\n}\nclass Repo<T> : Entity\n{\n}\nclass Special : Entity, Repo<int>\n{\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1939");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(
            flagged[0].message,
            "'Repo' implements 'Entity' so 'Entity' can be removed from the inheritance list."
        );
    }
}
