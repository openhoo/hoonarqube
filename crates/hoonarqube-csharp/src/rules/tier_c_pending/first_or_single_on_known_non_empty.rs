use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, walk_all};
use crate::rules::dataflow::{WriteKind, callable_blocks, identifier_write};
use crate::rules::expressions::{callee_name, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S7130 — First/Single on collections proven non-empty.
/// Subset: same-callable proof in document order — the receiver identifier
/// was populated by `.Add`/`.AddRange`/`.Insert` or a non-empty collection
/// initializer and never reassigned or cleared before the call; other
/// receiver shapes and cross-method flow stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for body in callable_blocks(root) {
        let mut populated: std::collections::HashSet<String> = std::collections::HashSet::new();
        walk_all(body, &mut |node| {
            if !visited.insert(node.id()) {
                return;
            }
            match node.kind() {
                "invocation_expression" => {
                    let Some(receiver) = invocation_receiver(node) else {
                        return;
                    };
                    if receiver.kind() != "identifier" {
                        return;
                    }
                    let name = node_text(receiver, source);
                    match callee_name(node, source) {
                        Some("Add" | "AddRange" | "Insert") => {
                            populated.insert(name.to_owned());
                        }
                        Some("Clear") => {
                            populated.remove(name);
                        }
                        Some("FirstOrDefault" | "SingleOrDefault") if populated.contains(name) => {
                            issues.push(issue(
                                    language,
                                    "S7130",
                                    "Use 'First' or 'Single' here; this collection is known to be non-empty.",
                                    range_of(node, source),
                                ));
                        }
                        _ => {}
                    }
                }
                "variable_declaration" => {
                    for declarator in collect_kinds(node, &["variable_declarator"]) {
                        let Some(initializer) =
                            collect_kinds(declarator, &["initializer_expression"])
                                .into_iter()
                                .next()
                        else {
                            continue;
                        };
                        let mut cursor = initializer.walk();
                        if !initializer
                            .children(&mut cursor)
                            .any(|child| child.is_named())
                        {
                            continue;
                        }
                        if let Some(name) = declarator.child_by_field_name("name") {
                            populated.insert(node_text(name, source).to_owned());
                        }
                    }
                }
                "identifier" if identifier_write(node) == Some(WriteKind::Store) => {
                    // A declarator's own name is not a reassignment when the
                    // already-credited non-empty initializer populates it.
                    let credited_by_initializer = node.parent().is_some_and(|parent| {
                        parent.kind() == "variable_declarator"
                            && collect_kinds(parent, &["initializer_expression"])
                                .into_iter()
                                .next()
                                .is_some_and(|initializer| {
                                    initializer
                                        .children(&mut initializer.walk())
                                        .any(|child| child.is_named())
                                })
                    });
                    if !credited_by_initializer {
                        populated.remove(node_text(node, source));
                    }
                }
                _ => {}
            }
        });
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s7130_single_or_default_is_flagged_too() {
        let report = analyze_default(
            "void Register()\n{\n    var ids = new List<int>();\n    ids.Add(1);\n    var only = ids.SingleOrDefault();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S7130");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s7130_clear_and_reassignment_displace_the_proof() {
        let report = analyze_default(
            "void Register()\n{\n    var ids = new List<int>();\n    ids.Add(1);\n    ids.Clear();\n    ids = new List<int>();\n    var first = ids.FirstOrDefault();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S7130").is_empty());
    }

    #[test]
    fn s7130_non_empty_collection_initializers_populate() {
        let report = analyze_default(
            "void A()\n{\n    var ids = new List<int> { 1 };\n    var first = ids.FirstOrDefault();\n}\nvoid B()\n{\n    var ids = new List<int> { };\n    var first = ids.FirstOrDefault();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S7130");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s7130_add_range_and_insert_also_prove_non_emptiness() {
        let report = analyze_default(
            "void A()\n{\n    var ids = new List<int>();\n    ids.AddRange(new[] { 1 });\n    var first = ids.FirstOrDefault();\n}\nvoid B()\n{\n    var ids = new List<int>();\n    ids.Insert(0, 2);\n    var first = ids.FirstOrDefault();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S7130");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 11);
    }

    #[test]
    fn s7130_other_receiver_shapes_and_unpopulated_locals_stay_clean() {
        let report = analyze_default(
            "void Run()\n{\n    var ids = GetIds();\n    var first = ids.FirstOrDefault();\n    var other = Load().FirstOrDefault();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S7130").is_empty());
    }

    #[test]
    fn s7130_population_does_not_cross_callables() {
        let report = analyze_default(
            "void Fill()\n{\n    var ids = new List<int>();\n    ids.Add(1);\n}\nvoid Use()\n{\n    var ids = new List<int>();\n    var first = ids.FirstOrDefault();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S7130").is_empty());
    }
}
