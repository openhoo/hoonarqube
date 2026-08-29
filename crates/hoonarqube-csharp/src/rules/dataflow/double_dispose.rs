use super::support::WriteKind;
use super::support::callable_blocks;
use super::support::identifier_write;
use super::support::walk_owned;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, expression_name, invocation_receiver};
use crate::symbol_table::nearest_ancestor_of_kinds;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3966 — disposing an object twice either throws or hides
/// a lifecycle bug. Bound: document order across the member body —
/// branches that each dispose the same object are indistinguishable, so
/// a second dispose after an intervening store is clean but two bare
/// disposes are not. The enclosing `using` counts as a dispose too.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let mut disposed: std::collections::HashSet<String> = std::collections::HashSet::new();
        walk_owned(body, &mut |node| match node.kind() {
            "invocation_expression" => {
                if callee_name(node, source) != Some("Dispose") {
                    return;
                }
                let Some(receiver) = invocation_receiver(node) else {
                    return;
                };
                let Some(name) = expression_name(receiver, source) else {
                    return;
                };
                let under_using = nearest_ancestor_of_kinds(node, &["using_statement"])
                    .is_some_and(|using| {
                        collect_kinds(using, &["variable_declarator"])
                            .iter()
                            .any(|declarator| {
                                declarator
                                    .child_by_field_name("name")
                                    .is_some_and(|declared| node_text(declared, source) == name)
                            })
                    });
                if under_using || disposed.contains(name) {
                    issues.push(issue(
                        language,
                        "S3966",
                        format!("'{name}' is disposed more than once."),
                        range_of(node, source),
                    ));
                } else {
                    disposed.insert(name.to_owned());
                }
            }
            "identifier" if identifier_write(node) == Some(WriteKind::Store) => {
                disposed.remove(node_text(node, source));
            }
            _ => {}
        });
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S3966";

    #[test]
    fn s3966_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s3966_two_bare_disposes_flag_the_second() {
        let report = analyze_default(
            "class C {\n    void M(Gate gate) {\n        gate.Dispose();\n        gate.Dispose();\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
    }

    #[test]
    fn s3966_using_counts_as_first_dispose() {
        let report = analyze_default(
            "class C {\n    void M() {\n        using (var s = Make()) {\n            s.Dispose();\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
    }

    #[test]
    fn s3966_intervening_store_resets_disposed_set() {
        let report = analyze_default(
            "class C {\n    void M(Gate gate) {\n        gate.Dispose();\n        gate = Spawn();\n        gate.Dispose();\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s3966_distinct_objects_each_disposed_once_stay_clean() {
        let report = analyze_default(
            "class C {\n    void M(Gate left, Gate right) {\n        left.Dispose();\n        right.Dispose();\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s3966_non_dispose_callees_are_ignored() {
        let report = analyze_default(
            "class C {\n    void M(Gate gate) {\n        gate.Flush();\n        gate.Flush();\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
    #[test]
    fn s3966_distinct_unresolvable_receivers_stay_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        Make().Dispose();\n        Other().Dispose();\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s3966_local_function_state_does_not_leak_or_duplicate() {
        let report = analyze_default(
            "class C {\n    void M(Gate gate) {\n        gate.Dispose();\n        void Local(Gate gate) {\n            gate.Dispose();\n            gate.Dispose();\n        }\n        Local(Spawn());\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 6);
    }
}
