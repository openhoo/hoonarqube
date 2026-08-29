use super::support::WriteKind;
use super::support::callable_blocks;
use super::support::identifier_write;
use super::support::name_is_guarded;
use super::support::walk_except_blocks;
use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::block_statements;
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2259 — dereferencing a known-null reference crashes.
/// Bound: straight-line knowledge inside one block — names assigned
/// `null` by an unconditional statement stay null until another store
/// or an unknown-state use (`out`/`ref`) clears them; a member-wide
/// textual guard exempts a name entirely. Cross-branch reasoning is out
/// of scope.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let body_text = node_text(body, source);
        for block in collect_kinds(body, &["block"]) {
            let mut known_null: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for statement in block_statements(block) {
                // Dereferences first, then state updates: statements are
                // processed in source order.
                flag_known_null_dereferences(
                    statement,
                    &known_null,
                    body_text,
                    source,
                    language,
                    &mut issues,
                );
                update_known_nulls(statement, &mut known_null, source);
            }
        }
    }
    issues
}

fn flag_known_null_dereferences(
    statement: Node<'_>,
    known_null: &std::collections::HashSet<String>,
    body_text: &str,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    walk_except_blocks(statement, &mut |node| {
        let Some(base) = dereferenced_identifier(node) else {
            return;
        };
        let name = node_text(base, source);
        if known_null.contains(name)
            && !node_text(node, source).contains('?')
            && !name_is_guarded(body_text, name)
        {
            issues.push(issue(
                language,
                "S2259",
                format!("'{name}' is null here; this dereference will throw."),
                range_of(base, source),
            ));
        }
    });
}

fn dereferenced_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if !matches!(
        node.kind(),
        "member_access_expression" | "element_access_expression"
    ) {
        return None;
    }
    node.child_by_field_name("expression")
        .filter(|base| base.kind() == "identifier")
}

fn update_known_nulls(
    statement: Node<'_>,
    known_null: &mut std::collections::HashSet<String>,
    source: &str,
) {
    for identifier in collect_kinds(statement, &["identifier"]) {
        let name = node_text(identifier, source);
        if passed_by_reference(identifier, source) {
            known_null.remove(name);
            continue;
        }
        match identifier_write(identifier) {
            Some(WriteKind::Store) if stores_unconditional_null(identifier) => {
                known_null.insert(name.to_owned());
            }
            Some(WriteKind::Store | WriteKind::Increment) => {
                known_null.remove(name);
            }
            None => {}
        }
    }
}

fn passed_by_reference(identifier: Node<'_>, source: &str) -> bool {
    identifier.parent().is_some_and(|parent| {
        parent.kind() == "argument"
            && parent
                .children(&mut parent.walk())
                .any(|child| !child.is_named() && matches!(node_text(child, source), "out" | "ref"))
    })
}

fn stores_unconditional_null(identifier: Node<'_>) -> bool {
    let stores_null = identifier.parent().is_some_and(|parent| {
        parent
            .child_by_field_name("right")
            .is_some_and(|right| right.kind() == "null_literal")
            || declarator_initializer(parent, identifier)
                .is_some_and(|value| value.kind() == "null_literal")
    });
    stores_null && !conditional_context(identifier)
}

/// Ancestors between `node` and its nearest block-like boundary that run
/// conditionally: branches, loops, handlers, short-circuit operands.
fn conditional_context(node: Node<'_>) -> bool {
    ancestors_of(node)
        .take_while(|ancestor| {
            !matches!(
                ancestor.kind(),
                "method_declaration"
                    | "constructor_declaration"
                    | "destructor_declaration"
                    | "accessor_declaration"
                    | "local_function_statement"
                    | "operator_declaration"
            )
        })
        .any(|ancestor| {
            matches!(
                ancestor.kind(),
                "if_statement"
                    | "while_statement"
                    | "for_statement"
                    | "foreach_statement"
                    | "do_statement"
                    | "switch_statement"
                    | "switch_section"
                    | "try_statement"
                    | "catch_clause"
                    | "finally_clause"
                    | "conditional_expression"
                    | "using_statement"
            )
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S2259";

    #[test]
    fn s2259_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2259_member_access_on_known_null_flags() {
        let report = analyze_default(
            "class C {\n    void M() {\n        string name = null;\n        var len = name.Length;\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
    }

    #[test]
    fn s2259_reassignment_to_non_null_clears_the_state() {
        let report = analyze_default(
            "class C {\n    void M() {\n        string name = null;\n        name = Env();\n        var len = name.Length;\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2259_out_argument_clears_known_null() {
        let report = analyze_default(
            "class C {\n    void M() {\n        string name = null;\n        Fill(out name);\n        var len = name.Length;\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2259_guarded_name_is_exempt_member_wide() {
        let report = analyze_default(
            "class C {\n    void M(string? maybe) {\n        if (maybe == null) {\n            return;\n        }\n        var len = maybe.Length;\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2259_conditional_store_does_not_mark_known_null() {
        let report = analyze_default(
            "class C {\n    void M(bool flag) {\n        string name = \"x\";\n        if (flag) {\n            name = null;\n        }\n        var len = name.Length;\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2259_element_access_on_known_null_flags_too() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int[] cells = null;\n        var head = cells[0];\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }
}
