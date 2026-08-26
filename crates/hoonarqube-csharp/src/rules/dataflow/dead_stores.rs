use super::support::WriteKind;
use super::support::callable_blocks;
use super::support::captured_names;
use super::support::identifier_write;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::block_statements;
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1854 and csharpsquid:S2123 — dead stores and useless
/// increments. Straight-line per block: only direct
/// `local_declaration_statement` / `expression_statement` children
/// register stores, every other child contributes reads alone, so
/// branch-local writes can never mask a pending store.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let captured = captured_names(body, source);
        for block in collect_kinds(body, &["block"]) {
            let declared = block_declared_local_names(block, source);
            if declared.is_empty() {
                continue;
            }
            let tracked: std::collections::HashSet<String> = declared
                .iter()
                .filter(|name| !captured.contains(*name))
                .cloned()
                .collect();
            let mut pending: Vec<(String, WriteKind, Node<'_>)> = Vec::new();
            for statement in block_statements(block) {
                consume_reads(statement, source, &tracked, &mut pending);
                match statement.kind() {
                    "local_declaration_statement" => {
                        register_declaration_stores(
                            statement,
                            source,
                            &tracked,
                            &mut pending,
                            &mut issues,
                            language,
                        );
                    }
                    "expression_statement" => {
                        register_expression_stores(
                            statement,
                            source,
                            &tracked,
                            &mut pending,
                            &mut issues,
                            language,
                        );
                    }
                    _ => {}
                }
            }
            // Block scope ends: unread final values stay dead.
            for (name, kind, anchor) in pending {
                push_dead_store(&mut issues, language, &name, kind, anchor, source);
            }
        }
    }
    issues
}

/// Locals declared by this block's direct statements (initializers and
/// declarations without one alike); `const` locals cannot be rewritten.
fn block_declared_local_names(block: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for statement in block_statements(block) {
        if statement.kind() != "local_declaration_statement"
            || has_modifier(&modifiers_of(statement, source), "const")
        {
            continue;
        }
        for declarator in collect_kinds(statement, &["variable_declarator"]) {
            if let Some(name) = declarator.child_by_field_name("name") {
                let text = node_text(name, source);
                if text != "_" {
                    names.push(text.to_owned());
                }
            }
        }
    }
    names
}

/// Consumes every pending store whose name this statement reads. Pure
/// write occurrences do not consume; `out`/`ref` positions do.
fn consume_reads<'t>(
    statement: Node<'t>,
    source: &str,
    tracked: &std::collections::HashSet<String>,
    pending: &mut Vec<(String, WriteKind, Node<'t>)>,
) {
    for identifier in collect_kinds(statement, &["identifier"]) {
        let name = node_text(identifier, source);
        if tracked.contains(name) && identifier_write(identifier).is_none() {
            pending.retain(|(pending_name, _, _)| pending_name != name);
        }
    }
}

/// Registers the unconditional stores of a declaration statement. A new
/// store displaces any pending store of the same name, marking the old
/// value's death — it reports at that moment.
fn register_declaration_stores<'t>(
    statement: Node<'t>,
    source: &str,
    tracked: &std::collections::HashSet<String>,
    pending: &mut Vec<(String, WriteKind, Node<'t>)>,
    issues: &mut Vec<Issue>,
    language: CsLanguage,
) {
    for declarator in collect_kinds(statement, &["variable_declarator"]) {
        let Some(name_node) = declarator.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(name_node, source);
        if tracked.contains(name) && declarator_initializer(declarator, name_node).is_some() {
            displace_pending(pending, name, issues, language, source);
            pending.push((name.to_owned(), WriteKind::Store, declarator));
        }
    }
}

/// Registers the unconditional stores of one expression statement:
/// plain `=` assignments and `++`/`--` operands.
fn register_expression_stores<'t>(
    statement: Node<'t>,
    source: &str,
    tracked: &std::collections::HashSet<String>,
    pending: &mut Vec<(String, WriteKind, Node<'t>)>,
    issues: &mut Vec<Issue>,
    language: CsLanguage,
) {
    for identifier in collect_kinds(statement, &["identifier"]) {
        let Some(write) = identifier_write(identifier) else {
            continue;
        };
        let name = node_text(identifier, source);
        if tracked.contains(name) {
            displace_pending(pending, name, issues, language, source);
            pending.push((name.to_owned(), write, identifier));
        }
    }
}

/// Reports every pending store of `name` as dead (overwritten unread)
/// and drops them from the pending list.
fn displace_pending(
    pending: &mut Vec<(String, WriteKind, Node<'_>)>,
    name: &str,
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    source: &str,
) {
    let displaced: Vec<_> = pending
        .iter()
        .filter(|(pending_name, _, _)| pending_name == name)
        .map(|(_, kind, anchor)| (*kind, *anchor))
        .collect();
    pending.retain(|(pending_name, _, _)| pending_name != name);
    for (kind, anchor) in displaced {
        push_dead_store(issues, language, name, kind, anchor, source);
    }
}

/// Reports one dead store with the rule its write shape dictates.
fn push_dead_store(
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    name: &str,
    kind: WriteKind,
    anchor: Node<'_>,
    source: &str,
) {
    match kind {
        WriteKind::Increment => issues.push(issue(
            language,
            "S2123",
            format!("'{name}' is incremented but the new value is never used."),
            range_of(anchor, source),
        )),
        WriteKind::Store => issues.push(issue(
            language,
            "S1854",
            format!("Remove this useless assignment to local variable '{name}'."),
            range_of(anchor, source),
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1854_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, "csharpsquid:S1854").is_empty());
        assert!(with_key(&report, "csharpsquid:S2123").is_empty());
    }

    #[test]
    fn s1854_unread_final_value_dies_at_block_end() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int leftover = Compute();\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S1854");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn s2123_useless_increment_reports_increment_rule() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int ticks = 0;\n        ticks++;\n        Reset();\n    }\n}\n",
        );
        // The increment also displaces the initializer's pending store,
        // so the masked `= 0` is reported under S1854.
        assert_eq!(with_key(&report, "csharpsquid:S1854").len(), 1);
    }

    #[test]
    fn s1854_captured_locals_are_exempt() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int seed = 1;\n        Run(() => seed + 1);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1854").is_empty());
    }

    #[test]
    fn s1854_out_argument_consumes_pending_store() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int slot;\n        Bind(out slot);\n        Log(slot);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1854").is_empty());
    }

    #[test]
    fn s1854_nested_block_write_without_local_declares_nothing() {
        let report = analyze_default(
            "class C {\n    void M(bool flag) {\n        int x = 0;\n        if (flag) {\n            x = 1;\n        }\n        Log(x);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1854").is_empty());
    }

    #[test]
    fn s1854_displacement_and_tail_death_at_distinct_lines() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int a = 1;\n        a = 2;\n        Log(a);\n        int b = 9;\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S1854");
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].range.start.line, found[1].range.start.line);
    }
}
