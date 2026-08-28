use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    block_statements, callee_name, first_named_child, invocation_receiver,
};
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2190 — loops whose entry-true condition has no escape in
/// the body never terminate. Tail self-recursion with no conditional
/// wrapper recurses forever the same way.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["while_statement", "for_statement", "do_statement"]) {
        if is_error_tainted(header) || !condition_true_at_entry(header, source) {
            continue;
        }
        let Some(body) = header.child_by_field_name("body") else {
            continue;
        };
        if !subtree_escapes(body) {
            let anchor = ancestors_of(header)
                .find(|ancestor| ancestor.kind() == "method_declaration")
                .and_then(|method| method.child_by_field_name("name"))
                .unwrap_or(header);
            issues.push(issue(
                language,
                "S2190",
                "Add a way to break out of this method's recursion.",
                range_of(anchor, source),
            ));
        }
    }
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some(body) = body_of(method) else {
            continue;
        };
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let own_name = node_text(name, source);
        let statements = block_statements(body);
        let Some(last) = statements.last().copied() else {
            continue;
        };
        let tail_call = match last.kind() {
            "expression_statement" | "return_statement" => first_named_child(last),
            _ => None,
        }
        .filter(|expression| expression.kind() == "invocation_expression")
        .filter(|call| callee_name(*call, source) == Some(own_name))
        .filter(|call| {
            invocation_receiver(*call).is_none_or(|receiver| {
                receiver.kind() == "identifier" && node_text(receiver, source) == "this"
            })
        });
        // A base case anywhere else in the body terminates the recursion
        // (`if (n <= 1) return 1; return Fact(n - 1);`): every escape
        // site must live inside the trailing call itself.
        let unguarded_tail = tail_call.is_some()
            && collect_kinds(body, &["return_statement", "throw_statement"])
                .into_iter()
                .all(|site| {
                    site.start_byte() >= last.start_byte() && site.end_byte() <= last.end_byte()
                });
        if unguarded_tail {
            issues.push(issue(
                language,
                "S2190",
                "Add a way to break out of this method's recursion.",
                range_of(name, source),
            ));
        }
    }
    issues
}

/// Whether the loop condition is provably true at entry (literal `true`
/// or an omitted `for` condition).
fn condition_true_at_entry(header: Node<'_>, source: &str) -> bool {
    match header.child_by_field_name("condition") {
        None => header.kind() == "for_statement",
        Some(condition) => {
            condition.kind() == "boolean_literal" && node_text(condition, source) == "true"
        }
    }
}

/// Whether a subtree offers any way out: `break`, `return`, `throw`, or
/// an outward `goto`.
fn subtree_escapes(node: Node<'_>) -> bool {
    collect_kinds(
        node,
        &[
            "break_statement",
            "return_statement",
            "throw_statement",
            "goto_statement",
        ],
    )
    .iter()
    .any(|escape| !is_error_tainted(*escape))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S2190";

    #[test]
    fn s2190_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2190_while_true_without_escape_flags() {
        let report = analyze_default(
            "class C {\n    void M() {\n        while (true) {\n            Spin();\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
    }

    #[test]
    fn s2190_break_offers_the_way_out() {
        let report = analyze_default(
            "class C {\n    void M() {\n        while (true) {\n            if (Done()) {\n                break;\n            }\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2190_omitted_for_condition_with_return_is_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        for (;;) {\n            return;\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2190_unguarded_tail_recursion_recurses_forever() {
        let report = analyze_default(
            "class C {\n    int Loop(int n) {\n        return Loop(n + 1);\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn s2190_base_case_elsewhere_breaks_recursion_flag() {
        let report = analyze_default(
            "class C {\n    int Fact(int n) {\n        if (n <= 1) {\n            return 1;\n        }\n        return Fact(n - 1);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2190_throw_counts_as_escape() {
        let report = analyze_default(
            "class C {\n    void M() {\n        do {\n            throw new System.InvalidOperationException();\n        } while (true);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
