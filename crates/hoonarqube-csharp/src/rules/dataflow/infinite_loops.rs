use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
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
            issues.push(issue(
                language,
                "S2190",
                "Add an escape from this loop; it never terminates.",
                range_of(header),
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
                "Add a termination condition to this recursion.",
                range_of(last),
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
