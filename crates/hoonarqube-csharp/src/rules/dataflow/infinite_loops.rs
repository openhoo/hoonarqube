use super::support::collect_owned_kinds;
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
        if !subtree_escapes(header, body) {
            let anchor = ancestors_of(header)
                .find(|ancestor| {
                    matches!(
                        ancestor.kind(),
                        "local_function_statement"
                            | "method_declaration"
                            | "constructor_declaration"
                            | "destructor_declaration"
                            | "operator_declaration"
                            | "accessor_declaration"
                    )
                })
                .and_then(|callable| callable.child_by_field_name("name"))
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
        })
        .filter(|call| !has_incompatible_fixed_arity(method, *call));
        // A base case anywhere else in the body terminates the recursion
        // (`if (n <= 1) return 1; return Fact(n - 1);`): every escape
        // site must live inside the trailing call itself.
        let unguarded_tail = tail_call.is_some()
            && collect_owned_kinds(body, &["return_statement", "throw_statement"])
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

/// A same-name call with a provably incompatible positional argument count
/// delegates to another overload. Unsupported signatures and call shapes
/// cannot establish that proof, so they retain the existing recursion check.
fn has_incompatible_fixed_arity(method: Node<'_>, call: Node<'_>) -> bool {
    if method.has_error() || call.has_error() {
        return false;
    }
    let Some((minimum, maximum)) = fixed_parameter_arity(method) else {
        return false;
    };
    positional_argument_count(call).is_some_and(|count| count < minimum || count > maximum)
}

fn fixed_parameter_arity(method: Node<'_>) -> Option<(usize, usize)> {
    let parameters = method.child_by_field_name("parameters")?;
    let (mut minimum, mut maximum) = (0, 0);
    let mut cursor = parameters.walk();
    for child in parameters.children(&mut cursor) {
        match child.kind() {
            "(" | ")" | "," => {}
            "parameter" => {
                let optional = fixed_parameter_is_optional(child)?;
                maximum += 1;
                minimum += usize::from(!optional);
            }
            _ => return None,
        }
    }
    Some((minimum, maximum))
}

fn fixed_parameter_is_optional(parameter: Node<'_>) -> Option<bool> {
    parameter.child_by_field_name("type")?;
    parameter.child_by_field_name("name")?;
    let mut cursor = parameter.walk();
    let optional = parameter
        .children(&mut cursor)
        .any(|child| child.kind() == "=");
    // Only a type, name, and optional `= expression` are understood. Attributes
    // can alter omission semantics; modifiers and comments also refuse proof.
    let (children, named_children) = if optional { (4, 3) } else { (2, 2) };
    (parameter.child_count() == children && parameter.named_child_count() == named_children)
        .then_some(optional)
}

fn positional_argument_count(call: Node<'_>) -> Option<usize> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut count = 0;
    let mut cursor = arguments.walk();
    for child in arguments.children(&mut cursor) {
        match child.kind() {
            "(" | ")" | "," => {}
            "argument"
                if child.child_by_field_name("name").is_none()
                    && child.child_count() == 1
                    && child.named_child_count() == 1 =>
            {
                count += 1;
            }
            _ => return None,
        }
    }
    Some(count)
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
fn subtree_escapes(header: Node<'_>, node: Node<'_>) -> bool {
    collect_owned_kinds(
        node,
        &[
            "break_statement",
            "return_statement",
            "throw_statement",
            "goto_statement",
        ],
    )
    .iter()
    .any(|escape| {
        if is_error_tainted(*escape) {
            return false;
        }
        escape.kind() != "break_statement"
            || ancestors_of(*escape)
                .find(|ancestor| {
                    matches!(
                        ancestor.kind(),
                        "while_statement"
                            | "for_statement"
                            | "foreach_statement"
                            | "do_statement"
                            | "switch_statement"
                    )
                })
                .is_some_and(|owner| owner.id() == header.id())
    })
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

    #[test]
    fn s2190_nested_local_return_does_not_escape_outer_loop() {
        let report = analyze_default(
            "class C {\n    void M() {\n        while (true) {\n            void Local() { return; }\n            Local();\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
    }

    #[test]
    fn s2190_break_from_nested_loop_does_not_escape_outer_loop() {
        let report = analyze_default(
            "class C {\n    void M() {\n        while (true) {\n            while (true) { break; }\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
    }

    #[test]
    fn s2190_distinct_fixed_arity_forwarders_do_not_recurse() {
        for source in [
            "class C { int Forward(int n) { return Forward(n, 0); } int Forward(int n, int extra) { return n + extra; } }",
            "class C { int Forward(int n, int extra) { return Forward(n); } int Forward(int n) { return n; } }",
            "class C { string Humanize(int unit = 0) { return Humanize(null, unit); } string Humanize(string format, int unit = 0, object culture = null) { return format; } }",
            "class C { int Forward(int n) { return Forward(n, (0, 1).Item1); } int Forward(int n, int extra) { return n + extra; } }",
        ] {
            let report = analyze_default(source);
            assert!(with_key(&report, KEY).is_empty(), "{source:?}");
        }
    }

    #[test]
    fn s2190_arity_proof_preserves_optional_params_named_and_ref_boundaries() {
        for source in [
            "class C { int Loop(int n) { return Loop(n + 1); } }",
            "class C { int Loop(int n = 0) { return Loop(); } }",
            "class C { int Loop(int n, int extra = 0) { return Loop(n); } }",
            "class C { int Loop(params int[] values) { return Loop(1, 2); } }",
            "class C { int Loop(int n) { return Loop(n: n); } }",
            "class C { int Loop(ref int n) { return Loop(ref n); } }",
            "class C { int Forward(int n) { return Forward(extra: 0, n: n); } int Forward(int n, int extra) { return n + extra; } }",
            "class C { int Forward(ref int n) { return Forward(ref n, 0); } int Forward(ref int n, int extra) { return n + extra; } }",
            "class C { int Forward(int n) { return Forward((long)n); } int Forward(long n) { return (int)n; } }",
            "class C { int Loop([System.Runtime.InteropServices.Optional] int n) { return Loop(); } }",
        ] {
            let report = analyze_default(source);
            let findings = with_key(&report, KEY);
            assert_eq!(findings.len(), 1, "{source:?}");
            assert_eq!(
                findings[0].message,
                "Add a way to break out of this method's recursion."
            );
            assert!(findings[0].fix.is_none());
            assert!(findings[0].alternatives.is_empty());
            assert!(findings[0].flows.is_empty());
        }
    }

    #[test]
    fn s2190_distinct_arity_keeps_loop_ownership_base_cases_and_incomplete_sources() {
        let report = analyze_default(
            "class C { void Spin() { while (true) { void Local() { return; } Local(); } } int Fact(int n) { if (n <= 1) { return 1; } return Fact(n - 1); } }",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
        for source in [
            "class C { void Spin(bool done) { while (true) { if (done) { break; } } } }",
            "class C { int Fact(int n) { if (n <= 1) { return 1; } return Fact(n - 1); } }",
            "class C { int Broken(",
        ] {
            let report = analyze_default(source);
            assert!(with_key(&report, KEY).is_empty(), "{source:?}");
        }
    }
}
