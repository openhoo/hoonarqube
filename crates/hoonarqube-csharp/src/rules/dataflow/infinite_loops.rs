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
        .filter(|call| !has_incompatible_fixed_arity(method, *call, source))
        .filter(|call| !has_incompatible_double_argument(method, *call, source));
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
fn has_incompatible_fixed_arity(method: Node<'_>, call: Node<'_>, source: &str) -> bool {
    if method.has_error() || call.has_error() {
        return false;
    }
    let Some((minimum, maximum)) = fixed_parameter_arity(method, source) else {
        return false;
    };
    positional_argument_count(call).is_some_and(|count| count < minimum || count > maximum)
}

fn fixed_parameter_arity(method: Node<'_>, source: &str) -> Option<(usize, usize)> {
    let parameters = method.child_by_field_name("parameters")?;
    let (mut minimum, mut maximum) = (0, 0);
    let mut cursor = parameters.walk();
    for child in parameters.children(&mut cursor) {
        match child.kind() {
            "(" | ")" | "," => {}
            "parameter" => {
                let optional = fixed_parameter_is_optional(child, source, maximum == 0)?;
                maximum += 1;
                minimum += usize::from(!optional);
            }
            _ => return None,
        }
    }
    Some((minimum, maximum))
}

fn fixed_parameter_is_optional(
    parameter: Node<'_>,
    source: &str,
    first_parameter: bool,
) -> Option<bool> {
    let parameter_type = parameter.child_by_field_name("type")?;
    let name = parameter.child_by_field_name("name")?;
    // A plain leading extension receiver is one required value parameter.
    // Ref/scoped modifiers, receiver defaults, attributes, and comments remain
    // outside this proof, including comments nested inside its type.
    if first_parameter
        && parameter.child_count() == 3
        && parameter.named_child_count() == 3
        && parameter.child(1) == Some(parameter_type)
        && parameter.child(2) == Some(name)
        && parameter.child(0).is_some_and(|modifier| {
            modifier.kind() == "modifier"
                && modifier.child_count() == 0
                && node_text(modifier, source) == "this"
        })
        && collect_kinds(parameter, &["comment"]).is_empty()
    {
        return Some(false);
    }
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

/// An explicit `double` argument cannot implicitly convert to an integral
/// value parameter. For this exact shape, a same-name call cannot target the
/// containing method, including when its parameter is an extension receiver.
fn has_incompatible_double_argument(method: Node<'_>, call: Node<'_>, source: &str) -> bool {
    if method.has_error() || call.has_error() {
        return false;
    }
    let Some(parameters) = method.child_by_field_name("parameters") else {
        return false;
    };
    let Some(parameter) = single_parenthesized_child(parameters, "parameter") else {
        return false;
    };
    let Some(parameter_type) = parameter.child_by_field_name("type") else {
        return false;
    };
    if parameter_type.kind() != "predefined_type"
        || !matches!(
            node_text(parameter_type, source),
            "byte" | "sbyte" | "short" | "ushort" | "int" | "uint" | "long" | "ulong"
        )
        || parameter.child_by_field_name("name").is_none()
    {
        return false;
    }
    // Defaults, attributes, comments, and every modifier except a lone `this`
    // are outside this proof. In particular, do not infer ref/params binding.
    match (parameter.child_count(), parameter.named_child_count()) {
        (2, 2) => {}
        (3, 3)
            if parameter.child(0).is_some_and(|modifier| {
                modifier.kind() == "modifier" && node_text(modifier, source) == "this"
            }) => {}
        _ => return false,
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let Some(argument) = single_parenthesized_child(arguments, "argument") else {
        return false;
    };
    if argument.child_count() != 1
        || argument.named_child_count() != 1
        || argument.child_by_field_name("name").is_some()
    {
        return false;
    }
    first_named_child(argument).is_some_and(|cast| {
        cast.kind() == "cast_expression"
            && cast.child_count() == 4
            && cast.named_child_count() == 2
            && cast.child_by_field_name("type").is_some_and(|target| {
                target.kind() == "predefined_type" && node_text(target, source) == "double"
            })
    })
}

fn single_parenthesized_child<'a>(list: Node<'a>, kind: &str) -> Option<Node<'a>> {
    (list.child_count() == 3 && list.named_child_count() == 1)
        .then(|| list.named_child(0))
        .flatten()
        .filter(|child| child.kind() == kind)
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

    #[test]
    fn s2190_double_cast_cannot_recur_into_an_integral_value_parameter() {
        for integral in [
            "byte", "sbyte", "short", "ushort", "int", "uint", "long", "ulong",
        ] {
            for modifier in ["", "this "] {
                let source = format!(
                    "static class C {{ static double Forward({modifier}{integral} value) {{ return Forward((double)value); }} static double Forward(double value) {{ return value; }} }}"
                );
                let report = analyze_default(&source);
                assert!(with_key(&report, KEY).is_empty(), "{source:?}");
            }
        }
    }

    #[test]
    fn s2190_numeric_proof_preserves_same_type_and_widening_self_recursion() {
        for source in [
            "class C { int Loop(int value) { return Loop((int)value); } }",
            "class C { int Loop(int value) { return Loop(value); } }",
            "class C { double Loop(double value) { return Loop((int)value); } }",
            "class C { double Loop(double value) { return Loop((float)value); } }",
            "class C { double Loop(double value) { return Loop((double)value); } }",
            "class C { long Loop(long value) { return Loop((int)value); } }",
            "static class C { static int Loop(this int value) { return Loop((int)value); } }",
        ] {
            let report = analyze_default(source);
            let found = with_key(&report, KEY);
            assert_eq!(found.len(), 1, "{source:?}");
            assert_eq!(
                found[0].message,
                "Add a way to break out of this method's recursion."
            );
            assert!(found[0].fix.is_none());
            assert!(found[0].alternatives.is_empty());
            assert!(found[0].flows.is_empty());
        }
    }

    #[test]
    fn s2190_numeric_proof_refuses_unresolved_types_modifiers_and_arguments() {
        for source in [
            "class C { int Loop(int value = 0) { return Loop((double)value); } }",
            "class C { int Loop([A] int value) { return Loop((double)value); } }",
            "class C { int Loop(ref int value) { return Loop((double)value); } }",
            "class C { int Loop(out int value) { return Loop((double)value); } }",
            "class C { int Loop(in int value) { return Loop((double)value); } }",
            "class C { int Loop(scoped ref int value) { return Loop((double)value); } }",
            "static class C { static int Loop(this ref int value) { return Loop((double)value); } }",
            "class C { int Loop(params int[] value) { return Loop((double)value[0]); } }",
            "class C { int Loop(int? value) { return Loop((double)value); } }",
            "class C { int Loop(System.Int32 value) { return Loop((double)value); } }",
            "using I = System.Int32; class C { int Loop(I value) { return Loop((double)value); } }",
            "class C { int Loop(dynamic value) { return Loop((double)value); } }",
            "class C<T> { int Loop(T value) { return Loop((double)value); } }",
            "class C { int Loop(int value) { return Loop(value: (double)value); } }",
            "class C { int Loop(int value) { return Loop(in value); } }",
            "class C { int Loop(int value) { return Loop((System.Double)value); } }",
            "class C { int Loop(int value) { return Loop((double?)value); } }",
            "class C { int Loop(int value) { return Loop(((double)value)); } }",
            "class C { int Loop(int value) { return Loop((long)value); } }",
            "class C { int Loop(char value) { return Loop((double)value); } }",
            "class C { int Loop(float value) { return Loop((double)value); } }",
            "class C { int Loop(int /* parameter */ value) { return Loop((double)value); } }",
            "class C { int Loop(int value) { return Loop(/* argument */ (double)value); } }",
            "class C { int Loop(int value) { return Loop((/* cast */ double)value); } }",
            "class C { int Loop(int value, int extra) { return Loop((double)value, extra); } }",
        ] {
            let report = analyze_default(source);
            assert_eq!(with_key(&report, KEY).len(), 1, "{source:?}");
        }
    }

    #[test]
    fn s2190_numeric_proof_keeps_loop_ownership_base_cases_and_malformed_sources() {
        let report = analyze_default(
            "class C { void Spin() { while (true) { void Local() { return; } Local(); } } int Guarded(int value) { if (value <= 0) { return 0; } return Guarded((int)value); } }",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
        for source in [
            "class C { int Broken(",
            "class C { int Broken(int value) { return Broken((double)); } }",
            "class C { void Escapes(bool done) { while (true) { if (done) { break; } } } }",
        ] {
            let report = analyze_default(source);
            assert!(with_key(&report, KEY).is_empty(), "{source:?}");
        }
    }

    const EXTENSION_ARITY_REFERENCE: &str = r"public static class ExtensionControls
{
    public static int OptionalForward(this int value, int a = 0, int b = 0,
        int c = 0, int d = 0, int e = 0, int f = 0)
    {
        return OptionalForward(value, a, b, c, d, e, f, 0);
    }

    public static int OptionalForward(int value, int a, int b, int c,
        int d, int e, int f, int g)
    {
        return value + a + b + c + d + e + f + g;
    }

    public static int ArityForward(this int value, int repeat)
    {
        return ArityForward(value, repeat, 0, 0);
    }

    public static int ArityForward(int value, int repeat, int a, int b)
    {
        return value + repeat + a + b;
    }

    public static int TrueSelf(this int value)
    {
        return TrueSelf(value);
    }

    public static int OptionalSelf(this int value, int repeat = 0)
    {
        return OptionalSelf(value);
    }

    public static int ExplicitOptionalSelf(this int value, int repeat = 0)
    {
        return ExplicitOptionalSelf(value, repeat);
    }

    public static int SameTypeSelf(this int value)
    {
        return SameTypeSelf(value + 1);
    }

    public static int Finite(this int value, int count)
    {
        if (count <= 0) return value;
        return Finite(value, count - 1);
    }
}
";

    #[test]
    fn s2190_extension_arity_matches_compiled_reference() {
        let report = analyze_default(EXTENSION_ARITY_REFERENCE);
        let issues = with_key(&report, KEY);
        assert_eq!(issues.len(), 4, "{issues:?}");
        for (issue, (line, end)) in issues.iter().zip([(25, 30), (30, 34), (35, 42), (40, 34)]) {
            assert_eq!(
                (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.range.end.line,
                    issue.range.end.column
                ),
                (line, 22, line, end)
            );
            assert_eq!(
                issue.message,
                "Add a way to break out of this method's recursion."
            );
            assert!(issue.fix.is_none());
            assert!(issue.alternatives.is_empty());
            assert!(issue.flows.is_empty());
        }
    }

    #[test]
    fn s2190_extension_arity_removes_two_humanizer_forwarders() {
        let report = analyze_default(
            r#"using System;
using System.Globalization;
public static class HumanizerShapes
{
    public static string Humanize(this TimeSpan timeSpan, int precision = 1, CultureInfo culture = null, TimeUnit maxUnit = TimeUnit.Week, TimeUnit minUnit = TimeUnit.Millisecond, string collectionSeparator = ", ", bool toWords = false)
    {
        return Humanize(timeSpan, precision, false, culture, maxUnit, minUnit, collectionSeparator, toWords);
    }
    public static string Humanize(this TimeSpan timeSpan, int precision, bool countEmptyUnits, CultureInfo culture = null, TimeUnit maxUnit = TimeUnit.Week, TimeUnit minUnit = TimeUnit.Millisecond, string collectionSeparator = ", ", bool toWords = false) { return string.Empty; }
    public static string ToQuantity(this string input, double quantity)
    {
        return ToQuantity(input, quantity, null, null);
    }
    public static string ToQuantity(this string input, double quantity, string format = null, IFormatProvider formatProvider = null) { return input; }
}
"#,
        );
        let issues = with_key(&report, KEY);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn s2190_extension_arity_preserves_recursion_and_unsupported_shapes() {
        for source in [
            "static class C { static int Loop(this int value) { return Loop(value); } }",
            "static class C { static int Loop(this int value, int repeat = 0) { return Loop(value); } }",
            "static class C { static int Loop(this int value, int repeat = 0) { return Loop(value, repeat); } }",
            "static class C { static int Loop(this int value) { return Loop((int)value); } }",
            "static class C { static double Loop(this double value) { return Loop((int)value); } }",
            "static class C { static int Loop(this ref int value) { return Loop(value, 0); } }",
            "static class C { static int Loop(this in int value) { return Loop(value, 0); } }",
            "static class C { static int Loop(this scoped ref int value) { return Loop(value, 0); } }",
            "static class C { static int Loop([A] this int value) { return Loop(value, 0); } }",
            "static class C { static int Loop(this /* receiver */ int value) { return Loop(value, 0); } }",
            "static class C { static int Loop(this int /* parameter */ value) { return Loop(value, 0); } }",
            "static class C { static int Loop(this int value, [A] int repeat = 0) { return Loop(value, 0, 0); } }",
            "static class C { static int Loop(this int value, params int[] rest) { return Loop(value, 0, 0); } }",
            "static class C { static int Loop(this int value) { return Loop(ref value, 0); } }",
            "static class C { static int Loop(this int value) { return Loop(out value, 0); } }",
            "static class C { static int Loop(this int value) { return Loop(/* argument */ value, 0); } }",
            "static class C { static int Loop(int value, this int other) { return Loop(value, other, 0); } }",
            "static class C { static int Loop(this int value = 0) { return Loop(value, 0); } }",
            "static class C { static int Loop(this System.Collections.Generic.List</* type */ int> value) { return Loop(value, 0); } }",
        ] {
            let report = analyze_default(source);
            let issues = with_key(&report, KEY);
            assert_eq!(issues.len(), 1, "{source:?}: {issues:?}");
            assert_eq!(
                issues[0].message,
                "Add a way to break out of this method's recursion."
            );
            assert!(issues[0].fix.is_none());
            assert!(issues[0].alternatives.is_empty());
            assert!(issues[0].flows.is_empty());
        }
    }

    #[test]
    fn s2190_extension_arity_keeps_loop_ownership_base_cases_and_coordinates() {
        let source = "static class C { /* 😀 */ static int Vélo(this int value) { return Vélo(value); } }\r\n";
        let report = analyze_default(source);
        let issues = with_key(&report, KEY);
        assert_eq!(issues.len(), 1);
        let start = u32::try_from(source[..source.find("Vélo").unwrap()].chars().count()).unwrap();
        assert_eq!(
            (
                issues[0].range.start.line,
                issues[0].range.start.column,
                issues[0].range.end.line,
                issues[0].range.end.column
            ),
            (1, start, 1, start + 4)
        );
        let report = analyze_default(
            "static class C { static int Guarded(this int value) { if (value <= 0) return 0; return Guarded(value - 1); } static void Spin() { while (true) { void Local() { return; } Local(); } } }",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
        for source in [
            "static class C { static int Broken(",
            "static class C { static int Broken(this int value) { return Broken(,); } }",
        ] {
            assert!(
                with_key(&analyze_default(source), KEY).is_empty(),
                "{source:?}"
            );
        }
    }

    #[test]
    fn s2190_named_arity_migrates_prior_overload_boundary() {
        let source = r"class C { int Forward(int n) { return Forward(extra: 0, n: n); } int Forward(int n, int extra) { return n + extra; } }";
        let report = analyze_default(source);
        assert!(with_key(&report, KEY).is_empty(), "{source:?}");
    }

    #[test]
    fn s2190_named_arity_migrates_prior_extension_boundary() {
        let source = r"static class C { static int Loop(this int value) { return Loop(value: value, repeat: 0); } }";
        let report = analyze_default(source);
        assert!(with_key(&report, KEY).is_empty(), "{source:?}");
    }

    const NAMED_ARITY_REFERENCE: &str = r"public static class NamedControls
{
    public static int TooMany(int value)
    {
        return TooMany(value, repeat: 0);
    }

    public static int TooMany(int value, int repeat)
    {
        return value + repeat;
    }

    public static int OptionalTooMany(int value, int repeat = 0)
    {
        return OptionalTooMany(value, repeat, extra: 0);
    }

    public static int OptionalTooMany(int value, int repeat, int extra)
    {
        return value + repeat + extra;
    }

    public static int NamedFirst(int value)
    {
        return NamedFirst(value: value, 0);
    }

    public static int NamedFirst(int value, int repeat)
    {
        return value + repeat;
    }

    public static int TooFew(int value, int repeat)
    {
        return TooFew(value: value);
    }

    public static int TooFew(int value)
    {
        return value;
    }

    public static int TrueSelf(int value)
    {
        return TrueSelf(value: value);
    }

    public static int OptionalSelf(int value, int repeat = 0)
    {
        return OptionalSelf(value: value);
    }

    public static int ReorderedSelf(int value, int repeat)
    {
        return ReorderedSelf(repeat: repeat, value: value);
    }

    public static int MixedSelf(int value, int repeat)
    {
        return MixedSelf(value, repeat: repeat);
    }

    public static int Finite(int value)
    {
        if (value <= 0) return 0;
        return Finite(value: value - 1);
    }
}
";

    #[test]
    fn s2190_named_arity_matches_compiled_reference() {
        let report = analyze_default(NAMED_ARITY_REFERENCE);
        let issues = with_key(&report, KEY);
        assert_eq!(issues.len(), 4, "{issues:?}");
        for (issue, (line, end)) in issues.iter().zip([(43, 30), (48, 34), (53, 35), (58, 31)]) {
            assert_eq!(
                (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.range.end.line,
                    issue.range.end.column
                ),
                (line, 22, line, end)
            );
            assert_eq!(
                issue.message,
                "Add a way to break out of this method's recursion."
            );
            assert!(issue.fix.is_none());
            assert!(issue.alternatives.is_empty());
            assert!(issue.flows.is_empty());
        }
    }

    #[test]
    fn s2190_named_arity_removes_only_incompatible_ordinary_value_calls() {
        for source in [
            r"class C { string ToString(string format, System.IFormatProvider provider) { return ToString(format, provider, toSymbol: true); } string ToString(string format, System.IFormatProvider provider, bool toSymbol) { return format; } }",
            r"class C { int Forward(int value) { return Forward(value: value, 0); } int Forward(int value, int repeat) { return value + repeat; } }",
            r"class C { int Forward(int value, int repeat) { return Forward(value: value); } int Forward(int value) { return value; } }",
            r"class C { int Forward(int value, int repeat = 0) { return Forward(value, repeat, extra: 0); } int Forward(int value, int repeat, int extra) { return value + repeat + extra; } }",
            r"class C { int Forward(int value) { return Forward(value: (true ? (value, 1).Item1 : 0), repeat: 0); } int Forward(int value, int repeat) { return value + repeat; } }",
            r"class C { int Forward(int value) { return Forward(value: (first: value, second: 0).first, repeat: 0); } int Forward(int value, int repeat) { return value + repeat; } }",
            r"class C { int Forward(int value) { return Forward(_value2: value, _extra3: 0); } }",
        ] {
            let report = analyze_default(source);
            assert!(with_key(&report, KEY).is_empty(), "{source:?}");
        }
    }

    #[test]
    fn s2190_named_arity_preserves_recursion_and_unrecognized_arguments() {
        for source in [
            r"class C { int Loop(int value) { return Loop(value: value); } }",
            r"class C { int Loop(int value = 0) { return Loop(value: value); } }",
            r"class C { int Loop(int value, int repeat = 0) { return Loop(value: value); } }",
            r"class C { int Loop(int value, int repeat) { return Loop(repeat: repeat, value: value); } }",
            r"class C { int Loop(int value, int repeat) { return Loop(value, repeat: repeat); } }",
            r"class C { int Loop(int value) { return Loop(other: value); } }",
            r"class C { int Loop(int value) { return Loop(value: (double)value); } }",
            r"class C { int Loop(int value) { return Loop(value: value, value: 0); } }",
            r"class C { int Loop(int value) { return Loop(value: value, @value: 0); } }",
            r"class C { int Loop(int value) { return Loop(value: value, v\u0061lue: 0); } }",
            r"class C { int Loop(int value) { return Loop(välue: value, repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(value: ref value, repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(value: out value, repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(value: in value, repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(ref value, repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(out int other, repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(value: out int other, repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(value /* name */: value, repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(value: /* expression */ value, repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(value: (value /* nested */), repeat: 0); } }",
            r"class C { int Loop(int value) { return Loop(value: value, /* list */ repeat: 0); } }",
            r"class C { int Loop([A] int value) { return Loop(value: value, repeat: 0); } }",
            r"class C { int Loop(params int[] values) { return Loop(values: values, extra: 0); } }",
            r"class C { int Loop(ref int value) { return Loop(value: value, repeat: 0); } }",
            r"static class C { static int Loop(this ref int value) { return Loop(value: value, repeat: 0); } }",
        ] {
            let report = analyze_default(source);
            let issues = with_key(&report, KEY);
            assert_eq!(issues.len(), 1, "{source:?}: {issues:?}");
            assert_eq!(
                issues[0].message,
                "Add a way to break out of this method's recursion."
            );
            assert!(issues[0].fix.is_none());
            assert!(issues[0].alternatives.is_empty());
            assert!(issues[0].flows.is_empty());
        }
    }
}
