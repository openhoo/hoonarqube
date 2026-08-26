use super::support::declared_type_names;
use super::support::is_predefined_value_type_text;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2995 — 'Object.ReferenceEquals' called with value-typed
/// arguments, where it can only ever return false. Subset: literal numeric/
/// bool/char arguments, or both arguments resolving through the file-local
/// declaration table to a predefined value type or a file-local struct.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const VALUE_LITERALS: [&str; 4] = [
        "integer_literal",
        "real_literal",
        "boolean_literal",
        "character_literal",
    ];
    let types = declared_type_names(root, source);
    let structs: std::collections::HashSet<&str> = collect_kinds(root, &["struct_declaration"])
        .into_iter()
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect();
    let value_typed = |operand: Node<'_>| -> bool {
        operand.kind() == "identifier"
            && types
                .get(node_text(operand, source))
                .is_some_and(|declared| {
                    is_predefined_value_type_text(declared)
                        || structs.contains(simple_name(declared))
                })
    };
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| callee_name(*call, source) == Some("ReferenceEquals"))
        .filter(|call| invocation_arguments(*call).len() == 2)
        .filter(|call| {
            let expressions: Vec<Node<'_>> = invocation_arguments(*call)
                .into_iter()
                .map(argument_expression)
                .collect();
            expressions.iter().any(|argument| VALUE_LITERALS.contains(&argument.kind()))
                || (value_typed(expressions[0]) && value_typed(expressions[1]))
        })
        .map(|call| {
            issue(
                language,
                "S2995",
                "'ReferenceEquals' always returns false for value types; compare with '==' or 'Equals' instead.",
                range_of(call, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2995_minimal_input_emits_nothing() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2995").is_empty());
    }

    #[test]
    fn s2995_flags_numeric_literal_pair() {
        let report = analyze_default("var same = ReferenceEquals(1, 2);\n");
        let flagged = with_key(&report, "csharpsquid:S2995");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s2995_flags_boolean_and_character_literals() {
        let report = analyze_default("var equal = ReferenceEquals('x', true);\n");
        let flagged = with_key(&report, "csharpsquid:S2995");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s2995_mixed_value_and_reference_identifiers_are_not_flagged() {
        let report = analyze_default(
            "struct Point\n{\n}\nclass Box\n{\n}\nvoid Compare(Point point, Box box)\n{\n    var mixed = ReferenceEquals(point, box);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2995").is_empty());
    }

    #[test]
    fn s2995_boundary_wrong_arity_calls_are_not_flagged() {
        let report = analyze_default(
            "var one = ReferenceEquals(single);\nvar three = ReferenceEquals(a, b, extra);\n",
        );
        assert!(with_key(&report, "csharpsquid:S2995").is_empty());
    }

    #[test]
    fn s2995_flags_struct_pair_and_literal_pair_on_distinct_lines() {
        let report = analyze_default(
            "struct Pair\n{\n}\nvoid Check(Pair left, Pair right)\n{\n    var structs = ReferenceEquals(left, right);\n    var literals = ReferenceEquals(3, 4);\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2995");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 7);
    }
}
