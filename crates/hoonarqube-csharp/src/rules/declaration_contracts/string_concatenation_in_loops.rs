use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{
    LOOP_KINDS, binary_operands, declares_string_local, expression_name, first_named_child,
    operator_of,
};
use crate::rules::modifiers::has_ancestor_with_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1643 — `+=` concatenation in a loop is quadratic; use a
/// `StringBuilder`. String evidence comes from a string-literal operand or a
/// `string`-typed left-hand local.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| operator_of(*assignment) == Some("+="))
        .filter(|assignment| has_ancestor_with_kind(*assignment, &LOOP_KINDS))
        .filter(|assignment| {
            let Some((left, right)) = binary_operands(*assignment) else {
                return false;
            };
            !collect_kinds(right, &["string_literal"]).is_empty()
                || left
                    .child_by_field_name("name")
                    .or_else(|| first_named_child(left))
                    .and_then(|identifier| expression_name(identifier, source))
                    .is_some_and(|name| declares_string_local(left, name, source))
        })
        .map(|assignment| {
            issue(
                language,
                "S1643",
                "Use a 'StringBuilder' instead of '+=' concatenation in this loop.",
                range_of(assignment, source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1643_flags_do_and_foreach_loop_shapes() {
        let do_loop = analyze_default(
            "class C\n{\n    string Build()\n    {\n        var text = \"\";\n        do\n        {\n            text += \"!\";\n        }\n        while (More());\n        return text;\n    }\n}\n",
        );
        assert_eq!(with_key(&do_loop, "csharpsquid:S1643").len(), 1);

        let foreach_loop = analyze_default(
            "class C\n{\n    string Join(string[] parts)\n    {\n        var acc = \"\";\n        foreach (var part in parts)\n        {\n            acc += \".\";\n        }\n        return acc;\n    }\n}\n",
        );
        assert_eq!(with_key(&foreach_loop, "csharpsquid:S1643").len(), 1);
    }

    #[test]
    fn s1643_flags_concatenation_nested_in_conditionals() {
        let report = analyze_default(
            "class C\n{\n    string Build(bool loud)\n    {\n        var text = \"\";\n        while (More())\n        {\n            if (loud)\n            {\n                text += \"!\";\n            }\n        }\n        return text;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1643").len(), 1);
    }

    #[test]
    fn s1643_counts_each_compound_assignment() {
        let report = analyze_default(
            "class C\n{\n    string Build()\n    {\n        var text = \"<\";\n        while (More())\n        {\n            text += \"a\";\n            text += \">\";\n        }\n        return text;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1643").len(), 2);
    }

    #[test]
    fn s1643_spares_plain_string_assignment_in_loops() {
        let report = analyze_default(
            "class C\n{\n    string Replace()\n    {\n        var text = \"a\";\n        while (More())\n        {\n            text = text + \"b\";\n        }\n        return text;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1643").is_empty());
    }
}
