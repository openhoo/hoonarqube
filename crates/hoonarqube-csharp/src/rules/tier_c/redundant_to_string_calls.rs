use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1858 — `.ToString()` on a receiver that already yields a
/// string. Subset: string/char/interpolated-string receivers only; calls on
/// typed variables need semantic typing and stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| callee_name(*call, source) == Some("ToString"))
        .filter(|call| {
            invocation_receiver(*call).is_some_and(|receiver| {
                matches!(
                    receiver.kind(),
                    "string_literal" | "character_literal" | "interpolated_string_expression"
                )
            })
        })
        .map(|call| {
            issue(
                language,
                "S1858",
                "Remove this redundant 'ToString' call.",
                range_of(call, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1858_minimal_input_emits_nothing() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1858").is_empty());
    }

    #[test]
    fn s1858_flags_hole_free_interpolated_receiver() {
        let report = analyze_default("var text = $\"summary\".ToString();\n");
        let flagged = with_key(&report, "csharpsquid:S1858");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s1858_integer_receiver_is_not_flagged() {
        let report = analyze_default("var digits = 42.ToString();\n");
        assert!(with_key(&report, "csharpsquid:S1858").is_empty());
    }

    #[test]
    fn s1858_chained_member_receiver_is_not_flagged() {
        let report = analyze_default("var trimmed = name.Trim().ToString();\n");
        assert!(with_key(&report, "csharpsquid:S1858").is_empty());
    }

    #[test]
    fn s1858_flags_two_calls_within_one_statement() {
        let report = analyze_default("var joined = $\"{1}\".ToString() + 'q'.ToString();\n");
        let flagged = with_key(&report, "csharpsquid:S1858");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 1);
    }
}
