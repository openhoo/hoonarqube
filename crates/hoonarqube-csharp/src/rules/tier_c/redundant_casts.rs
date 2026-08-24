use super::support::FLOATING_TYPES;
use super::support::INTEGER_TYPES;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1905 — casts of literals to their own obvious type. Subset:
/// predefined-type targets over scalar literals; user-defined conversions,
/// nullable targets, and casts of computed expressions stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["cast_expression"])
        .into_iter()
        .filter(|cast| !is_error_tainted(*cast))
        .filter_map(|cast| {
            let type_node = cast.child_by_field_name("type")?;
            let value = cast.child_by_field_name("value")?;
            let type_text = node_text(type_node, source);
            if type_text.contains('?') {
                return None;
            }
            let target = simple_name(type_text);
            let redundant = match value.kind() {
                "integer_literal" => INTEGER_TYPES.contains(&target),
                "real_literal" => FLOATING_TYPES.contains(&target),
                "string_literal" => target == "string",
                "character_literal" => target == "char",
                "boolean_literal" => target == "bool",
                _ => false,
            };
            redundant.then_some(cast)
        })
        .map(|cast| {
            issue(
                language,
                "S1905",
                "Remove this redundant cast.",
                range_of(cast),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1905_minimal_input_emits_nothing() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1905").is_empty());
    }

    #[test]
    fn s1905_flags_floating_casts_on_distinct_lines() {
        let report = analyze_default("float scale = (float)1.5;\ndouble precise = (double)2.25;\n");
        let flagged = with_key(&report, "csharpsquid:S1905");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 2);
    }

    #[test]
    fn s1905_flags_char_cast() {
        let report = analyze_default("char initial = (char)'i';\n");
        let flagged = with_key(&report, "csharpsquid:S1905");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s1905_computed_expression_cast_is_not_flagged() {
        let report = analyze_default("var sum = (int)(1 + 2);\n");
        assert!(with_key(&report, "csharpsquid:S1905").is_empty());
    }

    #[test]
    fn s1905_nullable_targets_are_not_flagged() {
        let report = analyze_default("int? maybe = (int?)7;\ndouble? ratio = (double?)1.5;\n");
        assert!(with_key(&report, "csharpsquid:S1905").is_empty());
    }

    #[test]
    fn s1905_user_defined_type_target_is_not_flagged() {
        let report = analyze_default("var parsed = (CustomId)42;\n");
        assert!(with_key(&report, "csharpsquid:S1905").is_empty());
    }
}
