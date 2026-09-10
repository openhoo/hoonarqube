use super::support::INTEGER_TYPES;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, range_from_byte_offsets, range_of,
    simple_name,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1905 — redundant conversions with a narrow source-backed subset:
/// scalar casts remain the local historical check, while this rule also models
/// the compiler-obvious string-literal `as string` case handled by Sonar's
/// `AsExpression` provider.  General expressions and user-defined conversions
/// stay uncovered because this syntax-only rule cannot prove their binding.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = collect_kinds(root, &["cast_expression"])
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
            let value_text = node_text(value, source);
            let redundant = match value.kind() {
                "integer_literal" => INTEGER_TYPES.contains(&target),
                "real_literal" => match target {
                    "double" => !value_text.ends_with(['f', 'F', 'm', 'M']),
                    "float" => value_text.ends_with(['f', 'F']),
                    "decimal" => value_text.ends_with(['m', 'M']),
                    _ => false,
                },
                "string_literal" => target == "string",
                "character_literal" => target == "char",
                "boolean_literal" => target == "bool",
                _ => false,
            };
            redundant.then_some((type_node, target.to_owned()))
        })
        .map(|(type_node, target)| {
            issue(
                language,
                "S1905",
                format!("Remove this unnecessary cast to '{target}'."),
                range_of(type_node, source),
            )
        })
        .collect::<Vec<_>>();

    for expression in collect_kinds(root, &["as_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some(left) = expression.child_by_field_name("left") else {
            continue;
        };
        let Some(operator) = expression.child_by_field_name("operator") else {
            continue;
        };
        let Some(right) = expression.child_by_field_name("right") else {
            continue;
        };
        if node_text(left, source).is_empty()
            || left.kind() != "string_literal"
            || node_text(right, source) != "string"
            || node_text(operator, source) != "as"
        {
            continue;
        }
        let range = range_from_byte_offsets(operator.start_byte(), right.end_byte(), source);
        issues.push(issue(
            language,
            "S1905",
            "Remove this unnecessary cast to 'string'.",
            range,
        ));
    }
    issues
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
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 2);
    }

    #[test]
    fn s1905_flags_char_cast() {
        let report = analyze_default("char initial = (char)'i';\n");
        let flagged = with_key(&report, "csharpsquid:S1905");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s1905_flags_redundant_string_as_expression() {
        let report = analyze_default("string value = \"x\" as string;\n");
        let flagged = with_key(&report, "csharpsquid:S1905");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.column, 19);
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
