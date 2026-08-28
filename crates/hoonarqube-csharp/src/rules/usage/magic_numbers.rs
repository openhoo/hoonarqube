use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::integer_literal_value;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

fn canonical_number_text(text: &str) -> String {
    let unsuffixed = text.trim_end_matches(['f', 'F', 'd', 'D', 'm', 'M', 'u', 'U', 'l', 'L']);
    let normalized = unsuffixed.replace('_', "");
    normalized
        .parse::<f64>()
        .map_or(normalized.clone(), |value| value.to_string())
}

/// csharpsquid:S109 — numbers beyond -1/0/1 deserve names.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["integer_literal", "real_literal"])
        .into_iter()
        .filter(|literal| {
            !magic_number_exempt(*literal, source)
                && !is_small_allowed_number(node_text(*literal, source))
        })
        .map(|literal| {
            let value = canonical_number_text(node_text(literal, source));
            issue(
                language,
                "S109",
                format!("Assign this magic number '{value}' to a well-named variable or constant, and use that instead."),
                range_of(literal, source),
            )
        })
        .collect()
}

/// Whether a numeric literal's value is exactly -1, 0, or 1.
#[allow(clippy::float_cmp)] // 0.0/1.0 are exactly representable; exact match is the intent
fn is_small_allowed_number(text: &str) -> bool {
    if let Some(value) = integer_literal_value(text) {
        return value <= 1;
    }
    // Real literals: compare parsed values; 0.0 and 1.0 are exactly
    // representable, so equality stays deterministic across spellings
    // (exponents, suffixes, digit separators).
    let base = text
        .strip_suffix(['f', 'F', 'd', 'D', 'm', 'M'])
        .unwrap_or(text);
    base.replace('_', "")
        .parse::<f64>()
        .is_ok_and(|value| value == 0.0 || value == 1.0)
}

/// Contexts where even large numbers are not magic: enumeration members,
/// constant declarations, and parameter defaults.
fn magic_number_exempt(mut literal: Node<'_>, source: &str) -> bool {
    while let Some(parent) = literal.parent() {
        match parent.kind() {
            "enum_member_declaration" | "parameter" => return true,
            "field_declaration" | "local_declaration_statement" => {
                return has_modifier(&modifiers_of(parent, source), "const");
            }
            _ => {}
        }
        literal = parent;
    }
    false
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s109_flags_real_literal_exponent_forms() {
        let report = analyze_default(
            "class C\n{\n    double A()\n    {\n        double a = 1e2;\n        double b = 2.5e-1;\n        double c = 1.5e2;\n        return a + b + c;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S109").len(), 3);
    }

    #[test]
    fn s109_allows_exact_zero_and_one_real_spellings() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        double a = 0.0;\n        double b = 0.00f;\n        double c = 1.000m;\n        double d = 01.00;\n        double e = -1.0;\n        Use(a, b, c, d, e);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S109").is_empty());
    }

    #[test]
    fn s109_allows_exponent_spellings_of_zero_and_one() {
        let report = analyze_default(
            "class C\n{\n    double M()\n    {\n        double a = 1e0;\n        double b = 0e0;\n        double c = 1.0e0;\n        return a + b + c;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S109").is_empty());
    }

    #[test]
    fn s109_flags_integer_suffixes_and_digit_separators() {
        let report = analyze_default(
            "class C\n{\n    int M(int n)\n    {\n        int a = n * 2u;\n        int b = n * 3L;\n        int c = n * 1_000;\n        int d = n * 10_0;\n        return a + b + c + d;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S109").len(), 4);
    }

    #[test]
    fn s109_allows_small_values_behind_signs_and_suffixes() {
        let report = analyze_default(
            "class C\n{\n    int M(int n)\n    {\n        int a = n * -1;\n        int b = n * 0u;\n        long c = n + 1L;\n        return (int)(a + b + c);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S109").is_empty());
    }

    #[test]
    fn s109_flags_negatives_beyond_minus_one() {
        let report = analyze_default(
            "class C\n{\n    int M(int x, int y, int z)\n    {\n        int a = x * -7;\n        double b = y - 2.5;\n        int c = z * -2;\n        return a + (int)b + c;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S109").len(), 3);
    }

    #[test]
    fn s109_exempts_only_the_documented_constant_contexts() {
        let report = analyze_default(
            "class C\n{\n    const int Limit = 500;\n    int offset = 800;\n    int Prop { get; set; } = 12;\n    enum E\n    {\n        Max = 600,\n    }\n    int M(int retries = 7)\n    {\n        const int cap = 9;\n        int plain = 11;\n        return retries + cap + plain + Log(42);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S109").len(), 4);
    }

    #[test]
    fn s109_honors_const_fields_inside_nested_types() {
        let report = analyze_default(
            "class Outer\n{\n    class Inner\n    {\n        const int Cap = 400;\n        int Break() => 300;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S109").len(), 1);
    }

    #[test]
    fn s109_counts_every_occurrence_in_an_expression() {
        let report = analyze_default("class C\n{\n    int Sum() => 2 + 2 + 2 + 1;\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S109").len(), 3);
    }

    #[test]
    fn s109_allows_binary_zero_and_one_but_flags_larger() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        int flags = 0b0;\n        int mask = 0b1;\n        int big = 0b100;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S109");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }
}
