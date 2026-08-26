use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::has_modifier;
use crate::symbol_table::{MemberFlavor, MemberSymbol, UsageSymbols};
use hoonarqube_ir::Issue;

/// csharpsquid:S3263 — static field initializers reading later static
/// fields depend on unspecified initialization order.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_symbol in &symbols.types {
        let static_fields: Vec<&MemberSymbol> = symbols
            .members
            .iter()
            .filter(|member| {
                member.owner == type_symbol.declaration
                    && member.flavor == MemberFlavor::Field
                    && member.is_static_or_const
                    && !has_modifier(&modifiers_of(member.declaration, source), "const")
            })
            .collect();
        for field in &static_fields {
            let Some(declarator) = field.anchor.parent() else {
                continue;
            };
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(initializer) = declarator_initializer(declarator, name) else {
                continue;
            };
            let initializer_start = field.anchor.byte_range().start;
            for reference in collect_kinds(initializer, &["identifier"]) {
                let referenced = node_text(reference, source);
                if referenced == field.name
                    || !static_fields.iter().any(|sibling| {
                        sibling.name == referenced
                            && sibling.anchor.byte_range().start > initializer_start
                    })
                {
                    continue;
                }
                issues.push(issue(
                    language,
                    "S3263",
                    format!(
                        "'{referenced}' is declared after '{}'; static initialization order makes this read unreliable.",
                        field.name
                    ),
                    range_of(reference, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3263_minimal_class_produces_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3263").is_empty());
    }

    #[test]
    fn s3263_flags_two_forward_references_with_messages() {
        let report = analyze_default(
            "class C\n{\n    private static int first = second + third;\n    private static int second = 1;\n    private static int third = 2;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3263");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(
            flagged[0].message,
            "'second' is declared after 'first'; static initialization order makes this read unreliable."
        );
        assert_eq!(
            flagged[1].message,
            "'third' is declared after 'first'; static initialization order makes this read unreliable."
        );
    }

    #[test]
    fn s3263_ignores_self_references() {
        let report = analyze_default("class C\n{\n    private static int total = total + 1;\n}\n");
        assert!(with_key(&report, "csharpsquid:S3263").is_empty());
    }

    #[test]
    fn s3263_ignores_const_and_instance_siblings_declared_later() {
        let const_sibling = analyze_default(
            "class C\n{\n    private static int total = Rate + 1;\n    private const int Rate = 5;\n}\n",
        );
        assert!(with_key(&const_sibling, "csharpsquid:S3263").is_empty());

        let instance_sibling = analyze_default(
            "class C\n{\n    private static int total = other + 1;\n    private int other;\n}\n",
        );
        assert!(with_key(&instance_sibling, "csharpsquid:S3263").is_empty());
    }

    #[test]
    fn s3263_accepts_backward_references_and_skips_uninitialized_fields() {
        let report = analyze_default(
            "class C\n{\n    private static int later;\n    private static int eager = later;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3263").len(), 0);

        let uninitialized = analyze_default("class C\n{\n    private static int pending;\n}\n");
        assert!(with_key(&uninitialized, "csharpsquid:S3263").is_empty());
    }
}
