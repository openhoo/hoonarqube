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
                    range_of(reference),
                ));
            }
        }
    }
    issues
}
