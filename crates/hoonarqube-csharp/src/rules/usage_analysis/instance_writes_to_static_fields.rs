use super::support::member_writes;
use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, range_from_byte_offsets};
use crate::rules::expressions::binary_operands;
use crate::rules::modifiers::has_modifier;
use crate::symbol_table::{
    MemberFlavor, TIER_B_MEMBER_KINDS, UsageSymbols, nearest_ancestor_of_kinds,
};
use hoonarqube_ir::Issue;

/// csharpsquid:S2696 — instance members must not write shared static state.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in &symbols.members {
        if field.flavor != MemberFlavor::Field
            || !has_modifier(&modifiers_of(field.declaration, source), "static")
            || has_modifier(&modifiers_of(field.declaration, source), "const")
        {
            continue;
        }
        for site in member_writes(symbols, field, source) {
            let Some(context) = nearest_ancestor_of_kinds(site, &TIER_B_MEMBER_KINDS) else {
                continue;
            };
            if context.kind() == "constructor_declaration"
                || has_modifier(&modifiers_of(context, source), "static")
            {
                continue;
            }
            issues.push(issue(
                language,
                "S2696",
                "Make the enclosing instance method 'static' or remove this set on the 'static' field.",
                {
                    let left = binary_operands(site).map_or(site, |(left, _)| left);
                    range_from_byte_offsets(
                        left.start_byte(),
                        source[left.end_byte()..site.end_byte()]
                            .find('=')
                            .map_or(left.end_byte(), |relative| left.end_byte() + relative + 1),
                        source,
                    )
                },
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2696_does_not_resolve_unrelated_instance_field_as_static() {
        let report = analyze_default(
            "class A\n{\n    private static int shared;\n}\n\nclass B\n{\n    private int shared;\n    public void Set() { shared = 1; }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2696").is_empty());
    }

    #[test]
    fn s2696_reports_each_owner_scoped_static_write_once() {
        let report = analyze_default(
            "class A\n{\n    private static int shared;\n    public void Set() { shared = 1; }\n}\n\nclass B\n{\n    private static int shared;\n    public void Set() { shared = 2; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2696");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 4);
        assert_eq!(flagged[1].range.start.line, 10);
    }
}
