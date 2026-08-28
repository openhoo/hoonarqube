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
    for site in &symbols.writes {
        let Some(field) = symbols.members.iter().find(|member| {
            member.flavor == MemberFlavor::Field
                && member.name == site.name
                && has_modifier(&modifiers_of(member.declaration, source), "static")
        }) else {
            continue;
        };
        if has_modifier(&modifiers_of(field.declaration, source), "const") {
            continue;
        }
        let Some(context) = nearest_ancestor_of_kinds(site.node, &TIER_B_MEMBER_KINDS) else {
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
                let left = binary_operands(site.node).map_or(site.node, |(left, _)| left);
                range_from_byte_offsets(
                    left.start_byte(),
                    source[left.end_byte()..site.node.end_byte()]
                        .find('=')
                        .map_or(left.end_byte(), |relative| left.end_byte() + relative + 1),
                    source,
                )
            },
        ));
    }
    issues
}
