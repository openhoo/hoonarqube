use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, range_of};
use crate::rules::naming::has_explicit_interface_specifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, UsageSymbols, has_contract_modifier, is_private_member, owner_is_partial,
};
use hoonarqube_ir::Issue;

/// csharpsquid:S4487 — private members nobody references are dead weight.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        let modifiers = modifiers_of(member.declaration, source);
        if !is_private_member(member.declaration, source, member.nested_type)
            || has_contract_modifier(&modifiers)
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.name == "Main"
            || (member.flavor == MemberFlavor::Method
                && has_explicit_interface_specifier(member.declaration))
            || !symbols.uses_of(member.name).is_empty()
        {
            continue;
        }
        issues.push(issue(
            language,
            "S4487",
            format!(
                "Remove the unused private {} '{}'.",
                member.flavor.word(),
                member.name
            ),
            range_of(member.anchor),
        ));
    }
    issues
}
