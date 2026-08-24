use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{MemberFlavor, UsageSymbols, is_private_member, owner_is_partial};
use hoonarqube_ir::Issue;

/// csharpsquid:S3459 — private fields that are read but never assigned.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers_of(member.declaration, source), "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.has_initializer
            || !symbols.writes_of(member.name).is_empty()
            || symbols.uses_of(member.name).is_empty()
        {
            continue;
        }
        issues.push(issue(
            language,
            "S3459",
            format!(
                "Remove unassigned field '{}' or assign it a value.",
                member.name
            ),
            range_of(member.anchor),
        ));
    }
    issues
}
