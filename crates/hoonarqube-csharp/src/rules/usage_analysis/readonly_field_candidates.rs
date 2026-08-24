use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, UsageSymbols, is_matching_constructor_write, is_private_member,
    is_ref_or_out_argument, owner_is_partial,
};
use hoonarqube_ir::Issue;

/// csharpsquid:S2933 — private fields written only from constructors can
/// carry the `readonly` promise.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        let modifiers = modifiers_of(member.declaration, source);
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers, "readonly")
            || has_modifier(&modifiers, "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
        {
            continue;
        }
        let writes = symbols.writes_of(member.name);
        if writes.is_empty() && !member.has_initializer {
            continue;
        }
        if symbols
            .uses_of(member.name)
            .iter()
            .any(|use_site| is_ref_or_out_argument(*use_site, source))
        {
            continue;
        }
        let field_is_static = has_modifier(&modifiers, "static");
        if writes
            .iter()
            .all(|write| is_matching_constructor_write(*write, field_is_static, source))
        {
            issues.push(issue(
                language,
                "S2933",
                format!("Make field '{}' 'readonly'.", member.name),
                range_of(member.anchor),
            ));
        }
    }
    issues
}
