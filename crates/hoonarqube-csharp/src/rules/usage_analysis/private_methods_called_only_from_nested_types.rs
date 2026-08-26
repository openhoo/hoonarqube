use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, UsageSymbols, is_private_member, nearest_ancestor_of_kinds, owner_is_partial,
};
use hoonarqube_ir::Issue;

/// csharpsquid:S3398 — private methods referenced exclusively from nested
/// types belong beside their callers.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if member.flavor != MemberFlavor::Method
            || !is_private_member(member.declaration, source, member.nested_type)
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.name == "Main"
        {
            continue;
        }
        let uses = symbols.uses_of(member.name);
        if uses.is_empty() {
            continue;
        }
        let owner_span = member.owner.byte_range();
        let all_nested = uses.iter().all(|use_site| {
            nearest_ancestor_of_kinds(*use_site, &TYPE_DECLARATION_KINDS).is_some_and(|holder| {
                holder != member.owner
                    && holder.byte_range().start >= owner_span.start
                    && holder.byte_range().end <= owner_span.end
            })
        });
        if all_nested {
            issues.push(issue(
                language,
                "S3398",
                format!(
                    "Private method '{}' is only called from nested types.",
                    member.name
                ),
                range_of(member.anchor, source),
            ));
        }
    }
    issues
}
