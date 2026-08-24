use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, TIER_B_MEMBER_KINDS, UsageSymbols, is_private_member, nearest_ancestor_of_kinds,
    owner_is_partial,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1450 — fields touched by exactly one method behave like
/// locals and belong in that method.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers_of(member.declaration, source), "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
        {
            continue;
        }
        let uses = symbols.uses_of(member.name);
        if uses.is_empty() {
            continue;
        }
        let mut homes: Vec<Option<Node>> = uses
            .iter()
            .map(|use_site| nearest_ancestor_of_kinds(*use_site, &TIER_B_MEMBER_KINDS))
            .collect();
        homes.sort_by_key(|home| home.map(|owner| owner.byte_range().start));
        homes.dedup_by_key(|home| home.map(|owner| owner.byte_range().start));
        let single_method = matches!(homes.as_slice(), [Some(home)]
            if home.kind() == "method_declaration");
        if single_method {
            issues.push(issue(
                language,
                "S1450",
                format!(
                    "Field '{}' is used only within one method; make it a local variable instead.",
                    member.name
                ),
                range_of(member.anchor),
            ));
        }
    }
    issues
}
