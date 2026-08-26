use crate::CsLanguage;
use crate::cst::{base_simple_names, issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, UsageSymbols, declares_executable_code, has_contract_modifier, is_private_member,
    owner_is_partial, touches_instance_data,
};
use hoonarqube_ir::Issue;

/// csharpsquid:S2325 — private members ignoring instance data can become
/// `static`; public ones stay untouched because callers outside the file
/// invoke them through instances.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if !matches!(member.flavor, MemberFlavor::Method | MemberFlavor::Property)
            || !matches!(
                member.owner.kind(),
                "class_declaration" | "struct_declaration"
            )
            || !base_simple_names(member.owner, source).is_empty()
            || owner_is_partial(member.owner, source)
            || is_attributed(member.declaration, source)
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers_of(member.declaration, source), "static")
            || has_contract_modifier(&modifiers_of(member.declaration, source))
            || !declares_executable_code(member.declaration)
            || touches_instance_data(member, symbols)
        {
            continue;
        }
        issues.push(issue(
            language,
            "S2325",
            format!(
                "'{}' does not access instance data and can be marked 'static'.",
                member.name
            ),
            range_of(member.anchor, source),
        ));
    }
    issues
}
