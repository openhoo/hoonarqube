use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::symbol_table::UsageSymbols;
use hoonarqube_ir::Issue;

/// csharpsquid:S3218 — nested types redeclaring an outer static member
/// hide it and mislead readers.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_symbol in &symbols.types {
        let Some(mut ancestor) = type_symbol.parent else {
            continue;
        };
        let mut outer_names = symbols.static_members_of(ancestor);
        while let Some(grandparent) = symbols
            .types
            .iter()
            .find(|candidate| candidate.declaration == ancestor)
            .and_then(|candidate| candidate.parent)
        {
            ancestor = grandparent;
            outer_names.extend(symbols.static_members_of(grandparent));
        }
        for member in symbols.static_members_of(type_symbol.declaration) {
            if outer_names.iter().any(|outer| outer.name == member.name) {
                issues.push(issue(
                    language,
                    "S3218",
                    format!(
                        "Rename '{}'; it hides a static member of an outer type.",
                        member.name
                    ),
                    range_of(member.anchor, source),
                ));
            }
        }
    }
    issues
}
