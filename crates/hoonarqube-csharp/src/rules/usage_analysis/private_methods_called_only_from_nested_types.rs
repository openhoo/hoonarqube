use super::support::member_uses;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
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
        let uses = member_uses(symbols, member, source);
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
            let nested_name = uses
                .first()
                .and_then(|use_site| nearest_ancestor_of_kinds(*use_site, &TYPE_DECLARATION_KINDS))
                .and_then(|holder| holder.child_by_field_name("name"))
                .map_or("nested type", |name| node_text(name, source));
            issues.push(issue(
                language,
                "S3398",
                format!("Move this method inside '{nested_name}'."),
                range_of(member.anchor, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3398_ignores_same_named_calls_in_unrelated_types() {
        let report = analyze_default(
            "class Outer\n{\n    private void Work() { }\n    private class Inner\n    {\n        public void Run() { Work(); }\n    }\n}\n\nclass Other\n{\n    private void Work() { }\n    public void Run() { Work(); }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3398");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3398_nested_method_shadow_does_not_count_as_outer_call() {
        let report = analyze_default(
            "class Outer\n{\n    private void Work() { }\n    private class Inner\n    {\n        private void Work() { }\n        public void Run() { Work(); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3398").is_empty());
    }
}
