use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::{TSType, TSTypeName, TSTypeReference, TSUnionType};
use oxc_span::GetSpan;

/// `S4622` catalog parameter `threshold` default: maximum union members.
const MAX_UNION_TYPE_MEMBERS: usize = 3;

/// TypeScript utility type names whose type arguments are exempt from `S4622`
/// (upstream `isUsedWithUtilityType`).
pub(crate) const UTILITY_TYPE_NAMES: [&str; 21] = [
    "Awaited",
    "Partial",
    "Required",
    "Readonly",
    "Record",
    "Pick",
    "Omit",
    "Exclude",
    "Extract",
    "NonNullable",
    "Parameters",
    "ConstructorParameters",
    "ReturnType",
    "InstanceType",
    "ThisParameterType",
    "OmitThisParameter",
    "ThisType",
    "Uppercase",
    "Lowercase",
    "Capitalize",
    "Uncapitalize",
];

// `S4622` flags unions with more than `threshold` members, except unions that
// are the direct right-hand side of a type alias and unions used as utility
// type arguments (`Partial<A | B | C | D>`). The collector records those
// exempt spans while walking the enclosing nodes.
impl TsTypeCollector<'_, '_> {
    /// `S4622` logic extracted from `visit_ts_union_type`.
    pub(crate) fn check_s4622_ts_union_type(&mut self, it: &TSUnionType<'_>) {
        self.check_constituent_redundancy(&it.types, "union");

        if it.types.len() > MAX_UNION_TYPE_MEMBERS
            && !self.s4622_exempt_union_spans.contains(&it.span)
        {
            let message = format!(
                "Reduce this union type; it currently has {} members.",
                it.types.len()
            );
            self.sink
                .emit_span(RuleScope::TsOnly, "S4622", &message, it.span());
        }
    }

    /// Records the union members of a utility-type instantiation
    /// (`Partial<A | B>`) as `S4622`-exempt.
    pub(crate) fn record_s4622_utility_unions(&mut self, it: &TSTypeReference<'_>) {
        if !is_utility_type_reference(it) {
            return;
        }
        if let Some(arguments) = &it.type_arguments {
            for param in &arguments.params {
                if let TSType::TSUnionType(union) = param {
                    self.s4622_exempt_union_spans.insert(union.span);
                }
            }
        }
    }
}

/// Whether `reference` names one of the TypeScript utility types.
fn is_utility_type_reference(reference: &TSTypeReference<'_>) -> bool {
    matches!(
        &reference.type_name,
        TSTypeName::IdentifierReference(identifier)
            if UTILITY_TYPE_NAMES.contains(&identifier.name.as_str())
    )
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn oversized_unions_in_non_alias_positions_are_flagged() {
        let parameter = ts_keys("function f(p: 'a' | 'b' | 'c' | 'd'): void {}\n");
        assert_eq!(count_key(&parameter, "typescript:S4622"), 1);

        let variable = ts_keys("let v: 'a' | 'b' | 'c' | 'd';\n");
        assert_eq!(count_key(&variable, "typescript:S4622"), 1);

        let compact = ts_keys("function f(p: 'a' | 'b' | 'c'): void {}\n");
        assert_eq!(count_key(&compact, "typescript:S4622"), 0);
    }

    #[test]
    fn type_alias_unions_stay_silent() {
        // Issue #490: the direct right-hand side of a type alias is exempt.
        let alias = ts_keys(
            "export type TypePredicate = A | B | C | D;\ntype A = 1; type B = 2; type C = 3; type D = 4;\n",
        );
        assert_eq!(count_key(&alias, "typescript:S4622"), 0);

        // A union nested inside the alias (not the direct RHS) still counts.
        let nested = ts_keys(
            "type P = (A | B | C | D)[];\ntype A = 1; type B = 2; type C = 3; type D = 4;\n",
        );
        assert_eq!(count_key(&nested, "typescript:S4622"), 1);
    }

    #[test]
    fn utility_type_arguments_stay_silent() {
        let utility = ts_keys("type P = Partial<'a' | 'b' | 'c' | 'd'>;\n");
        assert_eq!(count_key(&utility, "typescript:S4622"), 0);
    }
}
