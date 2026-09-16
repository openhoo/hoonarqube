use super::collectors::TsTypeCollector;
use crate::support::{RuleScope, source_slice};
use oxc_ast::ast::{TSInterfaceDeclaration, TSType};
use oxc_span::{GetSpan, Span};
use std::collections::hash_map::Entry;

/// `S4323` thresholds from the upstream rule: composite types need more than
/// two members and more than two occurrences before an alias is suggested.
const TYPE_THRESHOLD: usize = 2;
const USAGE_THRESHOLD: usize = 2;

// `S4323` collects every union/intersection type with more than two members
// that appears outside type-alias declarations, normalizes the member text,
// and reports the first occurrence of any composite used more than twice.
impl TsTypeCollector<'_, '_> {
    /// Shared interface-body checks (`S6598` single call signature, `S4136`
    /// overload grouping) extracted from `visit_ts_interface_declaration`.
    pub(crate) fn check_ts_interface_declaration(&mut self, it: &TSInterfaceDeclaration<'_>) {
        self.check_single_call_signature(&it.body.body, it.span());
        self.check_overload_grouping(&it.body.body);
    }

    /// Records one `S4323` composite-type occurrence (union or intersection).
    pub(crate) fn check_s4323_composite_type(
        &mut self,
        types: &[TSType<'_>],
        span: Span,
        union: bool,
    ) {
        if self.type_alias_depth > 0 || types.len() <= TYPE_THRESHOLD {
            return;
        }
        if union && is_nullable_union(types) {
            return;
        }
        let mut members: Vec<String> = types
            .iter()
            .map(|member| source_slice(self.source, member.span()).to_string())
            .collect();
        members.sort();
        let key = members.join("|");
        let occurrences = match self.s4323_usages.entry(key.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                self.s4323_order.push(key);
                entry.insert(Vec::new())
            }
        };
        occurrences.push((span, union));
    }

    /// `S4323` emission at the end of the file: the first occurrence of every
    /// composite type used more than `USAGE_THRESHOLD` times.
    pub(crate) fn finish_s4323_type_alias_usage(&mut self) {
        for key in std::mem::take(&mut self.s4323_order) {
            let Some(occurrences) = self.s4323_usages.get(&key) else {
                continue;
            };
            if occurrences.len() <= USAGE_THRESHOLD {
                continue;
            }
            let (span, union) = occurrences[0];
            let kind = if union { "union" } else { "intersection" };
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4323",
                &format!("Replace this {kind} type with a type alias."),
                span,
            );
        }
    }
}

/// Upstream `isNullableType`: unions whose only non-nullish member is a single
/// type (`T | null | undefined`) are idiomatic optional types, not alias
/// candidates.
fn is_nullable_union(types: &[TSType<'_>]) -> bool {
    types
        .iter()
        .filter(|member| {
            !matches!(
                member,
                TSType::TSNullKeyword(_) | TSType::TSUndefinedKeyword(_)
            )
        })
        .count()
        == 1
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn repeated_unions_are_flagged_on_first_occurrence() {
        // Issue #488: a >2-member union used more than twice gets one finding
        // on its first occurrence.
        let repeated = ts(
            "type A = number; type B = string; type C = boolean;\nfunction f(source: A | B | C, m: number): void {}\nfunction g(source: A | B | C): void {}\nfunction h(source: A | B | C): void {}\n",
        );
        let hits: Vec<u32> = repeated
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S4323")
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(hits, vec![2]);
    }

    #[test]
    fn below_threshold_unions_stay_silent() {
        // Two occurrences are below the >2 usage threshold.
        let twice = ts_keys(
            "type A = number; type B = string; type C = boolean;\nfunction f(source: A | B | C): void {}\nfunction g(source: A | B | C): void {}\n",
        );
        assert_eq!(count_key(&twice, "typescript:S4323"), 0);

        // Two-member unions are below the >2 member threshold.
        let narrow = ts_keys(
            "type A = number; type B = string;\nfunction f(x: A | B): void {}\nfunction g(x: A | B): void {}\nfunction h(x: A | B): void {}\n",
        );
        assert_eq!(count_key(&narrow, "typescript:S4323"), 0);
    }

    #[test]
    fn alias_declarations_and_nullable_unions_stay_silent() {
        // Alias right-hand sides never count toward the usage map.
        let alias =
            ts_keys("type P = A | B | C;\ntype A = number; type B = string; type C = boolean;\n");
        assert_eq!(count_key(&alias, "typescript:S4323"), 0);

        // `T | null | undefined` is the idiomatic nullable form.
        let nullable = ts_keys(
            "type A = number;\nfunction f(x: A | null | undefined): void {}\nfunction g(x: A | null | undefined): void {}\nfunction h(x: A | null | undefined): void {}\n",
        );
        assert_eq!(count_key(&nullable, "typescript:S4323"), 0);
    }

    #[test]
    fn single_property_interfaces_are_not_flagged() {
        // Issue #488: the single-property-interface aspect is not part of the
        // upstream rule.
        let interface = ts_keys("interface Single { readonly value: string; }\n");
        assert_eq!(count_key(&interface, "typescript:S4323"), 0);
    }

    #[test]
    fn repeated_intersections_are_flagged() {
        let repeated = ts_keys(
            "type A = { a: number }; type B = { b: number }; type C = { c: number };\nfunction f(source: A & B & C): void {}\nfunction g(source: A & B & C): void {}\nfunction h(source: A & B & C): void {}\n",
        );
        assert_eq!(count_key(&repeated, "typescript:S4323"), 1);
    }
}
