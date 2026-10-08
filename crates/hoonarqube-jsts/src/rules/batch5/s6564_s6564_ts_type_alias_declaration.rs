use super::collectors::TsTypeCollector;
use crate::support::{RuleScope, source_slice};
use oxc_ast::ast::TSType;
use oxc_ast::ast::TSTypeAliasDeclaration;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S6564` logic extracted from `visit_ts_type_alias_declaration`.
    pub(crate) fn check_s6564_ts_type_alias_declaration(
        &mut self,
        it: &TSTypeAliasDeclaration<'_>,
    ) {
        if let TSType::TSTypeReference(reference) = &it.type_annotation
            && reference.type_arguments.is_none()
        {
            let replacement = source_slice(self.source, reference.type_name.span());
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6564",
                &format!(
                    "Remove this redundant type alias and replace its occurrences with \"{replacement}\"."
                ),
                it.id.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6564_reports_alias_name_and_referenced_type_message() {
        for (source, replacement, start, end) in [
            (
                "type Target = { value: string };\nexport type Alias = Target;\n",
                "Target",
                pos(2, 12),
                pos(2, 17),
            ),
            (
                "export type Alias = core.Target;\n",
                "core.Target",
                pos(1, 12),
                pos(1, 17),
            ),
        ] {
            let report = ts(source);
            let target: Vec<_> = report
                .issues
                .iter()
                .filter(|issue| issue.rule_key == "typescript:S6564")
                .collect();
            assert_eq!(target.len(), 1);
            assert_eq!(target[0].range.start, start);
            assert_eq!(target[0].range.end, end);
            assert_eq!(
                target[0].message,
                format!(
                    "Remove this redundant type alias and replace its occurrences with \"{replacement}\"."
                )
            );
        }
        for source in [
            "type Alias = Target<string>;\n",
            "type Alias = Target | Other;\n",
            "type Alias = Target & Other;\n",
            "type Alias = { value: string };\n",
        ] {
            assert_eq!(
                count_key(&report_keys(&ts(source)), "typescript:S6564"),
                0,
                "{source}"
            );
        }
    }
}
