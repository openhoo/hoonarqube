use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::PropertyDefinition;
use oxc_ast::ast::TSAccessibility;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S1444` logic extracted from `visit_property_definition`.
    pub(crate) fn check_s1444_property_definition(&mut self, it: &PropertyDefinition<'_>) {
        if it.r#static
            && !it.readonly
            && !matches!(
                it.accessibility,
                Some(TSAccessibility::Private | TSAccessibility::Protected)
            )
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S1444",
                "Add the readonly modifier to this static property.",
                it.span(),
            );
        }
    }
}
