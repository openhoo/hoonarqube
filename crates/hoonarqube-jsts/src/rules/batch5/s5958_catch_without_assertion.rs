use super::collectors_hotspots::ASSERTION_MARKERS;
use crate::rules::batch5::s2187_test_framework_rules::TestFrameworkCollector;
use crate::support::RuleScope;
use oxc_span::GetSpan;

impl TestFrameworkCollector<'_, '_> {
    /// `S5958`: catch blocks without any assertion.
    pub(crate) fn check_catch_without_assertion(&mut self, clause: &oxc_ast::ast::CatchClause<'_>) {
        let body_span = clause.body.span();
        if !ASSERTION_MARKERS
            .iter()
            .any(|marker| self.body_contains(body_span, marker))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S5958",
                "Assert inside this catch block or use '.throw'/'rejects' matchers.",
                clause.body.span(),
            );
        }
    }
}
