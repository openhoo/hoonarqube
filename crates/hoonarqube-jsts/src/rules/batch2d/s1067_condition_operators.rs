use super::collectors::{ConditionOperatorScanner, DuplicationCollector};
use crate::support::RuleScope;
use oxc_ast::ast::Expression;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

/// `S1067`: conditions carrying more boolean operators than this are
/// flagged (frozen catalog default of the `max` parameter).
const MAX_CONDITION_OPERATORS: usize = 3;

impl DuplicationCollector<'_> {
    /// `S1067`: conditions with more operators than the catalog maximum.
    pub(crate) fn check_condition_operators(&mut self, test: &Expression<'_>) {
        let mut scanner = ConditionOperatorScanner::default();
        scanner.visit_expression(test);
        if scanner.count > MAX_CONDITION_OPERATORS {
            self.sink.emit_span(
                RuleScope::Both,
                "S1067",
                &format!(
                    "This condition uses {} boolean operators; simplify it to at most {}.",
                    scanner.count, MAX_CONDITION_OPERATORS
                ),
                test.span(),
            );
        }
    }
}
