use super::collectors::DuplicationCollector;
use crate::support::RuleScope;
use oxc_span::Span;

/// `S1067`: expressions carrying more conditional operators than this are
/// flagged (frozen catalog default of the `max` parameter).
const MAX_CONDITION_OPERATORS: usize = 3;

impl DuplicationCollector<'_> {
    /// `S1067`: an expression tree with more conditional operators than the
    /// catalog maximum. `operators` counts `&&`/`||`/`??` and ternary `?`
    /// tokens accumulated by the collector's scope tracking; unary `!` is
    /// not a boolean operator for this rule.
    pub(crate) fn report_condition_operators(&mut self, operators: u32, span: Span) {
        let operators = usize::try_from(operators).unwrap_or(usize::MAX);
        if operators > MAX_CONDITION_OPERATORS {
            self.sink.emit_span(
                RuleScope::Both,
                "S1067",
                &format!(
                    "This condition uses {operators} boolean operators; simplify it to at most {MAX_CONDITION_OPERATORS}."
                ),
                span,
            );
        }
    }
}
