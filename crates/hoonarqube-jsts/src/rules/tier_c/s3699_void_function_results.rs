// Rule module s3699_void_function_results (generated).
use super::walker::TierCCallUsageCollector;
use crate::support::{RuleScope, callee_name};
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl<'a> TierCCallUsageCollector<'_, '_> {
    /// `S3699`: the result of a call whose census facts say it returns
    /// nothing is used in a value position.
    pub(crate) fn check_void_result(&mut self, it: &CallExpression<'a>) {
        if self.suppress_span != Some(it.span())
            && let Some(name) = callee_name(it)
            && let Some(facts) = self.census.functions.get(name)
            && facts.is_void()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3699",
                "The return value of this void function should not be used.",
                it.span(),
            );
        }
    }
}
