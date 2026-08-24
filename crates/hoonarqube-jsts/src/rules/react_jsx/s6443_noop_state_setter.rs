use super::walker::{ReactCollector, capitalize_first, is_state_setter_name};
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::callee_name;
use crate::support::identifier_name;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6443`: `setX(x)` calls passing the state variable back to its own
    /// setter.
    pub(crate) fn check_noop_state_setter(&mut self, call: &CallExpression<'_>) {
        let Some(callee) = callee_name(call) else {
            return;
        };
        if !is_state_setter_name(callee) || call.arguments.len() != 1 {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Some(name) = identifier_name(argument) else {
            return;
        };
        if capitalize_first(name) == callee[3..] {
            self.sink.emit_span(
                RuleScope::Both,
                "S6443",
                "Pass a different value or an updater function; setting the state to itself changes nothing.",
                call.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6443_flags_setter_called_with_its_own_value() {
        let findings = js_keys("setCount(count);\n");
        assert_eq!(count_key(&findings, "javascript:S6443"), 1);
    }

    #[test]
    fn s6443_allows_updater_or_new_value() {
        let findings = js_keys("setCount(count + 1);\n");
        assert_eq!(count_key(&findings, "javascript:S6443"), 0);
    }

    #[test]
    fn s6443_ignores_non_setter_callee_shape() {
        let findings = js_keys("setcount(count);\n");
        assert_eq!(count_key(&findings, "javascript:S6443"), 0);
    }
}
