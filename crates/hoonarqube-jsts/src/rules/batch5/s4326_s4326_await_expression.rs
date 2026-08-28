use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::AwaitExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ReturnStatement;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4326` logic extracted from `visit_await_expression`.
    pub(crate) fn check_s4326_await_expression(&mut self, it: &AwaitExpression<'_>) {
        if let Expression::AwaitExpression(_inner) = unparenthesized(&it.argument) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4326",
                "Redundant use of `await` on a return value.",
                it.span(),
            );
        }
    }
    /// `S4326`: plain `return await value;` is redundant. CE-parity: the
    /// documented noncompliant example is exactly this form, and the captured
    /// engine flags oracle-js `s4326_good.js` accordingly. Exempted inside try
    /// statements with a catch or finally handler, where awaiting preserves
    /// rejection handling. Double awaits (`return await await`) stay covered
    /// by [`Self::check_s4326_await_expression`] alone, avoiding duplicates.
    pub(crate) fn check_s4326_return_await(&mut self, it: &ReturnStatement<'_>) {
        if self.try_guard_depth > 0 {
            return;
        }
        let Some(argument) = &it.argument else {
            return;
        };
        let Expression::AwaitExpression(awaited) = unparenthesized(argument) else {
            return;
        };
        if matches!(
            unparenthesized(&awaited.argument),
            Expression::AwaitExpression(_)
        ) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S4326",
            "Redundant use of 'await' on a returned value; return the promise directly.",
            awaited.span(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s4326_flags_redundant_return_await() {
        // CE-parity: documented noncompliant example; captured CE fires on
        // oracle-js s4326_good.js `return await promise`.
        let findings = js_keys("async function load() {\n  return await promise;\n}\n");
        assert_eq!(count_key(&findings, "javascript:S4326"), 1);
    }

    #[test]
    fn s4326_allows_return_await_in_try_with_handler() {
        let findings = js_keys(
            "async function load() {\n  try {\n    return await promise;\n  } catch (error) {\n    handle(error);\n  }\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S4326"), 0);
    }

    #[test]
    fn s4326_reports_single_finding_for_nested_double_await() {
        // The nested form stays covered by the await-expression check alone;
        // no duplicate return-await finding on top of it.
        let findings = js_keys("async function load() {\n  return await await promise;\n}\n");
        assert_eq!(count_key(&findings, "javascript:S4326"), 1);
    }
}
