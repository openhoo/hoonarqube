use crate::rules::batch5::s2187_test_framework_rules::TestFrameworkCollector;
use crate::support::RuleScope;
use crate::support::callee_name;
use crate::support::expression_root_name;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

/// Test-runner globals whose calls mark a file as containing tests.
pub(crate) const TEST_FRAMEWORK_GLOBALS: [&str; 5] =
    ["describe", "it", "test", "context", "specify"];

/// Skipped-test spellings `S1607` flags.
const SKIPPED_TEST_NAMES: [&str; 3] = ["xit", "xdescribe", "xcontext"];

/// Focused-test spellings `S6426` flags.
const FOCUSED_TEST_NAMES: [&str; 2] = ["fit", "fdescribe"];

impl TestFrameworkCollector<'_, '_> {
    /// `S1607` and `S6426`: skipped and focused test spellings.
    pub(crate) fn check_skipped_or_focused(&mut self, call: &CallExpression<'_>) {
        if let Some(name) = callee_name(call) {
            if SKIPPED_TEST_NAMES.contains(&name) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1607",
                    "Do not skip this test; remove it or fix it.",
                    call.span(),
                );
                return;
            }
            if FOCUSED_TEST_NAMES.contains(&name) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6426",
                    "Remove this exclusive test focus ('only').",
                    call.span(),
                );
                return;
            }
        }
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        let root_is_test_global = expression_root_name(&member.object)
            .is_some_and(|root| TEST_FRAMEWORK_GLOBALS.contains(&root));
        if !root_is_test_global {
            return;
        }
        let (rule, message) = match property {
            "skip" => ("S1607", "Do not skip this test; remove it or fix it."),
            "only" => ("S6426", "Remove this exclusive test focus ('only')."),
            _ => return,
        };
        self.sink
            .emit_span(RuleScope::Both, rule, message, call.span());
    }
}
