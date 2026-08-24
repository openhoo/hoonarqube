use super::walker::ReactCollector;
use crate::support::RuleScope;
use crate::support::callee_name;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6440`: hook calls under conditions, loops, or callbacks.
    pub(crate) fn check_hook_call_site(&mut self, call: &CallExpression<'_>) {
        if self.conditional_depth == 0 {
            return;
        }
        let Some(callee) = callee_name(call) else {
            return;
        };
        let Some(tail) = callee.strip_prefix("use") else {
            return;
        };
        if !tail.starts_with(|ch: char| ch.is_ascii_uppercase()) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6440",
            "Move this hook call to the top level of the component; hooks must not run conditionally.",
            call.span(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6440_flags_hook_under_condition() {
        let findings = js_keys("function C() {\n  if (ready) {\n    useState();\n  }\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6440"), 1);
    }

    #[test]
    fn s6440_allows_top_level_hook() {
        let findings = js_keys("function Component() {\n  const [v] = useState(0);\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6440"), 0);
    }

    #[test]
    fn s6440_ignores_non_hook_use_prefix_callee() {
        let findings = js_keys("function C() {\n  if (ready) {\n    user();\n  }\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6440"), 0);
    }
}
