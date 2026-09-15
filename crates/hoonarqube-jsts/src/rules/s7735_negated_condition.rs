// Rule module s7735_negated_condition (generated).
//
// `javascript:S7735` + `typescript:S7735` — negated conditions should be
// avoided when an `else` clause is present. Reference semantics:
// eslint-plugin-unicorn `no-negated-condition` at the version pinned by
// SonarJS 13.x (v65.0.1, re-exported verbatim by SonarJS S7735).
//
// Issue #398: 26 pinned campaign findings (exceljs 16, express 10) with no
// detector. The reference rule reports the `test` of an `if` statement that
// has a non-`if` `else` branch, and the `test` of every conditional
// expression, when the test is a `!` unary negation or a `!=`/`!==`
// comparison. An `else if` alternate suppresses the finding for that `if`
// (the inner `if` is visited on its own). Parenthesized tests unwrap to the
// same node ESTree reports on, so `if ((!a)) … else …` flags `!a`. No
// auto-fix is offered.
//
// The regression tests below pin the documented surface plus the pinned
// campaign anchors; they stay green while the detector matches the
// reference rule.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    BinaryOperator, ConditionalExpression, Expression, IfStatement, Statement, UnaryOperator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_conditional_expression, walk_if_statement};
use oxc_span::GetSpan;

/// Entry point: `javascript:S7735` + `typescript:S7735`
/// no-negated-condition check over the parsed program. Purely syntactic, so
/// it runs without the semantic model.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut collector = NegatedConditionCollector {
        sink: IssueSink {
            index: ctx.index,
            language: ctx.language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(ctx.program);
    collector.sink.issues
}

struct NegatedConditionCollector<'index> {
    sink: IssueSink<'index>,
}

impl NegatedConditionCollector<'_> {
    /// `S7735`: the reference rule reports the test node when it is a `!`
    /// negation or a `!=`/`!==` comparison. Parentheses unwrap first so the
    /// reported span matches the `ESTree` node.
    fn check_test(&mut self, test: &Expression<'_>) {
        let test = unparenthesized(test);
        let negated = match test {
            Expression::UnaryExpression(unary) => unary.operator == UnaryOperator::LogicalNot,
            Expression::BinaryExpression(binary) => matches!(
                binary.operator,
                BinaryOperator::Inequality | BinaryOperator::StrictInequality
            ),
            _ => false,
        };
        if negated {
            self.sink.emit_span(
                RuleScope::Both,
                "S7735",
                "Unexpected negated condition.",
                test.span(),
            );
        }
    }
}

impl Visit<'_> for NegatedConditionCollector<'_> {
    fn visit_if_statement(&mut self, it: &IfStatement<'_>) {
        // The reference rule skips `if` statements without an `else` and
        // `else if` chains (an `IfStatement` alternate): only the final
        // `else`-bearing `if` of a chain is reported.
        let has_plain_else = matches!(&it.alternate, Some(alternate) if !matches!(alternate, Statement::IfStatement(_)));
        if has_plain_else {
            self.check_test(&it.test);
        }
        walk_if_statement(self, it);
    }

    fn visit_conditional_expression(&mut self, it: &ConditionalExpression<'_>) {
        self.check_test(&it.test);
        walk_conditional_expression(self, it);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7735_flags_pinned_express_ternary_anchors() {
        // Pinned anchors: express/lib/application.js:300 and
        // express/lib/request.js:312,389 — negated ternary tests.
        let source = "\
var extension = ext[0] !== '.'
  ? '.' + ext
  : ext;
var subdomains = !isIP(hostname)
  ? hostname.split('.').reverse()
  : [hostname];
return index !== -1
  ? header.substring(0, index).trim()
  : header.trim();
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7735"), 3);
        assert!(keys.contains(&("javascript:S7735".to_string(), 1)));
        assert!(keys.contains(&("javascript:S7735".to_string(), 4)));
        assert!(keys.contains(&("javascript:S7735".to_string(), 7)));
    }

    #[test]
    fn s7735_flags_negated_if_else_and_ternary() {
        let source = "\
if (!isValid) {
  handleError();
} else {
  processData();
}
if (a !== b) {
  first();
} else {
  second();
}
const value = !(a === b) ? left() : right();
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7735"), 3);
        assert!(keys.contains(&("javascript:S7735".to_string(), 1)));
        assert!(keys.contains(&("javascript:S7735".to_string(), 6)));
        assert!(keys.contains(&("javascript:S7735".to_string(), 11)));
    }

    #[test]
    fn s7735_flags_parenthesized_and_nested_negations() {
        // ESTree reports the unwrapped test node; `!(a === b)` and `((!x))`
        // both flag the inner negation.
        let source = "\
if ((!ready)) {
  wait();
} else {
  go();
}
const out = (!(a === b)) ? 1 : 2;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7735"), 2);
        assert!(keys.contains(&("javascript:S7735".to_string(), 1)));
        assert!(keys.contains(&("javascript:S7735".to_string(), 6)));
    }

    #[test]
    fn s7735_skips_bare_if_and_else_if_chain_heads() {
        // No `else` clause: unflagged. `else if` alternates: the head `if`
        // is skipped, the last `else`-bearing `if` is still reported.
        let source = "\
if (!ready) {
  wait();
}
if (!a) {
  first();
} else if (!b) {
  second();
} else if (c !== d) {
  third();
} else {
  fallback();
}
while (!done) {
  tick();
}
const plain = !flag ? 1 : 2;
";
        let keys = js_keys(source);
        // `else if (c !== d) … else` and the `!flag` ternary are reported.
        assert_eq!(count_key(&keys, "javascript:S7735"), 2);
        assert!(keys.contains(&("javascript:S7735".to_string(), 8)));
        assert!(keys.contains(&("javascript:S7735".to_string(), 16)));
    }

    #[test]
    fn s7735_ignores_positive_and_non_inequality_tests() {
        let source = "\
if (isValid) {
  processData();
} else {
  handleError();
}
if (a == b) {
  x();
} else {
  y();
}
if (a > b) {
  x();
} else {
  y();
}
const t = flag ? 1 : 2;
const u = a === b ? 1 : 2;
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7735"), 0);
    }

    #[test]
    fn s7735_reports_in_both_languages() {
        let source = "const v = !ok ? fallback() : run();\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7735"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7735"), 1);
    }
}
