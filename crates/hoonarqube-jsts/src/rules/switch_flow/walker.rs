// Family walker for 'switch_flow' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::shared::statement_ends_with_jump;
use crate::support::{IssueSink, LineIndex, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    Expression, IfStatement, LogicalOperator, Statement, SwitchCase, SwitchStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_switch_case, walk_switch_statement};
use oxc_span::GetSpan;

fn check_switch_flow(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = SwitchFlowCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        in_else_if_chain: false,
        case_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Switch-statement and if-chain flow rules in one traversal: `S126`
/// (chain without final `else`), `S128` (case fall-through), `S131`
/// (missing `default`), `S4524` (default not last), `S3616` (sequence or
/// logical-OR case test), `S1479` (too many cases), `S1301` (switch
/// convertible to `if`), and `S1821` (switch nested inside a case).
struct SwitchFlowCollector<'index> {
    sink: IssueSink<'index>,
    /// Set while visiting the `alternate` of an enclosing `if`; detects
    /// chains whose last link lacks a final `else` (`S126`).
    in_else_if_chain: bool,
    /// Number of enclosing `SwitchCase` consequents (`S1821`).
    case_depth: u32,
}

impl<'a> Visit<'a> for SwitchFlowCollector<'_> {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        if self.in_else_if_chain && it.alternate.is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S126",
                "Add a final \"else\" clause to this if/else-if chain.",
                it.span(),
            );
        }
        let saved_in_chain = self.in_else_if_chain;
        self.in_else_if_chain = false;
        self.visit_statement(&it.consequent);
        self.in_else_if_chain = matches!(&it.alternate, Some(Statement::IfStatement(_)));
        if let Some(alternate) = &it.alternate {
            self.visit_statement(alternate);
        }
        self.in_else_if_chain = saved_in_chain;
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        if self.case_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1821",
                "Extract this nested switch statement from its parent case.",
                it.span(),
            );
        }
        if it.cases.iter().all(|case| case.test.is_some()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S131",
                "Add a \"default\" case to this switch statement.",
                it.span(),
            );
        }
        let last_case_index = it.cases.len().saturating_sub(1);
        for (case_index, case) in it.cases.iter().enumerate() {
            if case.test.is_none() && case_index != last_case_index {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4524",
                    "Move this default case to the end of this switch statement.",
                    case.span(),
                );
            }
        }
        if it.cases.len() > MAX_SWITCH_CASES {
            self.sink.emit_span(
                RuleScope::Both,
                "S1479",
                &format!(
                    "Reduce the number of switch cases from {} to at most {}.",
                    it.cases.len(),
                    MAX_SWITCH_CASES
                ),
                it.span(),
            );
        }
        let tested_cases = it.cases.iter().filter(|case| case.test.is_some()).count();
        if (1..=MAX_TINY_SWITCH_CASES).contains(&tested_cases) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1301",
                "Replace this switch statement with an if statement.",
                it.span(),
            );
        }
        walk_switch_statement(self, it);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        if let Some(test) = &it.test
            && case_test_is_sequence_or_or(test)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3616",
                "Remove this sequence expression or logical OR from the case test.",
                test.span(),
            );
        }
        if let Some(last) = it.consequent.last()
            && !statement_ends_with_jump(last)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S128",
                "End this case with an unconditional break, return, throw, or continue statement.",
                it.span(),
            );
        }
        self.case_depth += 1;
        walk_switch_case(self, it);
        self.case_depth -= 1;
    }
}

/// `S1301`: switches with at most this many tested cases are flagged as
/// convertible to `if` (frozen catalog default).
const MAX_TINY_SWITCH_CASES: usize = 2;

// ===== Batch2b: statement-shape and control-flow walks =====
//
// Family A — switch/if-chain flow: `S126`, `S128`, `S131`, `S4524`,
// `S3616`, `S1479`, `S1301`, and `S1821`. Catalog parameters used by
// this section are kept as local constants mirroring the frozen
// catalog defaults.

/// `S1479`: switch statements carrying more cases than this are flagged
/// (frozen catalog default of the `maximum` parameter).
pub(crate) const MAX_SWITCH_CASES: usize = 30;

/// Whether a case test uses a sequence expression or a logical OR
/// (`S3616`).
fn case_test_is_sequence_or_or(test: &Expression<'_>) -> bool {
    match unparenthesized(test) {
        Expression::SequenceExpression(_) => true,
        Expression::LogicalExpression(logical) => logical.operator == LogicalOperator::Or,
        _ => false,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_switch_flow(ctx.program, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s126_flags_else_if_chain_without_final_else() {
        let chained =
            js_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n} else if (c) {\n  h();\n}\n");
        assert_eq!(count_key(&chained, "javascript:S126"), 1);
        let tail_line = chained
            .iter()
            .find(|(key, _)| key == "javascript:S126")
            .map(|(_, line)| *line);
        assert_eq!(tail_line, Some(5));

        let with_final_else =
            js_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n} else {\n  h();\n}\n");
        assert_eq!(count_key(&with_final_else, "javascript:S126"), 0);

        // A lone `if` is not a chain.
        let plain_if = js_keys("if (a) {\n  f();\n}\n");
        assert_eq!(count_key(&plain_if, "javascript:S126"), 0);
    }

    #[test]
    fn s128_requires_unconditional_case_termination() {
        let falling_through = js_keys("switch (x) {\n  case 1:\n    f();\n}\n");
        assert_eq!(count_key(&falling_through, "javascript:S128"), 1);

        let with_break = js_keys("switch (x) {\n  case 1:\n    f();\n    break;\n}\n");
        assert_eq!(count_key(&with_break, "javascript:S128"), 0);

        // Empty consequents (case grouping) and block-wrapped jumps stay
        // clean.
        let grouped = js_keys("switch (x) {\n  case 1:\n  case 2:\n    f();\n    break;\n}\n");
        assert_eq!(count_key(&grouped, "javascript:S128"), 0);

        let via_block_return = js_keys(
            "function f(x) {\n  switch (x) {\n    case 1:\n      { g(); return; }\n  }\n}\n",
        );
        assert_eq!(count_key(&via_block_return, "javascript:S128"), 0);
    }

    #[test]
    fn s131_flags_switch_without_default_case() {
        let source = "switch (x) {\n  case 1:\n    break;\n}\n";
        let missing = js_keys(source);
        assert_eq!(count_key(&missing, "javascript:S131"), 1);

        let with_default =
            js_keys("switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&with_default, "javascript:S131"), 0);

        let typescript = findings(source, JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S131"), 1);
        assert_eq!(count_key(&typescript, "javascript:S131"), 0);
    }

    #[test]
    fn s4524_flags_default_case_not_in_last_position() {
        let misplaced = js_keys("switch (x) {\n  default:\n    break;\n  case 1:\n    break;\n}\n");
        assert_eq!(count_key(&misplaced, "javascript:S4524"), 1);

        let last = js_keys("switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&last, "javascript:S4524"), 0);
    }

    #[test]
    fn s3616_flags_sequence_and_logical_or_case_tests() {
        let sequence = js_keys("switch (x) {\n  case (a(), b):\n    break;\n}\n");
        assert_eq!(count_key(&sequence, "javascript:S3616"), 1);

        let logical_or = js_keys("switch (x) {\n  case a || b:\n    break;\n}\n");
        assert_eq!(count_key(&logical_or, "javascript:S3616"), 1);

        // Logical AND tests are ordinary expressions.
        let logical_and = js_keys("switch (x) {\n  case a && b:\n    break;\n}\n");
        assert_eq!(count_key(&logical_and, "javascript:S3616"), 0);
    }

    #[test]
    fn s1479_flags_switches_with_more_than_thirty_cases() {
        let build = |case_count: usize| {
            let mut source = String::from("switch (x) {\n");
            for case_number in 0..case_count {
                let _ = write!(source, "  case {case_number}:\n    break;\n");
            }
            source.push_str("}\n");
            source
        };

        let at_limit = js_keys(&build(crate::MAX_SWITCH_CASES));
        assert_eq!(count_key(&at_limit, "javascript:S1479"), 0);

        let over_limit = js_keys(&build(crate::MAX_SWITCH_CASES + 1));
        assert_eq!(count_key(&over_limit, "javascript:S1479"), 1);
    }

    #[test]
    fn s1301_flags_switches_convertible_to_if() {
        let two_cases = js_keys(
            "switch (x) {\n  case 1:\n    f();\n    break;\n  case 2:\n    g();\n    break;\n  default:\n    break;\n}\n",
        );
        assert_eq!(count_key(&two_cases, "javascript:S1301"), 1);

        let one_case =
            js_keys("switch (x) {\n  case 1:\n    f();\n    break;\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&one_case, "javascript:S1301"), 1);

        let mut three_cases_source = String::from("switch (x) {\n  default:\n    break;\n");
        for case_number in 0..3 {
            let _ = write!(three_cases_source, "  case {case_number}:\n    break;\n");
        }
        three_cases_source.push_str("}\n");
        let three_cases = js_keys(&three_cases_source);
        assert_eq!(count_key(&three_cases, "javascript:S1301"), 0);
    }

    #[test]
    fn s1821_flags_switch_nested_inside_case_consequent() {
        let nested = js_keys(
            "switch (x) {\n  case 1:\n    switch (y) {\n      case 2:\n        break;\n    }\n    break;\n}\n",
        );
        assert_eq!(count_key(&nested, "javascript:S1821"), 1);
        let inner_line = nested
            .iter()
            .find(|(key, _)| key == "javascript:S1821")
            .map(|(_, line)| *line);
        assert_eq!(inner_line, Some(3));

        // Sibling switches at the top level stay clean.
        let sibling = js_keys(
            "switch (x) {\n  case 1:\n    break;\n}\nswitch (y) {\n  default:\n    break;\n}\n",
        );
        assert_eq!(count_key(&sibling, "javascript:S1821"), 0);
    }
    #[test]
    fn s126_nested_if_is_not_a_chain() {
        let nested = js_keys("if (a) {\n  if (b) {\n    f();\n  }\n}\n");
        assert_eq!(count_key(&nested, "javascript:S126"), 0);
    }

    #[test]
    fn s128_return_and_throw_terminate_cases() {
        let via_return =
            js_keys("function f(x) {\n  switch (x) {\n    case 1:\n      return g();\n  }\n}\n");
        assert_eq!(count_key(&via_return, "javascript:S128"), 0);

        let via_throw = js_keys(
            "function f(x) {\n  switch (x) {\n    case 1:\n      throw new Error('bad');\n  }\n}\n",
        );
        assert_eq!(count_key(&via_throw, "javascript:S128"), 0);
    }

    #[test]
    fn s131_default_only_switch_passes_and_stays_last() {
        let default_only = js_keys("switch (x) {\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&default_only, "javascript:S131"), 0);
        assert_eq!(count_key(&default_only, "javascript:S4524"), 0);
    }

    #[test]
    fn s3616_bitwise_and_case_test_passes() {
        let bitwise = js_keys("switch (x) {\n  case a & b:\n    break;\n}\n");
        assert_eq!(count_key(&bitwise, "javascript:S3616"), 0);
    }

    #[test]
    fn s4524_default_between_cases_still_flags() {
        let middle = js_keys(
            "switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n  case 2:\n    break;\n}\n",
        );
        assert_eq!(count_key(&middle, "javascript:S4524"), 1);
    }

    #[test]
    fn s1301_two_cases_without_default_remain_convertible() {
        let no_default = js_keys(
            "switch (x) {\n  case 1:\n    f();\n    break;\n  case 2:\n    g();\n    break;\n}\n",
        );
        assert_eq!(count_key(&no_default, "javascript:S1301"), 1);
    }

    #[test]
    fn s1821_deeply_nested_switches_flag_per_level() {
        let deep = js_keys(
            "switch (x) {\n  case 1:\n    switch (y) {\n      case 2:\n        switch (z) {\n          case 3:\n            break;\n        }\n        break;\n    }\n    break;\n}\n",
        );
        assert_eq!(count_key(&deep, "javascript:S1821"), 2);
    }
}
